"""Prompt-to-plan layer (phase 2a): natural-language prompt -> structured PLAN.

NO execution happens here. The interpreter maps a prompt to an :class:`Intent`
(stage + params) using deterministic keyword rules — no LLM — behind the
:class:`PlanInterpreter` interface, so an LLM-backed interpreter can replace it
later without touching the endpoint or the preview builder. An unknown or
ambiguous prompt yields a clarifying message, never a guessed plan.

``plan()`` then enriches an Intent for a specific engagement into a :class:`Plan`
with a human-readable preview (stage, engagement, host count it would touch, rate
cap, tools, and whether it sends traffic to the target). Building the preview only
READS the store and scope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional, Protocol

from ..engagement import list_engagements, load_engagement
from ..scope_guard import ScopeGuard
from ..seeds import enumeration_seeds
from ..store import Store
from .service import UnknownEngagement

# Per-process secret used to sign confirm tokens. A /api/run is accepted only if
# it carries a token this process minted for exactly that plan core, which both
# enforces the explicit confirm step and detects client-side tampering of the plan.
_CONFIRM_SECRET = secrets.token_bytes(32)


def plan_core(engagement: str, stage: Optional[str], params: dict) -> dict:
    """The execution-relevant subset of a plan that a confirm token binds to."""
    return {"engagement": engagement, "stage": stage, "params": params or {}}


def confirm_token(core: dict) -> str:
    msg = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_CONFIRM_SECRET, msg, hashlib.sha256).hexdigest()


def verify_token(core: dict, token: Optional[str]) -> bool:
    return bool(token) and hmac.compare_digest(confirm_token(core), token)

# stage -> prompt keywords that select it (checked as substrings, lowercased)
_STAGE_KEYWORDS = {
    "passive_recon": ["passive", "subdomain", "enumerat", "subfinder", "amass", "recon"],
    "dns_resolve": ["resolve", "resolution", "dns", "dnsx"],
    "liveness": ["live", "alive", "probe", "httpx", "http status", "status code", "http probe"],
    "signal_scan": ["nuclei", "signal", "vuln", "vulnerab", "template", "cve"],
}
# stage -> sends traffic to the target host?
_STAGE_TRAFFIC = {"passive_recon": False, "dns_resolve": False, "liveness": True,
                  "signal_scan": True}
# stages that accept a single --host (they hit the target per host)
_HOST_CAPABLE = ("liveness", "signal_scan")

_HOST_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b",
                      re.IGNORECASE)
_LIMIT_PATTERNS = [
    re.compile(r"\blimit\s+(\d+)"), re.compile(r"\bfirst\s+(\d+)"),
    re.compile(r"\btop\s+(\d+)"), re.compile(r"\b(\d+)\s+hosts?\b"),
]
_ONE_HOST_RE = re.compile(r"\b(?:one|a single|just one|single)\s+host\b")


@dataclass
class Intent:
    """What the interpreter understood from a prompt (engagement-independent)."""
    stage: Optional[str] = None
    params: dict = field(default_factory=dict)      # {"host": str, "limit": int}
    needs_clarification: bool = False
    message: str = ""


class PlanInterpreter(Protocol):
    """Swappable prompt->Intent backend (keyword today, LLM later)."""
    def interpret(self, prompt: str) -> Intent: ...


def _extract_host(prompt: str) -> Optional[str]:
    m = _HOST_RE.search(prompt)
    return m.group(1).lower() if m else None


def _extract_limit(low: str) -> Optional[int]:
    if _ONE_HOST_RE.search(low):
        return 1
    for pat in _LIMIT_PATTERNS:
        m = pat.search(low)
        if m:
            n = int(m.group(1))
            if n > 0:
                return n
    return None


class KeywordInterpreter:
    """Deterministic, rule-based prompt interpreter (no network, no LLM)."""

    def interpret(self, prompt: str) -> Intent:
        text = (prompt or "").strip()
        if not text:
            return Intent(needs_clarification=True,
                          message="Enter a prompt, e.g. 'enumerate subdomains', "
                                  "'resolve DNS', or 'probe live hosts'.")
        low = text.lower()
        host = _extract_host(text)
        limit = _extract_limit(low)
        matched = [s for s, kws in _STAGE_KEYWORDS.items() if any(k in low for k in kws)]

        # A specific host is only meaningful for host-capable stages (liveness /
        # signal_scan); CLI/web --host targets exactly one host.
        if host:
            others = [s for s in matched if s not in _HOST_CAPABLE]
            if others:
                return Intent(needs_clarification=True,
                              message=f"A specific host ({host}) can only be used by the "
                                      f"liveness or signal_scan stage, but the prompt also "
                                      f"asks for {', '.join(others)}. Rephrase to one stage.")
            hostcap = [s for s in matched if s in _HOST_CAPABLE]
            if len(hostcap) > 1:
                return Intent(needs_clarification=True,
                              message=f"Ambiguous: a host ({host}) with both "
                                      f"{', '.join(sorted(hostcap))}. Ask for one stage.")
            stage = hostcap[0] if hostcap else "liveness"   # default to liveness
            return Intent(stage=stage, params={"host": host})

        if not matched:
            return Intent(needs_clarification=True,
                          message="Couldn't tell which stage you mean. Try 'enumerate "
                                  "subdomains' (passive), 'resolve DNS' (dns_resolve), or "
                                  "'probe live hosts' (liveness).")
        if len(matched) > 1:
            return Intent(needs_clarification=True,
                          message="Ambiguous: the prompt matches multiple stages "
                                  f"({', '.join(sorted(matched))}). Ask for one at a time.")

        params: dict = {}
        if limit is not None and matched[0] in ("dns_resolve", "liveness"):
            params["limit"] = limit
        return Intent(stage=matched[0], params=params)


DEFAULT_INTERPRETER: PlanInterpreter = KeywordInterpreter()


@dataclass
class Plan:
    ok: bool
    engagement: str
    stage: Optional[str]
    params: dict
    preview: dict
    message: str
    needs_clarification: bool = False
    confirm_token: Optional[str] = None     # set only for an ok plan; required by /api/run

    def to_dict(self) -> dict:
        return asdict(self)


def _stage_tools(scope, stage: str) -> list[str]:
    """Allowlisted tools this stage would run, read from scope (no duplication of
    the stages' own selection beyond the passive filter)."""
    if stage == "dns_resolve":
        return [t for t in ("dnsx",) if t in scope.allowed_tools]
    if stage == "liveness":
        return [t for t in ("httpx",) if t in scope.allowed_tools]
    if stage == "signal_scan":
        return [t for t in ("nuclei",) if t in scope.allowed_tools]
    # passive_recon: passive subdomain tools (subfinder/amass), as the stage selects
    return sorted(t for t in ("subfinder", "amass") if t in scope.allowed_tools)


def _host_estimate(scope, store: Store, stage: str, params: dict) -> int:
    if params.get("host"):
        return 1
    if stage == "passive_recon":
        n = len(enumeration_seeds(scope))
    elif stage == "dns_resolve":
        n = store.count_assets("subdomain")
    elif stage == "signal_scan":        # live hosts not yet signal-scanned
        n = store.count_assets("subdomain", flag_true="live", flag_absent="signal_scanned_at_run")
    else:  # liveness: resolved hosts not yet probed
        n = store.count_assets("subdomain", flag_true="resolves", flag_absent="probed_at_run")
    limit = params.get("limit")
    return min(n, limit) if limit else n


def _rate_cap(scope, stage: str) -> str:
    if not _STAGE_TRAFFIC[stage]:
        return "n/a (no traffic to target)"
    eff = scope.limits.effective(force_safe_mode=scope.limits.safe_mode)
    rps = eff.max_rps_per_host
    rps_s = f"{rps:g}"
    return f"{rps_s} rps/host" + (" (safe mode)" if eff.safe_mode else "")


def build_plan(base_dir: str | Path, engagement: str, stage: Optional[str],
               params: Optional[dict]) -> Plan:
    """Validate a (stage, params) for an engagement and build its preview Plan.
    Reads only; executes nothing. This is the authoritative server-side validation
    reused by both /api/plan and /api/run (so a run never trusts the client plan):
    it re-checks the engagement, the stage, scope (host gate), and tool
    availability. Raises UnknownEngagement for an unknown engagement."""
    if engagement not in list_engagements(base_dir):
        raise UnknownEngagement(engagement)
    if stage not in _STAGE_TRAFFIC:
        return Plan(ok=False, engagement=engagement, stage=stage, params=params or {},
                    preview={}, message=f"Unknown stage {stage!r}.")

    scope = load_engagement(engagement, base_dir)
    params = dict(params or {})

    # A --host must pass the scope gate, exactly like the runner enforces.
    host = params.get("host")
    if host:
        dec = ScopeGuard(scope).check(host)
        if not dec.allowed:
            return Plan(ok=False, engagement=engagement, stage=stage, params=params,
                        preview={}, needs_clarification=False,
                        message=f"Host {host!r} is out of scope for {engagement}: {dec.reason}. "
                                f"Nothing will run.")
        params["host"] = dec.host

    store = Store.open_for_engagement(engagement, base_dir=base_dir)
    try:
        tools = _stage_tools(scope, stage)
        hosts = _host_estimate(scope, store, stage, params)
    finally:
        store.close()

    sends = _STAGE_TRAFFIC[stage]
    rate = _rate_cap(scope, stage)
    scope_note = f"host {params['host']}" if host else f"{hosts} host(s)"
    summary = (f"{stage} on {engagement}: {scope_note}, tools {', '.join(tools) or '(none)'}, "
               f"rate {rate}, " + ("SENDS TRAFFIC to target" if sends else "no target traffic"))
    preview = {
        "stage": stage, "engagement": engagement, "hosts": hosts, "rate_cap": rate,
        "tools": tools, "sends_traffic": sends, "params": params, "summary": summary,
    }
    if not tools:
        return Plan(ok=False, engagement=engagement, stage=stage, params=params,
                    preview=preview, needs_clarification=False,
                    message=f"No allowlisted tool for {stage} in {engagement}; nothing to run.")
    token = confirm_token(plan_core(engagement, stage, params))
    return Plan(ok=True, engagement=engagement, stage=stage, params=params,
                preview=preview, message=summary, confirm_token=token)


def plan(base_dir: str | Path, engagement: str, prompt: str,
         interpreter: PlanInterpreter = DEFAULT_INTERPRETER) -> Plan:
    """Interpret ``prompt`` for ``engagement`` and build a preview Plan."""
    if engagement not in list_engagements(base_dir):
        raise UnknownEngagement(engagement)
    intent = interpreter.interpret(prompt)
    if intent.needs_clarification or not intent.stage:
        return Plan(ok=False, engagement=engagement, stage=None, params={},
                    preview={}, message=intent.message, needs_clarification=True)
    return build_plan(base_dir, engagement, intent.stage, intent.params)
