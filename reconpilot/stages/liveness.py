"""Stage 3: liveness — HTTP liveness probing of RESOLVED hosts with httpx.

This is the first stage that sends real HTTP to target hosts, so the actual
execution is deliberately NOT performed here. This module owns only the offline
parts — parsing httpx JSONL output, applying the redirect-drop policy, and
storing results — all tested with fakes. The one network call lives behind
``LivenessStage.invoke_tool`` (a clearly-marked seam, left unimplemented), which,
when wired to the EXISTING GuardedRunner, inherits every guard already proven by
tests: engagement User-Agent injection, the per-host rate limiter + global
concurrency cap, and the run-wide circuit breaker.

Redirects are NOT followed (scope safety): httpx runs without ``-fr``, so it never
issues a request to a redirect target. Instead the ``Location`` header is read
from the ``-json`` output and the redirect-TARGET host is evaluated:
  * matches an engagement ``drop_on_redirect_to`` pattern (``*.aws.amazon.com`` /
    ``midway-auth.amazon.com``) -> dropped + audited (``drop_on_redirect``);
  * otherwise fails the scope guard -> dropped + audited (out-of-scope redirect);
  * in-scope -> stored normally, with the redirect target recorded.
Nothing is ever dropped silently, and the target is never requested.

Liveness fields are stored on the subdomain asset's ``attrs`` JSON:
    live            : bool
    status_code     : int
    title           : str
    tech            : list[str]
    url             : str        # the probed URL (not followed)
    location        : str        # raw Location header, if any
    redirect_target : str        # redirect target host, if in-scope
    probed_at_run   : int
and for a dropped redirect: ``live=False`` + ``dropped_by_redirect=<rule>``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..audit_log import AuditLog
from ..config import Scope, ToolSpec
from ..http_policy import filter_on_redirect, redirect_target_host
from ..scope_guard import ScopeGuard, normalize_target
from ..store import Store

# httpx JSON keys vary by version; probe a few for each field.
_TECH_KEYS = ("tech", "technologies")


def _tech(rec: dict) -> list[str]:
    for k in _TECH_KEYS:
        v = rec.get(k)
        if isinstance(v, list) and v:
            return [str(x) for x in v]
    return []


def parse_httpx_jsonl(path: str | Path) -> list[dict]:
    """Parse an httpx ``-json`` output file (one JSON object per line) into a list
    of raw records. Malformed/blank lines are skipped. No filtering here — scope
    was enforced upstream and the redirect-drop policy is applied at ingest."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _input_host(rec: dict) -> str:
    """The host we fed httpx (the asset key to enrich), normalized."""
    for k in ("input", "host", "url"):
        v = rec.get(k)
        if v:
            h = normalize_target(str(v))
            if h:
                return h
    return ""


def liveness_attrs(rec: dict, run_id: int, redirect_target: str = "") -> dict:
    return {
        "live": True,
        "status_code": rec.get("status_code") or rec.get("status-code"),
        "title": rec.get("title", ""),
        "tech": _tech(rec),
        "url": rec.get("url", ""),                 # probed URL (NOT followed)
        "location": rec.get("location", ""),       # raw Location header, if any
        "redirect_target": redirect_target,        # in-scope redirect host, if any
        "probed_at_run": run_id,
    }


@dataclass
class LivenessResult:
    run_id: int
    probed: int
    live: int
    dropped_redirect: int
    dropped_examples: list[tuple[str, str, str]] = field(default_factory=list)  # in,final,rule
    interrupted: bool = False
    interrupt_reason: str = ""
    dry_run: bool = False

    def summary_text(self) -> str:
        if self.dry_run:
            return f"[liveness] DRY RUN — would probe {self.probed} resolved hosts"
        status = (f"INTERRUPTED ({self.interrupt_reason}) — partial results stored"
                  if self.interrupted else "completed")
        lines = [
            f"[liveness] run #{self.run_id}: {status}",
            f"  probed (parsed)     : {self.probed}",
            f"  live kept           : {self.live}",
            f"  dropped on redirect : {self.dropped_redirect}",
        ]
        for inp, fin, rule in self.dropped_examples[:10]:
            lines.append(f"    {inp} -> {fin}  [{rule}]")
        return "\n".join(lines)


class LivenessStage:
    STAGE = "liveness"
    TOOL = "httpx"

    def __init__(self, scope: Scope, registry: dict[str, ToolSpec], store: Store,
                 audit: AuditLog, runner, output_dir: str | Path):
        self.scope = scope
        self.registry = registry
        self.store = store
        self.audit = audit
        self.runner = runner
        self.output_dir = Path(output_dir)
        # Non-auditing guard for checking redirect TARGETS (we emit our own
        # drop_on_redirect event); keeps one clear audit line per dropped target.
        self.guard = ScopeGuard(scope)
        if self.TOOL not in scope.allowed_tools:
            raise ValueError(f"liveness: '{self.TOOL}' is not in allowed_tools")

    # -- stage input: ONLY hosts that resolved in dns_resolve ---------------- #
    def hosts_to_probe(self, limit: Optional[int] = None) -> list[str]:
        return self.store.keys_where_flag("subdomain", "resolves", True, limit=limit)

    # -- ingest (parse + redirect-target policy + store), incremental -------- #
    def _drop(self, rec: dict, run_id: int, rule: str,
              examples: list[tuple[str, str, str]]) -> None:
        inp, tgt = _input_host(rec), redirect_target_host(rec)
        self.audit.log_event("drop_on_redirect", stage=self.STAGE, run=run_id,
                             input_host=inp, final_host=tgt, matched_rule=rule,
                             status_code=rec.get("status_code"))
        if inp:
            self.store.upsert_asset("subdomain", inp, run_id, attrs={
                "live": False, "dropped_by_redirect": rule, "probed_at_run": run_id})
        examples.append((inp, tgt, rule))

    def ingest_httpx_file(self, path: str | Path, run_id: int
                          ) -> tuple[int, int, list[tuple[str, str, str]]]:
        """Parse one httpx JSONL file and persist immediately. Redirects are not
        followed: each record's redirect TARGET (Location) is checked against the
        drop patterns and then the scope guard; out-of-scope targets are dropped +
        audited, in-scope redirects are stored. Returns (live_kept, dropped,
        dropped_examples)."""
        records = parse_httpx_jsonl(path)
        patterns = self.scope.http.drop_on_redirect_to
        redirecting = [r for r in records if redirect_target_host(r)]
        direct = [r for r in records if not redirect_target_host(r)]

        # 1. pattern drop (aws/midway) on the redirect TARGET, never followed
        kept_pat, dropped_pat = filter_on_redirect(
            redirecting, patterns, host_of=redirect_target_host)

        drop_examples: list[tuple[str, str, str]] = []
        for rec in dropped_pat:
            self._drop(rec, run_id, str(rec.get("_dropped_by", "drop_on_redirect_to")),
                       drop_examples)

        live = 0
        # 2. redirects that passed the patterns: scope-check the target
        for rec in kept_pat:
            tgt = redirect_target_host(rec)
            dec = self.guard.check(tgt)
            if not dec.allowed:
                self._drop(rec, run_id,
                           f"out_of_scope_redirect:{dec.matched_rule or dec.reason}",
                           drop_examples)
                continue
            inp = _input_host(rec)
            if inp:
                self.store.upsert_asset("subdomain", inp, run_id,
                                        attrs=liveness_attrs(rec, run_id, redirect_target=tgt))
                live += 1

        # 3. non-redirecting responses: store as live
        for rec in direct:
            inp = _input_host(rec)
            if inp:
                self.store.upsert_asset("subdomain", inp, run_id, attrs=liveness_attrs(rec, run_id))
                live += 1
        return live, len(drop_examples), drop_examples

    # -- execution seam (wire this to the real runner) ----------------------- #
    def invoke_tool(self, hosts: list[str], out_dir: Path):
        res = self.runner.run(self.TOOL, hosts, out_dir)   # batch mode, not seed
        return res.invocations

    # -- orchestration ------------------------------------------------------- #
    def run(self, dry_run: bool = False,
            executor: Optional[Callable[[list[str], Path], Iterable]] = None,
            limit: Optional[int] = None) -> LivenessResult:
        hosts = self.hosts_to_probe(limit=limit)
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = self.output_dir / tag
        if dry_run:
            return LivenessResult(run_id=0, probed=len(hosts), live=0,
                                  dropped_redirect=0, dry_run=True)

        run = executor or (lambda hosts_, out_: self.invoke_tool(hosts_, out_))
        run_id = self.store.start_run(self.STAGE, tool=self.TOOL, note=json.dumps(
            {"artifacts": str(base), "resolved_input": len(hosts)}))
        probed = live = dropped = 0
        drop_examples: list[tuple[str, str, str]] = []
        try:
            for inv in run(hosts, base) or []:
                ok = inv.exit_code == 0 or getattr(inv, "timed_out", False)
                if ok and inv.output_path:
                    probed += len(parse_httpx_jsonl(inv.output_path))
                    l, d, ex = self.ingest_httpx_file(inv.output_path, run_id)
                    live += l; dropped += d; drop_examples += ex
        except BaseException as e:  # noqa: BLE001 - Ctrl-C included: finalize first
            reason = type(e).__name__ if isinstance(e, KeyboardInterrupt) \
                else f"{type(e).__name__}: {e}"
            self.store.finish_run(run_id, status="interrupted", note=json.dumps(
                {"artifacts": str(base), "reason": reason, "live": live, "dropped": dropped}))
            self.audit.log_event("run_interrupted", stage=self.STAGE, run=run_id,
                                 reason=reason, live=live, dropped=dropped)
            if not isinstance(e, KeyboardInterrupt):
                raise
            return LivenessResult(
                run_id=run_id, probed=probed, live=live, dropped_redirect=dropped,
                dropped_examples=drop_examples, interrupted=True, interrupt_reason=reason)

        self.store.finish_run(run_id, status="completed")
        return LivenessResult(run_id=run_id, probed=probed, live=live,
                              dropped_redirect=dropped, dropped_examples=drop_examples)
