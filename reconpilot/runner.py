"""The generic guarded runner: the ONLY path from a tool spec to a subprocess.

Every invocation is forced through, in order:

    1. tool allowlist + presence   (tool_detect.require_tool)
    2. scope gate on every target  (scope_guard.filter — out-of-scope dropped)
    3. rate limiting               (per-host token bucket OR {rps} + breaker)
    4. audit log                   (command, targets, exit code, duration)

It builds an ``argv`` list and runs it with ``shell=False`` — there is no shell,
so a target string can never inject a flag or a command; combined with the scope
gate (which rejects anything not matching an in-scope host/CIDR), argument
injection via a crafted target is closed off too.

Read-only posture: the runner only ever runs the exact args from tools.yaml. It
adds no flags, follows no redirects of its own, submits nothing. Which tools and
flag-sets are permitted for an engagement is decided upstream (allowlist +
posture flags + the plan-confirm step); the runner is the mechanism, not the policy.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .audit_log import AuditLog
from .config import Scope, ToolSpec
from .errors import RunnerError
from .rate_limiter import RateLimiter
from .scope_guard import ScopeDecision, ScopeGuard
from .tool_detect import detect_tool, require_tool

# A tool's args reference its batch input file by one of these names; they all
# resolve to the single input file the runner writes from the in-scope targets.
_FILE_KEYS = ("targets_file", "urls_file", "hosts_file")
_PLACEHOLDER_RE = re.compile(r"\{[a-z_]+\}")


def _utc_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:80] or "x"


# --------------------------------------------------------------------------- #
# Pure command builder (no I/O, no exec) — the testable core.
# --------------------------------------------------------------------------- #
def build_command(spec: ToolSpec, binary: str, *,
                  target: Optional[str] = None,
                  input_file: Optional[str] = None,
                  output: Optional[str] = None,
                  rps: Optional[int] = None,
                  concurrency: Optional[int] = None,
                  wordlist: Optional[str] = None,
                  templates: Optional[str] = None,
                  extra_args: Optional[list[str]] = None) -> list[str]:
    """Substitute placeholders in ``spec.args`` and return an argv list.

    Tokenizes first (shlex), then replaces placeholders inside each token, so a
    substituted value containing spaces stays one argv element and a token like
    ``{target}/FUZZ`` is handled correctly. Any unsubstituted ``{placeholder}``
    left over is a RunnerError — we never exec a half-formed command line.
    """
    subs: dict[str, Optional[str]] = {
        "target": target,
        "output": output,
        "rps": None if rps is None else str(rps),
        "concurrency": None if concurrency is None else str(concurrency),
        "wordlist": wordlist,
        "templates": templates,
    }
    for key in _FILE_KEYS:
        subs[key] = input_file

    argv = [binary]
    for tok in shlex.split(spec.args):
        for key, val in subs.items():
            needle = "{" + key + "}"
            if needle in tok:
                if val is None:
                    raise RunnerError(
                        f"tool '{spec.name}': args need '{needle}' but no value was provided")
                tok = tok.replace(needle, val)
        argv.append(tok)

    # Already-substituted policy args (UA header, OOB-disable flags) appended last.
    argv.extend(extra_args or [])

    leftover = [t for t in argv if _PLACEHOLDER_RE.search(t)]
    if leftover:
        raise RunnerError(
            f"tool '{spec.name}': unresolved placeholders in command: {leftover}")
    return argv


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
@dataclass
class Invocation:
    """One subprocess (or planned subprocess, in dry-run)."""
    tool: str
    target: str                      # the specific target, or "batch:<n>"
    command: list[str]
    output_path: str
    exit_code: Optional[int] = None  # None = not executed (dry-run / skipped)
    duration_s: float = 0.0
    error: str = ""                  # populated on timeout / exec failure
    stdout_tail: str = ""
    stderr_tail: str = ""


@dataclass
class RunResult:
    tool: str
    stage: str
    mode: str                        # "per_target" | "batch" | "single"
    dry_run: bool
    tool_available: bool
    allowed: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)
    skipped_reason: str = ""

    @property
    def ran(self) -> bool:
        return any(iv.exit_code is not None for iv in self.invocations)

    @property
    def ok(self) -> bool:
        return self.ran and all(iv.exit_code == 0 for iv in self.invocations)


# --------------------------------------------------------------------------- #
# The runner
# --------------------------------------------------------------------------- #
class GuardedRunner:
    def __init__(self, scope: Scope, registry: dict[str, ToolSpec], audit: AuditLog,
                 *, rate_limiter: Optional[RateLimiter] = None,
                 guard: Optional[ScopeGuard] = None,
                 force_safe_mode: bool = False,
                 which: Callable[[str], Optional[str]] = __import__("shutil").which,
                 default_timeout_s: int = 1800):
        self.scope = scope
        self.registry = registry
        self.audit = audit
        self.which = which
        self.default_timeout_s = default_timeout_s
        self.rl = rate_limiter or RateLimiter(scope.limits, force_safe_mode=force_safe_mode)
        # Guard audits through the same engagement log, satisfying its
        # "audit sink must be thread-safe" contract (AuditLog holds a lock).
        self.guard = guard or ScopeGuard(scope, audit=audit.log_scope_decision)

    # -- public API ---------------------------------------------------------- #
    def run(self, tool: str, targets: list[str], output_dir: str | Path, *,
            wordlist: Optional[str] = None, templates: Optional[str] = None,
            dry_run: bool = False, timeout_s: Optional[int] = None) -> RunResult:
        spec = self.registry.get(tool)
        if spec is None:
            # require_tool raises with the right message; surfaces not_in_registry too
            require_tool(tool, self.registry, self.scope, which=self.which)

        status = detect_tool(tool, self.registry, self.scope, which=self.which)
        if not dry_run and not status.available:
            # real runs must have a usable tool — raises with install hint etc.
            require_tool(tool, self.registry, self.scope, which=self.which)

        mode = self._mode(spec)
        result = RunResult(tool=tool, stage=spec.stage, mode=mode,
                           dry_run=dry_run, tool_available=status.available)

        # 1b. HTTP policy (item 3): refuse / skip before doing any work.
        http_args, skip_reason, refuse_reason = self._http_policy(spec)
        if refuse_reason:
            self.audit.log_event("tool_refused", tool=tool, reason=refuse_reason)
            if not dry_run:
                raise RunnerError(refuse_reason)
            result.skipped_reason = refuse_reason
            return result
        if skip_reason:
            self.audit.log_event("tool_skipped", tool=tool, reason=skip_reason)
            result.skipped_reason = skip_reason
            return result

        # 2. scope gate — every target decided + audited by the guard
        allowed_dec, rejected_dec = self.guard.filter(targets)
        result.allowed = [d.target for d in allowed_dec]
        result.rejected = [d.target for d in rejected_dec]

        if mode in ("per_target", "batch") and not allowed_dec:
            result.skipped_reason = "no in-scope targets"
            self.audit.log_event("tool_skipped", tool=tool, reason=result.skipped_reason,
                                 rejected=len(rejected_dec))
            return result

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        eff = self.scope.limits.effective(force_safe_mode=self.rl.safe_mode)
        rps = max(1, int(eff.max_rps_per_host))
        conc = eff.max_global_concurrency
        tmpl = templates or spec.templates_default or None
        binary = status.path or spec.binary

        if mode == "per_target":
            for dec in allowed_dec:
                result.invocations.append(self._run_per_target(
                    spec, binary, dec, out_dir, rps, conc, wordlist, tmpl,
                    dry_run, timeout_s, http_args))
        elif mode == "batch":
            result.invocations.append(self._run_batch(
                spec, binary, allowed_dec, out_dir, rps, conc, wordlist, tmpl,
                dry_run, timeout_s, http_args))
        else:  # single
            result.invocations.append(self._run_single(
                spec, binary, out_dir, rps, conc, wordlist, tmpl, dry_run, timeout_s,
                http_args))
        return result

    # -- HTTP policy (item 3) ----------------------------------------------- #
    def _http_policy(self, spec: ToolSpec) -> tuple[list[str], Optional[str], Optional[str]]:
        """Return ``(extra_args, skip_reason, refuse_reason)`` for a tool.

        Only ACTIVE tools are subject to HTTP policy; passive/local tools (and
        active non-HTTP tools like dnsx, which declare no ``ua_arg``) get nothing.
        - refuse: require_user_agent set but UA missing/placeholder -> hard stop.
        - skip:   tool requires third-party OOB but no_third_party_oob is set.
        - extra:  the UA header flag and/or OOB-disable flag to append.
        """
        http = self.scope.http
        if not spec.active:
            return [], None, None

        extra: list[str] = []
        ua_capable = bool(spec.ua_arg)

        if ua_capable:
            if http.require_user_agent and not http.user_agent_is_valid():
                return [], None, (
                    f"refusing to launch active tool '{spec.name}': "
                    "http.require_user_agent is set but http.user_agent is empty or a "
                    "placeholder (set a real User-Agent in the engagement file)")
            if http.user_agent_is_valid():
                extra += self._subst(spec.ua_arg, {"user_agent": http.user_agent})

        if http.no_third_party_oob:
            if spec.requires_oob:
                return [], (
                    f"skipping '{spec.name}': it can only work via a third-party OOB "
                    "callback, which http.no_third_party_oob disables"), None
            if spec.no_oob_arg:
                extra += shlex.split(spec.no_oob_arg)

        return extra, None, None

    @staticmethod
    def _subst(template: str, subs: dict[str, str]) -> list[str]:
        toks = []
        for tok in shlex.split(template):
            for k, v in subs.items():
                tok = tok.replace("{" + k + "}", v)
            toks.append(tok)
        return toks

    # -- what string to feed the tool --------------------------------------- #
    @staticmethod
    def _feed(spec: ToolSpec, dec: ScopeDecision) -> str:
        """URL-oriented tools get the full target (scheme/path preserved);
        domain/host tools get the normalized bare host. The scope decision is
        always made on the host, but what we hand the tool depends on its input
        type — e.g. subfinder wants ``api.acme.com``, katana wants the URL."""
        return dec.target if spec.input == "urls_file" else dec.host

    # -- mode detection ------------------------------------------------------ #
    @staticmethod
    def _uses_file(spec: ToolSpec) -> bool:
        return any(("{" + k + "}") in spec.args for k in _FILE_KEYS)

    @classmethod
    def _mode(cls, spec: ToolSpec) -> str:
        if cls._uses_file(spec):
            return "batch"
        if "{target}" in spec.args:
            return "per_target"
        return "single"

    # -- per-target ---------------------------------------------------------- #
    def _run_per_target(self, spec, binary, dec: ScopeDecision, out_dir, rps, conc,
                        wordlist, templates, dry_run, timeout_s, http_args) -> Invocation:
        out_path = out_dir / f"{_safe(spec.name)}-{_safe(dec.host)}-{_utc_tag()}.out"
        writes_own = "{output}" in spec.args
        cmd = build_command(spec, binary, target=self._feed(spec, dec),
                            output=str(out_path) if writes_own else None,
                            rps=rps, concurrency=conc, wordlist=wordlist, templates=templates,
                            extra_args=http_args)
        if dry_run:
            return Invocation(spec.name, dec.target, cmd, str(out_path))
        # 3. rate limit this single request against the per-host bucket + breaker
        self.rl.acquire(dec.host)
        return self._exec(spec, cmd, dec.target, out_path, writes_own, timeout_s)

    # -- batch (file input; tool self-paces via {rps}) ----------------------- #
    def _run_batch(self, spec, binary, allowed_dec, out_dir, rps, conc,
                   wordlist, templates, dry_run, timeout_s, http_args) -> Invocation:
        tag = _utc_tag()
        in_path = out_dir / f"input-{_safe(spec.name)}-{tag}.txt"
        in_path.write_text("".join(self._feed(spec, d) + "\n" for d in allowed_dec),
                           encoding="utf-8")
        out_path = out_dir / f"{_safe(spec.name)}-batch-{tag}.out"
        writes_own = "{output}" in spec.args
        cmd = build_command(spec, binary, input_file=str(in_path),
                            output=str(out_path) if writes_own else None,
                            rps=rps, concurrency=conc, wordlist=wordlist, templates=templates,
                            extra_args=http_args)
        label = f"batch:{len(allowed_dec)}"
        if dry_run:
            return Invocation(spec.name, label, cmd, str(out_path))
        # 3. count the batch against the breaker; the tool enforces per-host rps
        self.rl.charge(len(allowed_dec))
        return self._exec(spec, cmd, label, out_path, writes_own, timeout_s)

    def _run_single(self, spec, binary, out_dir, rps, conc, wordlist, templates,
                    dry_run, timeout_s, http_args) -> Invocation:
        out_path = out_dir / f"{_safe(spec.name)}-{_utc_tag()}.out"
        writes_own = "{output}" in spec.args
        cmd = build_command(spec, binary, output=str(out_path) if writes_own else None,
                            rps=rps, concurrency=conc, wordlist=wordlist, templates=templates,
                            extra_args=http_args)
        if dry_run:
            return Invocation(spec.name, "single", cmd, str(out_path))
        self.rl.charge(1)
        return self._exec(spec, cmd, "single", out_path, writes_own, timeout_s)

    # -- execution ----------------------------------------------------------- #
    def _exec(self, spec, cmd, target, out_path, writes_own, timeout_s) -> Invocation:
        timeout = timeout_s or self.default_timeout_s
        run_id = self.audit.log_tool_start(spec.name, target, cmd, stage=spec.stage)
        started = time.monotonic()
        inv = Invocation(spec.name, target, cmd, str(out_path))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, shell=False)
            inv.exit_code = proc.returncode
            inv.stdout_tail = (proc.stdout or "")[-2000:]
            inv.stderr_tail = (proc.stderr or "")[-2000:]
            if writes_own:
                # tool wrote out_path itself; keep stdout/stderr alongside for debugging
                Path(str(out_path) + ".log").write_text(
                    (proc.stdout or "") + (proc.stderr or ""), encoding="utf-8")
            else:
                Path(out_path).write_text(proc.stdout or "", encoding="utf-8")
        except subprocess.TimeoutExpired:
            inv.exit_code = -1
            inv.error = f"timeout after {timeout}s"
        except (OSError, ValueError) as e:  # exec failure, bad binary, etc.
            inv.exit_code = -1
            inv.error = f"{type(e).__name__}: {e}"
        inv.duration_s = round(time.monotonic() - started, 3)
        self.audit.log_tool_end(run_id, spec.name, target, exit_code=inv.exit_code,
                                duration_s=inv.duration_s, output_path=str(out_path),
                                extra={"error": inv.error} if inv.error else None)
        return inv
