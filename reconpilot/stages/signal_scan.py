"""Stage 4: signal_scan — nuclei over LIVE hosts (PLUMBING ONLY; seam unwired).

This stage is built out exactly like liveness was before wiring: all orchestration
(input selection, chunking, incremental + interrupt-safe ingest, scope filtering,
findings storage) is here and tested with fakes, but the one call that actually runs
nuclei — ``NucleiStage.invoke_tool`` — raises NotImplementedError with a TODO. No
nuclei is invoked; no network.

Policy (reuses the engagement's existing ``http:`` block, which the GuardedRunner
already enforces for active tools):
  * engagement User-Agent injected into nuclei (ToolSpec.ua_arg), same as httpx;
  * ``no_third_party_oob`` -> nuclei runs with ``-no-interactsh`` (ToolSpec.no_oob_arg)
    so it makes no third-party OOB callback (Amazon allows no public interactsh);
  * rate-limited through the SAME per-host limiter as httpx — nuclei hits the target,
    so it is NOT resolver/passive and keeps the rate cap;
  * templates default to lower-noise groups (ToolSpec.templates_default), configurable.

Findings are stored as LEADS, never reportable bugs: raw scanner output is out of
scope AS A REPORT on this program, so every finding is labelled
``lead — needs manual PoC``. Each finding's host is scope-filtered before storage
(dropped + audited otherwise).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..audit_log import AuditLog
from ..config import Scope, ToolSpec
from ..scope_guard import ScopeGuard, normalize_target
from ..store import Store
from ._ingest import choose_output, chunked

# Every stored finding is a lead, not a reportable bug (raw scanner output is
# out-of-scope-as-a-report on this program).
LEAD_LABEL = "lead — needs manual PoC"
# nuclei colorizes by default; -nc disables it, but strip SGR escapes defensively
# (existing output files / older builds), like dnsx.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_nuclei_jsonl(path: str | Path) -> list[dict]:
    """Parse a nuclei ``-jsonl`` output file into normalized finding dicts.

    Fields vary by nuclei version; probe the common spellings. ANSI color escapes
    and CR are stripped before JSON parsing. Non-JSON / blank lines are skipped.
    """
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = _ANSI_RE.sub("", line).strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info") or {}
        tid = rec.get("template-id") or rec.get("templateID") or rec.get("template_id") or ""
        matched = (rec.get("matched-at") or rec.get("matched_at")
                   or rec.get("matched") or rec.get("url") or "")
        out.append({
            "template_id": tid,
            "name": info.get("name") or tid or "(unnamed)",
            "severity": (info.get("severity") or "unknown"),
            "host": rec.get("host") or matched,
            "matched_at": matched,
            "type": rec.get("type") or "",
        })
    return out


@dataclass
class SignalScanResult:
    run_id: int
    hosts_scanned: int
    findings: int                                  # LEADS stored
    dropped: int                                   # findings dropped (out of scope)
    dropped_examples: list[tuple[str, str]] = field(default_factory=list)  # (host, rule)
    interrupted: bool = False
    interrupt_reason: str = ""
    dry_run: bool = False

    def summary_text(self) -> str:
        if self.dry_run:
            return f"[signal_scan] DRY RUN — would scan {self.hosts_scanned} live host(s)"
        status = (f"INTERRUPTED ({self.interrupt_reason}) — partial results stored"
                  if self.interrupted else "completed")
        lines = [
            f"[signal_scan] run #{self.run_id}: {status}",
            f"  hosts scanned        : {self.hosts_scanned}",
            f"  findings (LEADS)     : {self.findings}  [{LEAD_LABEL}]",
            f"  dropped out-of-scope : {self.dropped}",
        ]
        for host, rule in self.dropped_examples[:10]:
            lines.append(f"    {host}  [{rule}]")
        return "\n".join(lines)


class NucleiStage:
    STAGE = "signal_scan"
    TOOL = "nuclei"
    DEFAULT_CHUNK = 200      # nuclei is heavier per host than httpx; keep chunks small

    def __init__(self, scope: Scope, registry: dict[str, ToolSpec], store: Store,
                 audit: AuditLog, runner, output_dir: str | Path):
        self.scope = scope
        self.registry = registry
        self.store = store
        self.audit = audit
        self.runner = runner
        self.output_dir = Path(output_dir)
        # Guard for filtering FINDING hosts before storage (we emit our own
        # finding_dropped audit event).
        self.guard = ScopeGuard(scope)
        if self.TOOL not in scope.allowed_tools:
            raise ValueError(f"signal_scan: '{self.TOOL}' is not in allowed_tools")

    # -- stage input: LIVE hosts not yet signal-scanned ---------------------- #
    def hosts_to_scan(self, limit: Optional[int] = None) -> list[str]:
        """Live subdomains (liveness live=true) not yet scanned this cycle. A
        scanned host carries ``signal_scanned_at_run``, so a resume continues with
        the remaining live hosts instead of restarting."""
        return self.store.keys_flagged("subdomain", true_flag="live",
                                       null_flag="signal_scanned_at_run", limit=limit)

    # -- ingest (parse + scope-filter + store as LEADS), incremental --------- #
    def ingest_nuclei_file(self, path: str | Path, run_id: int
                           ) -> tuple[int, int, list[tuple[str, str]]]:
        """Parse one nuclei JSONL file; scope-filter each finding's host and store
        the in-scope ones as LEADS. Returns (stored, dropped, dropped_examples)."""
        stored = 0
        dropped_examples: list[tuple[str, str]] = []
        for f in parse_nuclei_jsonl(path):
            host = normalize_target(f["host"]) or f["host"]
            dec = self.guard.check(host)
            if not dec.allowed:
                rule = dec.matched_rule or dec.reason
                self.audit.log_event("finding_dropped", stage=self.STAGE, run=run_id,
                                     host=host, matched_rule=rule,
                                     template_id=f["template_id"])
                dropped_examples.append((host, rule))
                continue
            self.store.upsert_finding(
                tool=self.TOOL, name=f["name"], target=dec.host, severity=f["severity"],
                matched_at=f["matched_at"], run_id=run_id,
                attrs={"lead": True, "label": LEAD_LABEL, "template_id": f["template_id"],
                       "type": f["type"], "matched_at": f["matched_at"]})
            stored += 1
        return stored, len(dropped_examples), dropped_examples

    # -- execution seam (wire this to the real runner) ----------------------- #
    def invoke_tool(self, hosts: list[str], out_dir: Path):
        res = self.runner.run(self.TOOL, hosts, out_dir)
        return res.invocations

    # -- orchestration ------------------------------------------------------- #
    def run(self, dry_run: bool = False,
            executor: Optional[Callable[[list[str], Path], Iterable]] = None,
            limit: Optional[int] = None,
            hosts: Optional[list[str]] = None) -> SignalScanResult:
        hosts = list(hosts) if hosts is not None else self.hosts_to_scan(limit=limit)
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = self.output_dir / tag
        if dry_run:
            return SignalScanResult(run_id=0, hosts_scanned=len(hosts), findings=0,
                                    dropped=0, dry_run=True)

        run = executor or (lambda hosts_, out_: self.invoke_tool(hosts_, out_))
        chunk_size = self.scope.limits.chunk_size(self.STAGE, self.DEFAULT_CHUNK)
        run_id = self.store.start_run(self.STAGE, tool=self.TOOL, note=json.dumps(
            {"artifacts": str(base), "live_input": len(hosts), "chunk_size": chunk_size}))
        scanned = findings = dropped = chunks_done = 0
        drop_examples: list[tuple[str, str]] = []
        try:
            # chunk so each nuclei invocation fits the timeout; rate limiter spans
            # chunks (aggregate rate unchanged). Ingest + mark scanned after EACH
            # chunk so an interrupt/kill keeps every finished chunk's findings.
            for ci, chunk in enumerate(chunked(hosts, chunk_size)):
                for inv in run(chunk, base / f"chunk-{ci:04d}") or []:
                    if inv.exit_code == 0 or getattr(inv, "timed_out", False):
                        path = choose_output(inv, parse_nuclei_jsonl)
                        if path:
                            s, d, ex = self.ingest_nuclei_file(path, run_id)
                            findings += s; dropped += d; drop_examples += ex
                # mark every attempted host scanned so a resume skips them
                for host in chunk:
                    self.store.upsert_asset("subdomain", host, run_id,
                                            attrs={"signal_scanned_at_run": run_id})
                scanned += len(chunk)
                chunks_done += 1
                self.audit.log_event("chunk_completed", stage=self.STAGE, run=run_id,
                                     chunk=ci, hosts=len(chunk), findings=findings,
                                     dropped=dropped)
        except BaseException as e:  # noqa: BLE001 - Ctrl-C included: finalize first
            reason = type(e).__name__ if isinstance(e, KeyboardInterrupt) \
                else f"{type(e).__name__}: {e}"
            self.store.finish_run(run_id, status="interrupted", note=json.dumps(
                {"artifacts": str(base), "reason": reason, "findings": findings,
                 "dropped": dropped, "chunks_done": chunks_done}))
            self.audit.log_event("run_interrupted", stage=self.STAGE, run=run_id,
                                 reason=reason, findings=findings, chunks_done=chunks_done)
            if not isinstance(e, KeyboardInterrupt):
                raise
            return SignalScanResult(
                run_id=run_id, hosts_scanned=scanned, findings=findings, dropped=dropped,
                dropped_examples=drop_examples, interrupted=True, interrupt_reason=reason)

        self.store.finish_run(run_id, status="completed")
        return SignalScanResult(run_id=run_id, hosts_scanned=scanned, findings=findings,
                                dropped=dropped, dropped_examples=drop_examples)
