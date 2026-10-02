"""Stage 1: passive_recon — subdomain enumeration from third-party datasets.

Genuinely passive: it runs only tools marked ``active: false`` whose output is
``subdomains`` (subfinder, amass passive). It never sends traffic to the target.

Flow:
  1. derive enumeration roots from the engagement in_scope — a ``*.X`` wildcard
     contributes X as a SEED even when apex X is not itself an in-scope target
     (see ``reconpilot.seeds``)
  2. run each passive tool on ONE root at a time via the guarded runner in seed
     mode (seed gate + ``seed_decision`` audit, allowlist/rate/timeout checks)
  3. as soon as that invocation finishes, scope-filter EVERY returned hostname
     through ScopeGuard — out-of-scope hosts (aws.*, test.*, *.dev, subsidiaries)
     are dropped and each rejection audited — and upsert the allowed ones. Results
     are persisted per root, so an interruption never discards finished work.
  4. finalize the run: ``completed``, or ``interrupted`` (Ctrl-C / error) with the
     roots each tool completed recorded in the run note
  5. report the diff: what's NEW since the previous run
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..audit_log import AuditLog
from ..config import Scope, ToolSpec
from ..scope_guard import ScopeGuard
from ..seeds import declared_seed_rule, enumeration_seeds
from ..store import Store

# We stay lenient here and let ScopeGuard do the authoritative
# normalization/validation downstream.
_LINE_COMMENT = re.compile(r"^\s*#")
# amass v4 prints graph relations: "a.x.com (FQDN) --> cname_record --> b.x.com (FQDN)"
_AMASS_FQDN = re.compile(r"(\S+)\s+\(FQDN\)")


def parse_hosts(path: str | Path) -> list[str]:
    """Extract candidate hostnames from a tool's output file, deduped in order.

    subfinder prints one host per line (first whitespace token). amass v4 prints
    graph relations — every node tagged ``(FQDN)`` on the line is a hostname, on
    either side of the arrow; IP/ASN/netblock nodes are ignored. Blank/comment
    lines are skipped. Returns lowercased tokens; scope normalization/validation
    happens in the guard.
    """
    p = Path(path)
    if not p.exists():
        return []
    out: dict[str, None] = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or _LINE_COMMENT.match(line):
            continue
        toks = _AMASS_FQDN.findall(line) or [line.split()[0]]
        for tok in toks:
            tok = tok.strip().lower()
            if tok:
                out.setdefault(tok, None)
    return list(out)


@dataclass
class PassiveReconResult:
    run_id: int
    roots: list[str]
    roots_enumerated: list[str]              # seeds the runner accepted (seed gate)
    roots_dropped: list[str]                 # seeds the runner rejected (seed gate)
    total_found: int                         # unique hostnames returned by tools
    in_scope_kept: int
    out_of_scope_dropped: int
    new_subdomains: list[str]                # NEW since the previous run
    by_tool: dict[str, int] = field(default_factory=dict)
    dropped_examples: list[tuple[str, str]] = field(default_factory=list)  # (host, matched_rule)
    planned_commands: list[str] = field(default_factory=list)  # dry-run only
    dry_run: bool = False
    interrupted: bool = False
    interrupt_reason: str = ""
    completed_roots: dict[str, list[str]] = field(default_factory=dict)  # tool -> roots

    def summary_text(self) -> str:
        if self.dry_run:
            lines = [f"[passive_recon] DRY RUN — {len(self.roots_enumerated)} seed(s), "
                     f"{len(self.roots_dropped)} invalid seed(s) dropped"]
            if self.roots_dropped:
                lines.append(f"  dropped seeds : {', '.join(self.roots_dropped)}")
            lines += [f"  $ {c}" for c in self.planned_commands]
            return "\n".join(lines)
        status = (f"INTERRUPTED ({self.interrupt_reason}) — partial results stored"
                  if self.interrupted else "completed")
        lines = [
            f"[passive_recon] run #{self.run_id}: {status}",
            f"  roots enumerated : {len(self.roots_enumerated)}"
            f" ({len(self.roots_dropped)} invalid seed(s) dropped)",
            f"  total found      : {self.total_found}",
            f"  in-scope kept    : {self.in_scope_kept}",
            f"  out-of-scope drop: {self.out_of_scope_dropped}",
            f"  NEW since last   : {len(self.new_subdomains)}",
        ]
        if self.by_tool:
            lines.append("  by tool          : "
                         + ", ".join(f"{t}={n}" for t, n in sorted(self.by_tool.items())))
        if self.interrupted:
            n = len(self.roots)
            lines.append("  roots completed  : " + ", ".join(
                f"{t} {len(r)}/{n}" for t, r in sorted(self.completed_roots.items())))
        if self.new_subdomains:
            shown = self.new_subdomains[:15]
            more = "" if len(self.new_subdomains) <= 15 else f" (+{len(self.new_subdomains) - 15} more)"
            lines.append("  new              : " + ", ".join(shown) + more)
        return "\n".join(lines)


class PassiveReconStage:
    STAGE = "passive_recon"

    def __init__(self, scope: Scope, registry: dict[str, ToolSpec], store: Store,
                 audit: AuditLog, runner, output_dir: str | Path,
                 only: Optional[Iterable[str]] = None):
        self.scope = scope
        self.registry = registry
        self.store = store
        self.audit = audit
        self.runner = runner
        self.output_dir = Path(output_dir)
        # Guard for RESULT filtering; audits every decision through the engagement log.
        self.guard = ScopeGuard(scope, audit=audit.log_scope_decision)
        self.tools = self._select_tools()
        if only is not None:
            # --only can NARROW the eligible tools, never widen them past the
            # stage's passive/allowlist filter.
            wanted = sorted({t.strip() for t in only if t.strip()})
            bad = [t for t in wanted if t not in self.tools]
            if bad or not wanted:
                raise ValueError(
                    f"passive_recon --only: {', '.join(bad) or '(empty)'} not eligible; "
                    f"choose from: {', '.join(self.tools) or '(none)'}")
            self.tools = wanted

    # -- tool selection (data-driven; passive subdomain tools only) ---------- #
    def _select_tools(self) -> list[str]:
        return sorted(
            name for name, s in self.registry.items()
            if s.stage == self.STAGE and not s.active and s.output == "subdomains"
            and name in self.scope.allowed_tools)

    # -- enumeration roots --------------------------------------------------- #
    def enumeration_roots(self) -> list[str]:
        """Seeds to enumerate: exactly X for every ``*.X`` entry, plus plain
        entries not already under another seed. These are passive search keys,
        not targets — ``*.amazonalexa.com`` yields ``amazonalexa.com`` although
        the apex is not in scope. Wildcards are never enumerated as literals.

        Safety net: a seed that is not declared by an in_scope entry (a plain
        entry or a ``*.X`` base) is a derivation error — audited and dropped,
        never enumerated."""
        roots = []
        for seed in enumeration_seeds(self.scope):
            if declared_seed_rule(self.scope, seed) is None:
                self.audit.log_event(
                    "seed_derivation_error", seed=seed,
                    reason="derived seed is not an in_scope entry or *.X base; dropped")
                continue
            roots.append(seed)
        return roots

    # -- ingest (scope-filter + store) --------------------------------------- #
    def ingest(self, discovered: Iterable[tuple[str, str]], run_id: int
               ) -> tuple[list[str], list[tuple[str, str]]]:
        """Scope-filter and store. ``discovered`` is (host, source_tool) pairs.
        Returns (kept_hosts, dropped[(host, matched_rule)])."""
        kept: list[str] = []
        dropped: list[tuple[str, str]] = []
        for host, source in discovered:
            dec = self.guard.check(host)   # audited (allow + reject)
            if dec.allowed:
                self.store.upsert_asset(
                    "subdomain", dec.host, run_id,
                    attrs={"source": source, "engagement": self.scope.engagement.name})
                kept.append(dec.host)
            else:
                dropped.append((dec.host or host, dec.matched_rule or dec.reason))
        return kept, dropped

    def ingest_output(self, path: str | Path, tool: str, run_id: int,
                      progress: Optional["_Progress"] = None) -> tuple[int, int]:
        """Parse one tool output file and persist it immediately: hosts not yet
        seen in this run are scope-filtered (audited) and the allowed ones
        upserted. Returns (kept, dropped) for this file. Also used to recover
        output files left on disk by an interrupted run."""
        progress = progress if progress is not None else _Progress()
        fresh = [h for h in parse_hosts(path) if h not in progress.seen]
        progress.seen.update(fresh)
        progress.by_tool.setdefault(tool, set()).update(fresh)
        kept, dropped = self.ingest([(h, tool) for h in fresh], run_id)
        progress.kept.update(kept)
        progress.dropped.extend(dropped)
        return len(kept), len(dropped)

    # -- orchestration ------------------------------------------------------- #
    def run(self, dry_run: bool = False) -> PassiveReconResult:
        if not self.tools:
            raise RuntimeError(
                "passive_recon: no passive subdomain tools are allowlisted "
                "(need subfinder/amass in allowed_tools)")
        roots = self.enumeration_roots()
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = self.output_dir / tag
        if dry_run:
            return self._plan(roots, base)

        run_id = self.store.start_run(self.STAGE, tool=",".join(self.tools),
                                      note=json.dumps({"artifacts": str(base)}))
        prog = _Progress()
        roots_enum: set[str] = set()
        roots_dropped: set[str] = set()
        try:
            for tool in self.tools:
                prog.completed.setdefault(tool, [])
                for root in roots:
                    # one root per runner call, so results land in the DB as soon
                    # as that root finishes rather than at the end of the run
                    res = self.runner.run(tool, [root], base / tool, seeds=True)
                    roots_enum.update(res.allowed)
                    roots_dropped.update(res.rejected)
                    kept = dropped = 0
                    for inv in res.invocations:
                        # a timed-out invocation's partial output is still usable
                        # (and still scope-filtered at ingest)
                        ok = inv.exit_code == 0 or getattr(inv, "timed_out", False)
                        if ok and inv.output_path:
                            k, d = self.ingest_output(inv.output_path, tool, run_id, prog)
                            kept, dropped = kept + k, dropped + d
                    prog.completed[tool].append(root)
                    self.audit.log_event("root_completed", stage=self.STAGE, run=run_id,
                                         tool=tool, root=root, kept=kept, dropped=dropped)
        except BaseException as e:  # noqa: BLE001 - Ctrl-C included: finalize, then decide
            reason = type(e).__name__ if isinstance(e, KeyboardInterrupt) \
                else f"{type(e).__name__}: {e}"
            self.store.finish_run(run_id, status="interrupted", note=json.dumps({
                "artifacts": str(base), "reason": reason, "completed_roots": prog.completed}))
            self.audit.log_event("run_interrupted", stage=self.STAGE, run=run_id,
                                 reason=reason, completed_roots=prog.completed)
            if not isinstance(e, KeyboardInterrupt):
                raise           # real errors still surface (after finalizing)
            return self._result(run_id, roots, roots_enum, roots_dropped, prog,
                                interrupted=True, reason=reason)

        self.store.finish_run(run_id, status="completed")
        return self._result(run_id, roots, roots_enum, roots_dropped, prog)

    def _plan(self, roots: list[str], base: Path) -> PassiveReconResult:
        roots_enum: set[str] = set()
        roots_dropped: set[str] = set()
        planned: list[str] = []
        for tool in self.tools:
            res = self.runner.run(tool, roots, base / tool, dry_run=True, seeds=True)
            roots_enum.update(res.allowed)
            roots_dropped.update(res.rejected)
            planned += [" ".join(iv.command) for iv in res.invocations]
        return PassiveReconResult(
            run_id=0, roots=roots, roots_enumerated=sorted(roots_enum),
            roots_dropped=sorted(roots_dropped), total_found=0, in_scope_kept=0,
            out_of_scope_dropped=0, new_subdomains=[], planned_commands=planned,
            dry_run=True)

    def _result(self, run_id, roots, roots_enum, roots_dropped, prog: "_Progress",
                interrupted: bool = False, reason: str = "") -> PassiveReconResult:
        new = [a["key"] for a in self.store.new_assets_in_run(run_id, "subdomain")]
        return PassiveReconResult(
            run_id=run_id, roots=roots, roots_enumerated=sorted(roots_enum),
            roots_dropped=sorted(roots_dropped), total_found=len(prog.seen),
            in_scope_kept=len(prog.kept), out_of_scope_dropped=len(prog.dropped),
            new_subdomains=new, by_tool={t: len(h) for t, h in prog.by_tool.items()},
            dropped_examples=prog.dropped[:10], interrupted=interrupted,
            interrupt_reason=reason, completed_roots=prog.completed)


@dataclass
class _Progress:
    """Running totals for one passive_recon run (deduped across tools)."""
    seen: set[str] = field(default_factory=set)                 # every host parsed
    kept: set[str] = field(default_factory=set)                 # stored (in scope)
    dropped: list[tuple[str, str]] = field(default_factory=list)  # (host, rule)
    by_tool: dict[str, set[str]] = field(default_factory=dict)  # hosts first seen per tool
    completed: dict[str, list[str]] = field(default_factory=dict)  # tool -> finished roots
