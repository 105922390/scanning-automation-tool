"""Stage 1: passive_recon — subdomain enumeration from third-party datasets.

Genuinely passive: it runs only tools marked ``active: false`` whose output is
``subdomains`` (subfinder, amass passive). It never sends traffic to the target.

Flow:
  1. derive enumeration roots (registrable domains) from the engagement in_scope
  2. run each passive tool on the roots via the guarded runner (which scope-gates
     and audits the SEEDS, and rate/allowlist-checks the tool)
  3. scope-filter EVERY returned hostname through ScopeGuard — out-of-scope hosts
     (aws.*, test.*, *.dev, subsidiaries) are dropped and each rejection audited
  4. upsert allowed hosts into the assets table (dedup, first/last seen, source)
  5. report the diff: what's NEW since the previous run
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from ..audit_log import AuditLog
from ..config import Scope, ToolSpec
from ..scope_guard import ScopeGuard
from ..store import Store

# First token on a line that plausibly looks like a hostname. We stay lenient and
# let ScopeGuard do the authoritative normalization/validation downstream.
_LINE_COMMENT = re.compile(r"^\s*#")


def parse_hosts(path: str | Path) -> list[str]:
    """Extract candidate hostnames from a tool's output file.

    subfinder prints one host per line; amass may decorate lines
    (``host (FQDN) --> ...``) — in both cases the first whitespace token is the
    hostname. Blank/comment lines are skipped. Returns lowercased tokens; scope
    normalization/validation happens in the guard.
    """
    p = Path(path)
    if not p.exists():
        return []
    out: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or _LINE_COMMENT.match(line):
            continue
        tok = line.split()[0].strip().lower()
        if tok:
            out.append(tok)
    return out


@dataclass
class PassiveReconResult:
    run_id: int
    roots: list[str]
    roots_enumerated: list[str]              # seeds the runner accepted (in scope)
    roots_dropped: list[str]                 # seeds the runner rejected (out of scope)
    total_found: int                         # unique hostnames returned by tools
    in_scope_kept: int
    out_of_scope_dropped: int
    new_subdomains: list[str]                # NEW since the previous run
    by_tool: dict[str, int] = field(default_factory=dict)
    dropped_examples: list[tuple[str, str]] = field(default_factory=list)  # (host, matched_rule)
    planned_commands: list[str] = field(default_factory=list)  # dry-run only
    dry_run: bool = False

    def summary_text(self) -> str:
        if self.dry_run:
            lines = [f"[passive_recon] DRY RUN — {len(self.roots_enumerated)} in-scope "
                     f"roots, {len(self.roots_dropped)} out-of-scope seed(s) dropped"]
            if self.roots_dropped:
                lines.append(f"  dropped seeds : {', '.join(self.roots_dropped)}")
            lines += [f"  $ {c}" for c in self.planned_commands]
            return "\n".join(lines)
        lines = [
            f"[passive_recon] run #{self.run_id}",
            f"  roots enumerated : {len(self.roots_enumerated)}"
            f" ({len(self.roots_dropped)} out-of-scope seed(s) dropped)",
            f"  total found      : {self.total_found}",
            f"  in-scope kept    : {self.in_scope_kept}",
            f"  out-of-scope drop: {self.out_of_scope_dropped}",
            f"  NEW since last   : {len(self.new_subdomains)}",
        ]
        if self.by_tool:
            lines.append("  by tool          : "
                         + ", ".join(f"{t}={n}" for t, n in sorted(self.by_tool.items())))
        if self.new_subdomains:
            shown = self.new_subdomains[:15]
            more = "" if len(self.new_subdomains) <= 15 else f" (+{len(self.new_subdomains) - 15} more)"
            lines.append("  new              : " + ", ".join(shown) + more)
        return "\n".join(lines)


class PassiveReconStage:
    STAGE = "passive_recon"

    def __init__(self, scope: Scope, registry: dict[str, ToolSpec], store: Store,
                 audit: AuditLog, runner, output_dir: str | Path):
        self.scope = scope
        self.registry = registry
        self.store = store
        self.audit = audit
        self.runner = runner
        self.output_dir = Path(output_dir)
        # Guard for RESULT filtering; audits every decision through the engagement log.
        self.guard = ScopeGuard(scope, audit=audit.log_scope_decision)
        self.tools = self._select_tools()

    # -- tool selection (data-driven; passive subdomain tools only) ---------- #
    def _select_tools(self) -> list[str]:
        return sorted(
            name for name, s in self.registry.items()
            if s.stage == self.STAGE and not s.active and s.output == "subdomains"
            and name in self.scope.allowed_tools)

    # -- enumeration roots --------------------------------------------------- #
    def enumeration_roots(self) -> list[str]:
        """Registrable domains to enumerate: wildcard bases + plain in_scope
        entries, deduped. Wildcards themselves are never enumerated as literals."""
        roots: set[str] = set()
        for d in self.scope.in_scope_domains:
            d = d.strip().lower().rstrip(".")
            if not d:
                continue
            roots.add(d[2:] if d.startswith("*.") else d)
        return sorted(r for r in roots if r)

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

    # -- orchestration ------------------------------------------------------- #
    def run(self, dry_run: bool = False) -> PassiveReconResult:
        if not self.tools:
            raise RuntimeError(
                "passive_recon: no passive subdomain tools are allowlisted "
                "(need subfinder/amass in allowed_tools)")
        roots = self.enumeration_roots()
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = self.output_dir / tag

        roots_enum: set[str] = set()
        roots_dropped: set[str] = set()
        by_tool: dict[str, int] = {}
        discovered: list[tuple[str, str]] = []
        planned: list[str] = []

        run_id = 0 if dry_run else self.store.start_run(self.STAGE, tool=",".join(self.tools))
        try:
            for tool in self.tools:
                res = self.runner.run(tool, roots, base / tool, dry_run=dry_run)
                roots_enum.update(res.allowed)
                roots_dropped.update(res.rejected)
                if dry_run:
                    planned += [" ".join(iv.command) for iv in res.invocations]
                    continue
                count = 0
                for inv in res.invocations:
                    if inv.exit_code == 0 and inv.output_path:
                        for h in parse_hosts(inv.output_path):
                            discovered.append((h, tool))
                            count += 1
                by_tool[tool] = count

            if dry_run:
                return PassiveReconResult(
                    run_id=0, roots=roots, roots_enumerated=sorted(roots_enum),
                    roots_dropped=sorted(roots_dropped), total_found=0, in_scope_kept=0,
                    out_of_scope_dropped=0, new_subdomains=[], planned_commands=planned,
                    dry_run=True)

            # dedup across tools; first source wins for the attr
            uniq: dict[str, str] = {}
            for host, src in discovered:
                uniq.setdefault(host, src)
            kept, dropped = self.ingest(list(uniq.items()), run_id)
            new = [a["key"] for a in self.store.new_assets_in_run(run_id, "subdomain")]
            self.store.finish_run(run_id, status="ok")
            return PassiveReconResult(
                run_id=run_id, roots=roots, roots_enumerated=sorted(roots_enum),
                roots_dropped=sorted(roots_dropped), total_found=len(uniq),
                in_scope_kept=len(set(kept)), out_of_scope_dropped=len(dropped),
                new_subdomains=new, by_tool=by_tool, dropped_examples=dropped[:10])
        except Exception as e:  # noqa: BLE001
            if run_id:
                self.store.finish_run(run_id, status="error", note=f"{type(e).__name__}: {e}")
            raise
