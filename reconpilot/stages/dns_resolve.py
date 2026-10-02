"""Stage 2: dns_resolve — resolve the in-scope subdomains with dnsx.

dnsx queries public DNS resolvers (not Amazon hosts), so this stage sends no
traffic to the targets themselves. Its job is to record which discovered
subdomains actually resolve (A / AAAA / CNAME + IPs) and mark that on the asset,
which naturally shrinks the set the liveness stage has to probe — most CT-log
subdomains are dead.

This module owns the PARSING + STORAGE (pure, offline, tested with fakes). The
single point where the resolved-host list is handed to a real tool is
``DnsResolveStage.invoke_tool`` — a clearly-marked seam left unimplemented so the
execution can be wired through the existing GuardedRunner (see its TODO).

Resolution fields are stored in the asset's ``attrs`` JSON (the schema's designed
extension point, merged by ``Store.upsert_asset``):
    resolves : bool           # True once dnsx returned any record for it
    a        : list[str]      # A records (IPv4)
    aaaa     : list[str]      # AAAA records (IPv6)
    cname    : list[str]      # CNAME targets
    ips      : list[str]      # a + aaaa, deduped (convenience for later stages)
    resolved_at_run : int
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
from ..store import Store

# dnsx text output (-a -resp): "host [A] [1.2.3.4]" with one [TYPE] [value] pair
# per record; a host may appear on several lines. We also accept dnsx -json.
_RESP_RE = re.compile(r"\[([A-Za-z]+)\]\s*\[([^\]]+)\]")
_RECORD_FIELDS = ("a", "aaaa", "cname")


@dataclass
class Resolution:
    host: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa or self.cname)

    @property
    def ips(self) -> list[str]:
        seen: dict[str, None] = {}
        for ip in self.a + self.aaaa:
            seen.setdefault(ip, None)
        return list(seen)

    def attrs(self, run_id: int) -> dict:
        return {"resolves": self.resolves, "a": self.a, "aaaa": self.aaaa,
                "cname": self.cname, "ips": self.ips, "resolved_at_run": run_id}


def _merge_into(table: dict[str, Resolution], host: str, rtype: str, value: str) -> None:
    host = host.strip().lower().rstrip(".")
    value = value.strip().rstrip(".")
    if not host or not value:
        return
    res = table.setdefault(host, Resolution(host))
    rt = rtype.strip().lower()
    bucket = {"a": res.a, "aaaa": res.aaaa, "cname": res.cname}.get(rt)
    if bucket is not None and value not in bucket:
        bucket.append(value)


def parse_dnsx(path: str | Path) -> list[Resolution]:
    """Parse a dnsx output file into one Resolution per host.

    Accepts both text (``host [A] [1.2.3.4]``) and JSONL (``dnsx -json``). A host
    that appears multiple times (multiple records / lines) is merged. Only hosts
    with at least one record are returned — a host dnsx could not resolve simply
    doesn't appear in its output.
    """
    p = Path(path)
    if not p.exists():
        return []
    table: dict[str, Resolution] = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(rec.get("host") or rec.get("name") or "").strip()
            if not host:
                continue
            for f in _RECORD_FIELDS:
                for v in rec.get(f, []) or []:
                    _merge_into(table, host, f, str(v))
            continue
        # text form: first token is the host, then zero+ [TYPE] [value] pairs
        host = line.split()[0]
        pairs = _RESP_RE.findall(line)
        for rtype, value in pairs:
            # a [value] may itself contain comma-separated entries
            for v in re.split(r"[,\s]+", value):
                _merge_into(table, host, rtype, v)
    return [r for r in table.values() if r.resolves]


@dataclass
class DnsResolveResult:
    run_id: int
    input_hosts: int
    resolved: int
    unresolved: int
    new_ips: int = 0
    interrupted: bool = False
    interrupt_reason: str = ""
    dry_run: bool = False

    def summary_text(self) -> str:
        if self.dry_run:
            return (f"[dns_resolve] DRY RUN — would resolve {self.input_hosts} "
                    f"in-scope subdomains")
        status = (f"INTERRUPTED ({self.interrupt_reason}) — partial results stored"
                  if self.interrupted else "completed")
        return "\n".join([
            f"[dns_resolve] run #{self.run_id}: {status}",
            f"  input hosts   : {self.input_hosts}",
            f"  resolved      : {self.resolved}",
            f"  unresolved    : {self.unresolved}",
            f"  distinct IPs  : {self.new_ips}",
        ])


class DnsResolveStage:
    STAGE = "dns_resolve"
    TOOL = "dnsx"

    def __init__(self, scope: Scope, registry: dict[str, ToolSpec], store: Store,
                 audit: AuditLog, runner, output_dir: str | Path):
        self.scope = scope
        self.registry = registry
        self.store = store
        self.audit = audit
        self.runner = runner
        self.output_dir = Path(output_dir)
        if self.TOOL not in scope.allowed_tools:
            raise ValueError(f"dns_resolve: '{self.TOOL}' is not in allowed_tools")

    # -- stage input --------------------------------------------------------- #
    def hosts_to_resolve(self, limit: Optional[int] = None) -> list[str]:
        """The in-scope subdomains to resolve — every stored subdomain asset."""
        return self.store.keys("subdomain", limit=limit)

    # -- ingest (parse + store), incremental --------------------------------- #
    def ingest_dnsx_file(self, path: str | Path, run_id: int) -> tuple[int, set]:
        """Parse one dnsx output file and persist resolution status immediately.
        Returns (resolved_count, set_of_ips). Hosts present in the file resolved;
        hosts absent are left as-is (optionally marked unresolved by ``run``)."""
        ips: set[str] = set()
        resolved = 0
        for res in parse_dnsx(path):
            self.store.upsert_asset("subdomain", res.host, run_id, attrs=res.attrs(run_id))
            ips.update(res.ips)
            resolved += 1
        return resolved, ips

    # -- execution seam (wire this to the real runner) ----------------------- #
    def invoke_tool(self, hosts: list[str], out_dir: Path):
        """SEAM — left unimplemented on purpose.

        Run dnsx over ``hosts`` through the EXISTING GuardedRunner, exactly like
        the passive stage does, and return its invocations (objects exposing
        ``.output_path``, ``.exit_code`` and ``.timed_out``). dnsx is a batch
        (``-l {targets_file}``) tool, so one call handles the whole list and the
        runner writes the input file + enforces its own ``-rl {rps}`` pacing.

        The ``run()`` orchestration below (input selection, incremental ingest,
        interrupt-safe finalize, diff) is complete and tested with a fake
        executor; only this network call is left for you to wire:

            # TODO(you): execute dnsx via the guarded runner
            # res = self.runner.run(self.TOOL, hosts, out_dir)   # NOT seed mode
            # return res.invocations
        """
        raise NotImplementedError(
            "DnsResolveStage.invoke_tool is a seam; wire it to self.runner.run "
            "or pass executor=... to run(). See the docstring.")

    # -- orchestration ------------------------------------------------------- #
    def run(self, dry_run: bool = False,
            executor: Optional[Callable[[str, list[str], Path], Iterable]] = None,
            limit: Optional[int] = None) -> DnsResolveResult:
        hosts = self.hosts_to_resolve(limit=limit)
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = self.output_dir / tag
        if dry_run:
            return DnsResolveResult(run_id=0, input_hosts=len(hosts), resolved=0,
                                    unresolved=len(hosts), dry_run=True)

        run = executor or (lambda hosts_, out_: self.invoke_tool(hosts_, out_))
        run_id = self.store.start_run(self.STAGE, tool=self.TOOL,
                                      note=json.dumps({"artifacts": str(base),
                                                       "input_hosts": len(hosts)}))
        resolved_hosts: set[str] = set()
        ips: set[str] = set()
        try:
            for inv in run(hosts, base) or []:
                ok = inv.exit_code == 0 or getattr(inv, "timed_out", False)
                if ok and inv.output_path:
                    for res in parse_dnsx(inv.output_path):
                        self.store.upsert_asset("subdomain", res.host, run_id,
                                                attrs=res.attrs(run_id))
                        resolved_hosts.add(res.host)
                        ips.update(res.ips)
        except BaseException as e:  # noqa: BLE001 - Ctrl-C included: finalize first
            reason = type(e).__name__ if isinstance(e, KeyboardInterrupt) \
                else f"{type(e).__name__}: {e}"
            self.store.finish_run(run_id, status="interrupted", note=json.dumps(
                {"artifacts": str(base), "reason": reason,
                 "resolved": len(resolved_hosts)}))
            self.audit.log_event("run_interrupted", stage=self.STAGE, run=run_id,
                                 reason=reason, resolved=len(resolved_hosts))
            if not isinstance(e, KeyboardInterrupt):
                raise
            return DnsResolveResult(
                run_id=run_id, input_hosts=len(hosts), resolved=len(resolved_hosts),
                unresolved=len(hosts) - len(resolved_hosts), new_ips=len(ips),
                interrupted=True, interrupt_reason=reason)

        self.store.finish_run(run_id, status="completed")
        return DnsResolveResult(
            run_id=run_id, input_hosts=len(hosts), resolved=len(resolved_hosts),
            unresolved=len(hosts) - len(resolved_hosts), new_ips=len(ips))
