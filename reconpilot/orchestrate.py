"""One construction path for running a pipeline stage.

``run_stage`` is the exact stage-construction + GuardedRunner-building logic that
``cli._run_active_stage`` used, factored out so the CLI and the web run layer go
through the same path. It builds the registry, audit log, store, and GuardedRunner,
constructs the stage, runs it, and returns the pieces the caller needs (result +
the still-open store/audit for printing or closing).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


@dataclass
class StageRun:
    result: object        # the stage's result dataclass (has summary_text(), run_id, …)
    store: object         # Store — left OPEN; the caller closes it
    audit: object         # AuditLog
    stage: object         # the constructed stage (has .TOOL)
    out: Path             # the run-artifact directory used


def run_stage(scope, stage_cls, stage_name: str, *, base_dir, tools: str = "tools.yaml",
              out=None, force_safe_mode: bool = False, dry_run: bool = False,
              limit: Optional[int] = None, hosts: Optional[list] = None) -> StageRun:
    """Build and run one stage. Mirrors cli._run_active_stage's construction exactly:
    load_tools(tools) -> AuditLog(eng_base/'audit.jsonl') -> Store.open_for_engagement
    -> GuardedRunner(scope, registry, audit, force_safe_mode=...) -> stage_cls(scope,
    registry, store, audit, runner, out) -> stage.run(...).

    On any failure during construction or the run, the store is closed before the
    exception propagates; on success the store is returned OPEN for the caller."""
    from .audit_log import AuditLog
    from .config import load_tools
    from .runner import GuardedRunner
    from .store import Store

    registry = load_tools(tools)
    slug = _slug(scope.engagement.name)
    eng_base = Path(base_dir) / slug
    out = Path(out) if out else eng_base / "runs" / stage_name
    audit = AuditLog(eng_base / "audit.jsonl", engagement=scope.engagement.name)
    store = Store.open_for_engagement(scope.engagement.name, base_dir=base_dir)
    runner = GuardedRunner(scope, registry, audit, force_safe_mode=force_safe_mode)
    try:
        stage = stage_cls(scope, registry, store, audit, runner, out)
        run_kwargs = {"dry_run": dry_run}
        # limit/hosts only exist on the active stages' run(); passive run() takes
        # neither, so pass them only when set (planner never sets them for passive).
        if limit is not None:
            run_kwargs["limit"] = limit
        if hosts is not None:
            run_kwargs["hosts"] = hosts
        result = stage.run(**run_kwargs)
    except BaseException:
        store.close()
        raise
    return StageRun(result=result, store=store, audit=audit, stage=stage, out=out)
