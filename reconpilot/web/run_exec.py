"""Execution for web-triggered runs: drives the stages via the shared run_stage.

The plan reaching here has already been confirm-checked and re-validated server-side
by the /api/run endpoint. This maps the plan's stage to its stage class and runs it
through ``orchestrate.run_stage`` — the SAME construction path the CLI uses. The
JobManager runs this in a background thread and records the returned dict as the job
result; raising maps the job to status=failed.
"""

from __future__ import annotations

from pathlib import Path

from .. import orchestrate
from ..engagement import load_engagement
from ..stages import DnsResolveStage, LivenessStage, NucleiStage, PassiveReconStage

_STAGE_CLASSES = {
    "passive_recon": PassiveReconStage,
    "dns_resolve": DnsResolveStage,
    "liveness": LivenessStage,
    "signal_scan": NucleiStage,
}


def execute_plan(plan: dict, base_dir: str | Path) -> dict:
    stage_name = plan["stage"]
    stage_cls = _STAGE_CLASSES[stage_name]
    params = plan.get("params") or {}
    scope = load_engagement(plan["engagement"], base_dir)
    hosts = [params["host"]] if params.get("host") else None

    sr = orchestrate.run_stage(scope, stage_cls, stage_name, base_dir=base_dir,
                               limit=params.get("limit"), hosts=hosts)
    try:
        return {"summary": sr.result.summary_text(),
                "run_id": getattr(sr.result, "run_id", None)}
    finally:
        sr.store.close()
