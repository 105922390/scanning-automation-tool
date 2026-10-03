"""FastAPI app for the read-only ReconPilot dashboard (phase 1).

LOCAL ONLY: the launcher (``python -m reconpilot.web``) binds 127.0.0.1 and never
0.0.0.0. This phase performs NO active scanning — every route only reads the
engagement's SQLite store (via service.py / store.py) and audit log.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from ..engagement import DEFAULT_DIR
from . import planner, service
from .jobs import JobManager, job_log
from .run_exec import execute_plan


class PlanRequest(BaseModel):
    prompt: str
    engagement: str


class RunRequest(BaseModel):
    plan: dict                 # must carry engagement, stage, params (from /api/plan)
    confirm_token: str


class TriageRequest(BaseModel):
    status: str


class UploadValidateRequest(BaseModel):
    yaml: str


class UploadSaveRequest(BaseModel):
    yaml: str
    confirm_token: str
    overwrite: bool = False

_STATIC = Path(__file__).parent / "static"

# Hostnames a request's Host header may carry. The server binds 127.0.0.1 only,
# so a legitimate request always arrives as one of these; a DNS-rebinding attacker
# whose domain resolves to 127.0.0.1 still sends Host: attacker.com -> rejected.
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _host_only(host_header: str) -> str:
    """The hostname from a Host header, without the port, lowercased."""
    h = host_header.strip().lower()
    if not h:
        return ""
    if h.startswith("["):                       # [::1] or [::1]:port
        return h[1:h.index("]")] if "]" in h else h[1:]
    if h.count(":") == 1:                        # host:port (not a bare IPv6)
        host, port = h.rsplit(":", 1)
        if port.isdigit():
            return host
    return h


def host_is_allowed(host_header: str, allowed=ALLOWED_HOSTS) -> bool:
    """True only if the Host header names a loopback host. Blocks DNS rebinding:
    the attacker's browser request carries their domain in Host, which is rejected
    even though it resolved to 127.0.0.1."""
    return _host_only(host_header) in allowed


def create_app(base_dir: str | Path = DEFAULT_DIR, allowed_hosts=ALLOWED_HOSTS,
               executor=None) -> FastAPI:
    app = FastAPI(title="ReconPilot", docs_url=None, redoc_url=None)
    # executor drives the real stages (a seam) in prod; tests inject a fake one.
    jobs = JobManager(executor or (lambda plan, canceller: execute_plan(plan, base_dir, canceller)))
    app.state.jobs = jobs        # exposed so the desktop launcher can cancel on shutdown

    @app.middleware("http")
    async def _guard_host_and_cache(request, call_next):
        # DNS-rebinding defense: reject any non-loopback Host before routing.
        if not host_is_allowed(request.headers.get("host", ""), allowed_hosts):
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        response = await call_next(request)
        # API responses carry live recon data: never let a browser/proxy cache them.
        if request.url.path.startswith("/api/"):
            response.headers["cache-control"] = "no-store"
        return response

    def _guard(fn):
        try:
            return fn()
        except service.UnknownEngagement as e:
            raise HTTPException(status_code=404, detail=f"unknown engagement: {e}")
        except service.UnknownFinding as e:
            raise HTTPException(status_code=404, detail=f"unknown finding: {e}")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/engagements")
    def engagements():
        return {"engagements": service.available_engagements(base_dir)}

    @app.get("/api/engagements/{name}/stats")
    def stats(name: str):
        return _guard(lambda: service.stats(base_dir, name))

    @app.get("/api/engagements/{name}/assets")
    def assets(name: str,
               filter: str = Query("all"),
               search: Optional[str] = Query(None),
               sort: str = Query("recent"),
               limit: int = Query(100, ge=1, le=1000),
               offset: int = Query(0, ge=0)):
        return _guard(lambda: service.assets(
            base_dir, name, filter=filter, search=search, sort=sort,
            limit=limit, offset=offset))

    @app.get("/api/engagements/{name}/redirect-events")
    def redirect_events(name: str, limit: int = Query(200, ge=1, le=2000)):
        return _guard(lambda: service.redirect_events(base_dir, name, limit=limit))

    @app.get("/api/engagements/{name}/findings")
    def findings(name: str,
                 severity: Optional[str] = Query(None),
                 triage: Optional[str] = Query(None),
                 search: Optional[str] = Query(None),
                 sort: str = Query("severity"),
                 limit: int = Query(100, ge=1, le=1000),
                 offset: int = Query(0, ge=0)):
        return _guard(lambda: service.findings(
            base_dir, name, severity=severity, triage=triage, search=search,
            sort=sort, limit=limit, offset=offset))

    @app.post("/api/engagements/{name}/findings/{fid}/triage")
    def set_triage(name: str, fid: int, req: TriageRequest):
        # a write to OUR OWN DB (triage state), never a scan
        return _guard(lambda: service.set_triage(base_dir, name, fid, req.status))

    @app.get("/api/engagements/{name}/findings/{fid}/export")
    def export_lead(name: str, fid: int):
        return _guard(lambda: service.export_lead(base_dir, name, fid))

    @app.post("/api/plan")
    def make_plan(req: PlanRequest):
        # Prompt -> structured plan preview + confirm_token. NO execution here.
        return _guard(lambda: planner.plan(base_dir, req.engagement, req.prompt).to_dict())

    @app.post("/api/run")
    def start_run(req: RunRequest):
        p = req.plan or {}
        engagement, stage = p.get("engagement"), p.get("stage")
        params = p.get("params") or {}
        # 1. confirm enforcement: the token must match THIS plan core (prevents a
        #    single-request run and detects client tampering of the plan).
        core = planner.plan_core(engagement, stage, params)
        if not planner.verify_token(core, req.confirm_token):
            raise HTTPException(status_code=403,
                                detail="run not confirmed: missing or invalid confirm_token")
        # 2. re-validate server-side — never trust the client's plan/preview.
        validated = _guard(lambda: planner.build_plan(base_dir, engagement, stage, params))
        if not validated.ok:
            raise HTTPException(status_code=400,
                                detail=validated.message or "plan failed server-side validation")
        job = jobs.submit(validated.engagement, validated.stage, validated.params)
        return {"run_id": job.id, "status": job.status,
                "engagement": job.engagement, "stage": job.stage}

    @app.get("/api/runs/{run_id}/status")
    def run_status(run_id: str):
        job = jobs.get(run_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown run")
        return job.to_status()

    @app.get("/api/runs/{run_id}/log")
    def run_log(run_id: str, offset: int = Query(0, ge=0)):
        job = jobs.get(run_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown run")
        return job_log(base_dir, job, offset=offset)

    @app.post("/api/runs/{run_id}/stop")
    def stop_run(run_id: str):
        # cancel the background job AND kill its child tool process tree
        job = jobs.stop(run_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown run")
        return job.to_status()

    @app.post("/api/engagements/validate")
    def validate_engagement(req: UploadValidateRequest):
        # dry-run validation; returns a confirm_token the save step requires. The
        # token (unreadable cross-origin, unforgeable) is the confirm step for this
        # write endpoint, alongside the Host-header allowlist.
        def _do():
            try:
                info = service.validate_engagement_yaml(base_dir, req.yaml)
            except service.UploadError as e:
                return {"ok": False, "errors": [str(e)]}
            core = service.upload_core(info["slug"], req.yaml)
            return {"ok": True, **info, "confirm_token": planner.confirm_token(core)}
        return _guard(_do)

    @app.post("/api/engagements")
    def create_engagement(req: UploadSaveRequest):
        # 1. confirm enforcement: token must match THIS slug + exact content.
        try:
            info = service.validate_engagement_yaml(base_dir, req.yaml)
        except service.UploadError as e:
            raise HTTPException(status_code=400, detail=str(e))
        core = service.upload_core(info["slug"], req.yaml)
        if not planner.verify_token(core, req.confirm_token):
            raise HTTPException(status_code=403,
                                detail="upload not confirmed: validate first, then save")
        # 2. write (re-validates), with overwrite protection.
        try:
            return service.save_engagement_yaml(base_dir, req.yaml, overwrite=req.overwrite)
        except service.UploadError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except service.EngagementExists as e:
            raise HTTPException(status_code=409,
                                detail=f"engagement {e} already exists; set overwrite to replace it")

    @app.get("/")
    def index():
        idx = _STATIC / "index.html"
        if not idx.exists():
            return JSONResponse({"error": "frontend not found"}, status_code=500)
        return FileResponse(idx)

    return app
