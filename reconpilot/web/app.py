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

from ..engagement import DEFAULT_DIR
from . import service

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


def create_app(base_dir: str | Path = DEFAULT_DIR, allowed_hosts=ALLOWED_HOSTS) -> FastAPI:
    app = FastAPI(title="ReconPilot", docs_url=None, redoc_url=None)

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

    @app.get("/")
    def index():
        idx = _STATIC / "index.html"
        if not idx.exists():
            return JSONResponse({"error": "frontend not found"}, status_code=500)
        return FileResponse(idx)

    return app
