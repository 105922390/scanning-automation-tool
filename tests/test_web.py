"""Read-only dashboard: service layer against a temp DB + API wiring. No network."""

import json
from pathlib import Path

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.store import Store
from reconpilot.web import service
from reconpilot.web.app import create_app


@pytest.fixture
def engdir(tmp_path):
    """A temp engagements dir with one engagement ('demo') and a seeded store."""
    d = tmp_path / "engagements"
    d.mkdir()
    (d / "demo.yaml").write_text(
        "engagement:\n  name: demo\n  program_url: https://x.test/demo\n"
        "  authorized_by: t\n  authorized_date: 2026-10-01\n"
        "in_scope:\n  domains: [demo.com]\nallowed_tools: [httpx]\n")

    store = Store.open_for_engagement("demo", base_dir=d)
    r_pass = store.start_run("passive_recon")
    # a live host, a resolved-not-live host, a dead host, a redirect-dropped host
    store.upsert_asset("subdomain", "www.demo.com", r_pass,
                       attrs={"resolves": True, "live": True, "status_code": 200,
                              "title": "Home", "tech": ["nginx"], "ips": ["1.1.1.1", "1.1.1.2"]})
    store.upsert_asset("subdomain", "api.demo.com", r_pass,
                       attrs={"resolves": True, "ips": ["1.1.1.1"]})          # resolved, unprobed
    store.upsert_asset("subdomain", "dead.demo.com", r_pass, attrs={"resolves": False})
    store.upsert_asset("subdomain", "signin.demo.com", r_pass,
                       attrs={"resolves": True, "live": False,
                              "dropped_by_redirect": "drop_on_redirect_to:*.aws.amazon.com",
                              "ips": ["9.9.9.9"]})
    store.close()

    audit = AuditLog(d / "demo" / "audit.jsonl", engagement="demo")
    audit.log_event("drop_on_redirect", stage="liveness", run=2,
                    input_host="signin.demo.com", final_host="console.aws.amazon.com",
                    matched_rule="drop_on_redirect_to:*.aws.amazon.com", status_code=302)
    audit.log_event("tool_start", tool="httpx")     # noise the view must ignore
    return d


# --------------------------------------------------------------------------- #
# service layer
# --------------------------------------------------------------------------- #
def test_available_engagements(engdir):
    assert service.available_engagements(engdir) == ["demo"]


def test_stats(engdir):
    s = service.stats(engdir, "demo")
    assert s["subdomains"] == 4
    assert s["resolved"] == 3                 # www, api, signin
    assert s["live"] == 1                     # www only
    assert s["dropped_on_redirect"] == 1      # signin
    assert s["distinct_ips"] == 3             # 1.1.1.1, 1.1.1.2, 9.9.9.9 (deduped)


def test_assets_all_and_shape(engdir):
    d = service.assets(engdir, "demo", filter="all")
    assert d["total"] == 4
    row = {r["host"]: r for r in d["rows"]}["www.demo.com"]
    assert row["live"] is True and row["status_code"] == 200
    assert row["tech"] == ["nginx"] and row["resolves"] is True


@pytest.mark.parametrize("filt,expected", [
    ("resolved", {"www.demo.com", "api.demo.com", "signin.demo.com"}),
    ("live", {"www.demo.com"}),
    ("dropped", {"signin.demo.com"}),
])
def test_assets_filters(engdir, filt, expected):
    d = service.assets(engdir, "demo", filter=filt)
    assert {r["host"] for r in d["rows"]} == expected
    assert d["total"] == len(expected)


def test_assets_search_sort_and_paging(engdir):
    d = service.assets(engdir, "demo", search="demo.com", sort="host", limit=2, offset=0)
    assert [r["host"] for r in d["rows"]] == ["api.demo.com", "dead.demo.com"]  # alpha
    assert d["total"] == 4
    d2 = service.assets(engdir, "demo", sort="host", limit=2, offset=2)
    assert [r["host"] for r in d2["rows"]] == ["signin.demo.com", "www.demo.com"]


def test_assets_bad_filter_and_sort_raise(engdir):
    with pytest.raises(ValueError):
        service.assets(engdir, "demo", filter="bogus")
    with pytest.raises(ValueError):
        service.assets(engdir, "demo", sort="bogus")


def test_redirect_events(engdir):
    d = service.redirect_events(engdir, "demo")
    assert d["total"] == 1                     # tool_start noise excluded
    ev = d["rows"][0]
    assert ev["input_host"] == "signin.demo.com"
    assert ev["final_host"] == "console.aws.amazon.com"
    assert "aws.amazon.com" in ev["matched_rule"]


def test_unknown_engagement_raises(engdir):
    for call in (lambda: service.stats(engdir, "nope"),
                 lambda: service.assets(engdir, "nope"),
                 lambda: service.redirect_events(engdir, "nope")):
        with pytest.raises(service.UnknownEngagement):
            call()


def test_unknown_engagement_blocks_traversal(engdir):
    # a path-ish name is not in list_engagements -> rejected, never opened
    with pytest.raises(service.UnknownEngagement):
        service.stats(engdir, "../../etc/passwd")


# --------------------------------------------------------------------------- #
# app wiring + localhost-only launcher (no HTTP server started)
# --------------------------------------------------------------------------- #
def test_app_registers_expected_routes(engdir):
    app = create_app(base_dir=engdir)
    paths = {r.path for r in app.routes}
    assert {"/", "/api/engagements", "/api/engagements/{name}/stats",
            "/api/engagements/{name}/assets",
            "/api/engagements/{name}/redirect-events"} <= paths


def test_launcher_binds_localhost_only():
    from reconpilot.web import __main__ as web_main
    assert web_main.HOST == "127.0.0.1"
    src = Path(web_main.__file__).read_text(encoding="utf-8")
    assert "host=HOST" in src                 # the run() call binds HOST, not a literal
    assert '"0.0.0.0"' not in src and "'0.0.0.0'" not in src   # never a 0.0.0.0 bind


def test_index_html_exists_and_is_local_only():
    idx = Path(__file__).resolve().parent.parent / "reconpilot" / "web" / "static" / "index.html"
    assert idx.exists()
    html = idx.read_text(encoding="utf-8")
    assert "RECONPILOT" in html


# --------------------------------------------------------------------------- #
# Host-header allowlist (DNS-rebinding defense) + cache-control, via raw ASGI
# (no httpx/TestClient dependency)
# --------------------------------------------------------------------------- #
import asyncio
from reconpilot.web.app import host_is_allowed


@pytest.mark.parametrize("host,ok", [
    ("127.0.0.1", True), ("127.0.0.1:8000", True),
    ("localhost", True), ("localhost:8000", True),
    ("::1", True), ("[::1]:8000", True),
    ("attacker.com", False), ("attacker.com:8000", False),
    ("evil.127.0.0.1.nip.io", False), ("", False),
    ("127.0.0.1.attacker.com", False),
])
def test_host_is_allowed(host, ok):
    assert host_is_allowed(host) is ok


async def _asgi_get(app, path, host):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "GET", "path": path, "raw_path": path.encode(),
             "query_string": b"", "scheme": "http", "root_path": "",
             "headers": [(b"host", host.encode())] if host is not None else [],
             "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8000)}
    out = {}
    body = bytearray()

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
            out["headers"] = {k.decode().lower(): v.decode() for k, v in msg["headers"]}
        elif msg["type"] == "http.response.body":
            body.extend(msg.get("body", b""))

    await app(scope, receive, send)
    out["body"] = bytes(body)
    return out


def test_foreign_host_header_is_rejected(tmp_path):
    app = create_app(base_dir=tmp_path)            # empty dir: no DB needed
    res = asyncio.run(_asgi_get(app, "/api/engagements", "attacker.com"))
    assert res["status"] == 403
    assert b"forbidden host" in res["body"]


def test_localhost_hosts_pass_and_api_is_no_store(tmp_path):
    app = create_app(base_dir=tmp_path)
    for host in ("127.0.0.1:8000", "localhost:8000", "[::1]:8000"):
        res = asyncio.run(_asgi_get(app, "/api/engagements", host))
        assert res["status"] == 200, host
        assert res["headers"].get("cache-control") == "no-store"
