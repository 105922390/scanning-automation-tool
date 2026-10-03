"""Phase 2b run layer: confirm tokens, background jobs, status, log tailing.
Execution is faked — no real stage runs, no network."""

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.store import Store
from reconpilot.web import planner
from reconpilot.web.app import create_app
from reconpilot.web.jobs import JobManager, job_log
from reconpilot.web.run_exec import execute_plan


@pytest.fixture
def engdir(tmp_path):
    d = tmp_path / "engagements"
    d.mkdir()
    (d / "demo.yaml").write_text(
        "engagement:\n  name: demo\n  program_url: https://x.test/demo\n"
        "  authorized_by: t\n  authorized_date: 2026-10-01\n"
        "in_scope:\n  domains: [demo.com, '*.demo.com']\n"
        "limits:\n  max_rps_per_host: 5\n  max_global_concurrency: 5\n"
        "  max_requests_per_run: 50000\n  safe_mode: true\n"
        "allowed_tools: [subfinder, amass, dnsx, httpx]\n")
    store = Store.open_for_engagement("demo", base_dir=d)
    rid = store.start_run("passive_recon")
    store.upsert_asset("subdomain", "api.demo.com", rid, attrs={"resolves": True})
    store.close()
    return d


# --------------------------------------------------------------------------- #
# confirm tokens
# --------------------------------------------------------------------------- #
def test_confirm_token_roundtrip_and_tamper():
    core = planner.plan_core("demo", "liveness", {"host": "www.demo.com"})
    tok = planner.confirm_token(core)
    assert planner.verify_token(core, tok)
    assert not planner.verify_token(core, "")
    assert not planner.verify_token(core, "deadbeef")
    # changing any field invalidates the token
    tampered = planner.plan_core("demo", "liveness", {"host": "evil.com"})
    assert not planner.verify_token(tampered, tok)


# --------------------------------------------------------------------------- #
# JobManager with a fake executor
# --------------------------------------------------------------------------- #
def test_job_completes_with_fake_executor():
    seen = {}
    def fake(plan, canceller=None):
        seen.update(plan)
        return {"summary": "ok", "run_id": 7}
    jm = JobManager(fake)
    job = jm.submit("demo", "liveness", {"host": "www.demo.com"})
    assert job.wait(2)
    assert job.status == "completed" and job.result == {"summary": "ok", "run_id": 7}
    assert job.ended_at and seen["stage"] == "liveness"
    assert jm.get(job.id) is job


def test_job_failed_on_executor_error():
    def boom(plan, canceller=None):
        raise RuntimeError("nope")
    job = JobManager(boom).submit("demo", "dns_resolve", {})
    assert job.wait(2) and job.status == "failed" and "RuntimeError: nope" in job.error


def test_job_interrupted():
    def ki(plan, canceller=None):
        raise KeyboardInterrupt
    job = JobManager(ki).submit("demo", "liveness", {})
    assert job.wait(2) and job.status == "interrupted"


def test_default_executor_runs_through_run_stage(engdir, monkeypatch):
    # execute_plan is wired to orchestrate.run_stage now; verify it delegates there
    # (patched so nothing real runs / no network).
    import reconpilot.orchestrate as orch
    calls = []

    def fake_run_stage(scope, stage_cls, stage_name, **kw):
        calls.append((stage_cls, stage_name, kw))
        return SimpleNamespace(
            result=SimpleNamespace(summary_text=lambda: "ok", run_id=1),
            store=SimpleNamespace(close=lambda: None), audit=None, stage=None, out=None)

    monkeypatch.setattr(orch, "run_stage", fake_run_stage)
    job = JobManager(lambda plan, c=None: execute_plan(plan, engdir, c)).submit("demo", "liveness", {})
    assert job.wait(2) and job.status == "completed"
    assert job.result == {"summary": "ok", "run_id": 1}
    assert calls and calls[0][1] == "liveness"


def test_cli_and_web_share_one_run_stage(engdir, monkeypatch, capsys):
    """Both the CLI active-stage path and the web execute_plan go through the SAME
    orchestrate.run_stage — one construction path. Patch it once; both hit it."""
    import reconpilot.orchestrate as orch
    from reconpilot import cli
    from reconpilot.engagement import load_engagement
    from reconpilot.stages import DnsResolveStage, LivenessStage

    calls = []

    def fake_run_stage(scope, stage_cls, stage_name, **kw):
        calls.append({"stage_cls": stage_cls, "stage_name": stage_name,
                      "engagement": scope.engagement.name, "kw": kw})
        return SimpleNamespace(
            result=SimpleNamespace(summary_text=lambda: "ok", run_id=1,
                                   input_hosts=0, probed=0),
            store=SimpleNamespace(close=lambda: None, path="x"),
            audit=SimpleNamespace(path="y"), stage=SimpleNamespace(TOOL="dnsx"), out=None)

    monkeypatch.setattr(orch, "run_stage", fake_run_stage)

    # CLI path: `--run-dns` on the demo engagement
    rc = cli.main(["-e", "demo", "--engagements-dir", str(engdir), "--run-dns"])
    assert rc == 0

    # Web path: execute_plan for a liveness plan
    execute_plan({"engagement": "demo", "stage": "liveness", "params": {}}, engdir)

    assert len(calls) == 2
    assert calls[0]["stage_cls"] is DnsResolveStage and calls[0]["stage_name"] == "dns_resolve"
    assert calls[1]["stage_cls"] is LivenessStage and calls[1]["stage_name"] == "liveness"


# --------------------------------------------------------------------------- #
# log tailing
# --------------------------------------------------------------------------- #
def test_job_log_tails_events_since_start(engdir):
    # audit written AFTER the job starts should appear; earlier events excluded
    audit = AuditLog(Store.engagement_db_path("demo", engdir).with_name("audit.jsonl"),
                     engagement="demo")
    audit.log_event("old_event", stage="liveness")
    time.sleep(0.01)
    job = JobManager(lambda p: None).submit("demo", "liveness", {})
    job.wait(2)
    time.sleep(0.01)
    audit.log_event("chunk_completed", stage="liveness", run=1, chunk=0)
    audit.log_event("chunk_completed", stage="liveness", run=1, chunk=1)

    first = job_log(engdir, job, offset=0)
    evs = [e["event"] for e in first["events"]]
    assert "old_event" not in evs and evs.count("chunk_completed") == 2
    # offset paging: from the end returns nothing new
    nxt = job_log(engdir, job, offset=first["next_offset"])
    assert nxt["events"] == [] and nxt["next_offset"] == first["next_offset"]


# --------------------------------------------------------------------------- #
# /api/run endpoint over raw ASGI
# --------------------------------------------------------------------------- #
async def _asgi(app, method, path, body_obj=None, host="127.0.0.1:8000"):
    raw = json.dumps(body_obj).encode() if body_obj is not None else b""
    headers = [(b"host", host.encode())]
    if body_obj is not None:
        headers += [(b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "path": path, "raw_path": path.encode(),
             "query_string": b"", "scheme": "http", "root_path": "",
             "headers": headers, "client": ("127.0.0.1", 5), "server": ("127.0.0.1", 8000)}
    out, body = {}, bytearray()

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            body.extend(msg.get("body", b""))

    await app(scope, receive, send)
    out["json"] = json.loads(bytes(body) or b"null")
    return out


def _app_with_fake(engdir):
    runs = []
    def fake(plan, canceller=None):
        runs.append(plan)
        return {"summary": f"ran {plan['stage']}"}
    return create_app(base_dir=engdir, executor=fake), runs


def _valid_plan_body(engdir, prompt="probe live hosts"):
    p = planner.plan(engdir, "demo", prompt)
    assert p.ok
    return {"plan": {"engagement": p.engagement, "stage": p.stage, "params": p.params},
            "confirm_token": p.confirm_token}


def test_run_rejected_without_confirm_token(engdir):
    app, runs = _app_with_fake(engdir)
    body = _valid_plan_body(engdir)
    body["confirm_token"] = ""                      # not confirmed
    res = asyncio.run(_asgi(app, "POST", "/api/run", body))
    assert res["status"] == 403 and "not confirmed" in res["json"]["detail"]
    assert runs == []                               # nothing executed


def test_run_rejected_with_tampered_plan(engdir):
    # token minted for the original plan; attacker swaps params afterwards
    app, runs = _app_with_fake(engdir)
    body = _valid_plan_body(engdir, "probe app.demo.com")
    body["plan"]["params"] = {"host": "evil.com"}   # token no longer matches
    res = asyncio.run(_asgi(app, "POST", "/api/run", body))
    assert res["status"] == 403 and runs == []


def test_run_revalidates_scope_even_with_valid_token(engdir):
    # a VALID token for an out-of-scope host: server-side re-validation must reject
    app, runs = _app_with_fake(engdir)
    core_params = {"host": "evil.com"}
    core = planner.plan_core("demo", "liveness", core_params)
    body = {"plan": {"engagement": "demo", "stage": "liveness", "params": core_params},
            "confirm_token": planner.confirm_token(core)}
    res = asyncio.run(_asgi(app, "POST", "/api/run", body))
    assert res["status"] == 400 and "out of scope" in res["json"]["detail"]
    assert runs == []


def test_run_starts_job_and_status_transitions(engdir):
    app, runs = _app_with_fake(engdir)
    res = asyncio.run(_asgi(app, "POST", "/api/run", _valid_plan_body(engdir)))
    assert res["status"] == 200
    run_id = res["json"]["run_id"]
    # poll status until done
    for _ in range(40):
        st = asyncio.run(_asgi(app, "GET", f"/api/runs/{run_id}/status"))
        assert st["status"] == 200
        if st["json"]["done"]:
            break
        time.sleep(0.05)
    assert st["json"]["status"] == "completed"
    assert st["json"]["result"] == {"summary": "ran liveness"}
    assert runs and runs[0]["stage"] == "liveness"


def test_run_unknown_engagement_404(engdir):
    app, _ = _app_with_fake(engdir)
    core = planner.plan_core("nope", "liveness", {})
    body = {"plan": {"engagement": "nope", "stage": "liveness", "params": {}},
            "confirm_token": planner.confirm_token(core)}
    res = asyncio.run(_asgi(app, "POST", "/api/run", body))
    assert res["status"] == 404


def test_run_status_unknown_id_404(engdir):
    app, _ = _app_with_fake(engdir)
    res = asyncio.run(_asgi(app, "GET", "/api/runs/deadbeef/status"))
    assert res["status"] == 404


def test_run_endpoint_rejects_foreign_host(engdir):
    app, runs = _app_with_fake(engdir)
    res = asyncio.run(_asgi(app, "POST", "/api/run", _valid_plan_body(engdir), host="attacker.com"))
    assert res["status"] == 403 and runs == []


def test_web_run_rejects_out_of_scope_host_before_execution(tmp_path, monkeypatch):
    """A confirmed liveness --host www.google.com (out of scope for amazon-vrp) must
    be rejected by server-side scope re-validation BEFORE run_stage/execute_plan is
    reached — proving the browser can't trigger an out-of-scope scan even with a
    valid confirm token. Uses the REAL default executor; spies on run_stage."""
    import reconpilot.orchestrate as orch
    from reconpilot.web.app import create_app

    # a temp copy of the real amazon-vrp engagement (no live DB side effects)
    d = tmp_path / "engagements"
    d.mkdir()
    repo_yaml = Path(__file__).resolve().parent.parent / "engagements" / "amazon-vrp.yaml"
    (d / "amazon-vrp.yaml").write_text(repo_yaml.read_text(encoding="utf-8"), encoding="utf-8")

    # fail loudly if execution is ever reached for this request
    def tripwire(*a, **k):
        raise AssertionError("run_stage must NOT be called for an out-of-scope host")
    monkeypatch.setattr(orch, "run_stage", tripwire)

    app = create_app(base_dir=d)          # default (real) executor -> execute_plan -> run_stage
    params = {"host": "www.google.com"}
    core = planner.plan_core("amazon-vrp", "liveness", params)
    body = {"plan": {"engagement": "amazon-vrp", "stage": "liveness", "params": params},
            "confirm_token": planner.confirm_token(core)}      # a VALID token

    res = asyncio.run(_asgi(app, "POST", "/api/run", body))
    assert res["status"] == 400
    assert "out of scope" in res["json"]["detail"] and "google.com" in res["json"]["detail"]


# --------------------------------------------------------------------------- #
# Stop: cancel a running job + kill the child tool process tree
# --------------------------------------------------------------------------- #
def test_stop_cancels_running_job():
    import threading
    started = threading.Event()

    def long_job(plan, canceller):
        started.set()
        # emulate the runner: wait until cancel is requested, then stop
        if canceller.wait(5):
            raise KeyboardInterrupt("run cancelled")
        return {"summary": "finished (should not happen)"}

    jm = JobManager(long_job)
    job = jm.submit("demo", "liveness", {})
    assert started.wait(2)
    assert jm.stop(job.id) is job
    assert job.wait(3) and job.status == "cancelled"


def test_stop_unknown_job_returns_none():
    assert JobManager(lambda p, c=None: None).stop("nope") is None


def test_canceller_kills_real_child_process_tree(tmp_path):
    # the canceller must actually kill a live child tree (the manual pain point)
    import os, subprocess, time
    from reconpilot.web.jobs import Canceller
    from reconpilot.runner import _spawn

    py = __import__("sys").executable
    proc = _spawn([py, "-c", "import time; time.sleep(60)"])
    c = Canceller()
    c.register(proc)
    c.cancel()                                   # kill tree
    # the process must be dead shortly after
    for _ in range(50):
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    assert proc.poll() is not None               # child no longer running


def test_stop_endpoint_cancels_and_404(engdir):
    import threading
    from reconpilot.web.app import create_app
    gate = threading.Event()

    def long_job(plan, canceller):
        gate.set()
        if canceller.wait(5):
            raise KeyboardInterrupt("run cancelled")
        return {"summary": "x"}

    app = create_app(base_dir=engdir, executor=long_job)
    started = asyncio.run(_asgi(app, "POST", "/api/run", _valid_plan_body(engdir)))
    rid = started["json"]["run_id"]
    assert gate.wait(2)
    stopped = asyncio.run(_asgi(app, "POST", f"/api/runs/{rid}/stop"))
    assert stopped["status"] == 200 and stopped["json"]["stopping"] is True
    # unknown run -> 404
    nf = asyncio.run(_asgi(app, "POST", "/api/runs/deadbeef/stop"))
    assert nf["status"] == 404
