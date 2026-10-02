"""liveness: httpx JSONL parsing, redirect-drop policy, storage. No network."""

import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.config import Http, load_tools
from reconpilot.runner import GuardedRunner
from reconpilot.stages import LivenessStage, parse_httpx_jsonl
from reconpilot.store import Store

REPO_TOOLS = Path(__file__).resolve().parent.parent / "tools.yaml"


@pytest.fixture
def registry():
    return load_tools(REPO_TOOLS)


@pytest.fixture
def live_scope(scope):
    # httpx is already allowlisted in the conftest scope; add the redirect policy
    return dataclasses.replace(scope, http=Http(
        user_agent="amazonvrpresearcher_tester", require_user_agent=True,
        no_third_party_oob=True,
        drop_on_redirect_to=("*.aws.amazon.com", "midway-auth.amazon.com")))


def _stage(live_scope, registry, tmp_path):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement="t")
    stage = LivenessStage(live_scope, registry, store, audit, runner=None,
                          output_dir=tmp_path / "out")
    return stage, store, audit


def _jsonl(path, records):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return path


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def test_parse_httpx_jsonl_skips_noise(tmp_path):
    p = tmp_path / "httpx.json"
    p.write_text(
        json.dumps({"input": "a.amazon.com", "status_code": 200}) + "\n"
        "\n"                                   # blank
        "non-json banner line\n"
        + json.dumps({"input": "b.amazon.com", "status_code": 404}) + "\n")
    recs = parse_httpx_jsonl(p)
    assert [r["input"] for r in recs] == ["a.amazon.com", "b.amazon.com"]


# --------------------------------------------------------------------------- #
# ingest: live storage + redirect drop
# --------------------------------------------------------------------------- #
def test_ingest_stores_liveness_fields(live_scope, registry, tmp_path):
    stage, store, _ = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("liveness")
    f = _jsonl(tmp_path / "h.json", [{
        "input": "www.acme.com", "url": "https://www.acme.com/",
        "status_code": 200, "title": "Acme", "tech": ["Server: Server", "nginx"]}])
    live, dropped, _ = stage.ingest_httpx_file(f, rid)
    assert (live, dropped) == (1, 0)
    a = store.list_assets(kind="subdomain", search="www.acme.com")[0]["attrs"]
    assert a["live"] is True and a["status_code"] == 200 and a["title"] == "Acme"
    assert a["tech"] == ["Server: Server", "nginx"]
    assert a["url"] == "https://www.acme.com/"
    assert a["redirect_target"] == ""          # direct 200, no redirect


def test_in_scope_redirect_is_stored_not_followed(live_scope, registry, tmp_path):
    stage, store, _ = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("liveness")
    # 301 with a Location to an in-scope host: kept, target recorded, never fetched
    f = _jsonl(tmp_path / "h.json", [{
        "input": "go.acme.com", "url": "https://go.acme.com", "status_code": 301,
        "location": "https://www.acme.com/home"}])
    live, dropped, _ = stage.ingest_httpx_file(f, rid)
    assert (live, dropped) == (1, 0)
    a = store.list_assets(kind="subdomain", search="go.acme.com")[0]["attrs"]
    assert a["live"] is True and a["status_code"] == 301
    assert a["location"] == "https://www.acme.com/home"
    assert a["redirect_target"] == "www.acme.com"


def test_redirect_to_aws_or_midway_is_dropped_without_following(live_scope, registry, tmp_path):
    stage, store, audit = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("liveness")
    f = _jsonl(tmp_path / "h.json", [
        {"input": "good.acme.com", "url": "https://good.acme.com/", "status_code": 200},
        # Location header points at an AWS host -> dropped, never requested
        {"input": "signin.acme.com", "url": "https://signin.acme.com",
         "status_code": 302, "location": "https://console.aws.amazon.com/"},
        # Location points at midway -> dropped
        {"input": "corp.acme.com", "url": "https://corp.acme.com",
         "status_code": 302, "location": "https://midway-auth.amazon.com/login"},
    ])
    live, dropped, _ = stage.ingest_httpx_file(f, rid)
    assert live == 1 and dropped == 2
    assert store.keys_where_flag("subdomain", "live", True) == ["good.acme.com"]
    dropped_rows = {a["key"]: a["attrs"] for a in store.list_assets(kind="subdomain", limit=50)
                    if a["attrs"].get("dropped_by_redirect")}
    assert set(dropped_rows) == {"signin.acme.com", "corp.acme.com"}
    assert "aws.amazon.com" in dropped_rows["signin.acme.com"]["dropped_by_redirect"]
    # audit: a drop_on_redirect event per drop, naming the (un-fetched) target
    drops = {r["input_host"]: r["final_host"] for r in audit.read_all()
             if r["event"] == "drop_on_redirect"}
    assert drops["signin.acme.com"] == "console.aws.amazon.com"
    assert drops["corp.acme.com"] == "midway-auth.amazon.com"


def test_redirect_to_out_of_scope_host_is_dropped_by_guard(live_scope, registry, tmp_path):
    stage, store, audit = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("liveness")
    # Location to a host that is neither a drop-pattern nor in scope -> guard drop
    f = _jsonl(tmp_path / "h.json", [{
        "input": "ext.acme.com", "url": "https://ext.acme.com",
        "status_code": 302, "location": "https://tracker.evil.example.net/x"}])
    live, dropped, _ = stage.ingest_httpx_file(f, rid)
    assert (live, dropped) == (0, 1)
    rule = store.list_assets(kind="subdomain", search="ext.acme.com")[0]["attrs"]["dropped_by_redirect"]
    assert rule.startswith("out_of_scope_redirect:")
    drop = [r for r in audit.read_all() if r["event"] == "drop_on_redirect"][0]
    assert drop["final_host"] == "tracker.evil.example.net"


def test_relative_redirect_is_same_host_and_kept(live_scope, registry, tmp_path):
    stage, store, _ = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("liveness")
    # relative Location -> same host, nothing to check, stored as live
    f = _jsonl(tmp_path / "h.json", [{
        "input": "app.acme.com", "url": "https://app.acme.com", "status_code": 302,
        "location": "/login"}])
    live, dropped, _ = stage.ingest_httpx_file(f, rid)
    assert (live, dropped) == (1, 0)
    a = store.list_assets(kind="subdomain", search="app.acme.com")[0]["attrs"]
    assert a["live"] is True and a["redirect_target"] == ""


def test_hosts_to_probe_are_only_resolved(live_scope, registry, tmp_path):
    stage, store, _ = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("dns_resolve")
    store.upsert_asset("subdomain", "up.acme.com", rid, attrs={"resolves": True})
    store.upsert_asset("subdomain", "dead.acme.com", rid, attrs={"resolves": False})
    store.upsert_asset("subdomain", "unknown.acme.com", rid)
    assert stage.hosts_to_probe() == ["up.acme.com"]


# --------------------------------------------------------------------------- #
# run() via FAKE executor: incremental persistence + interrupt
# --------------------------------------------------------------------------- #
def _executor(records):
    def run(hosts, out_dir):
        p = _jsonl(Path(out_dir) / "httpx.json", records)
        return [SimpleNamespace(output_path=str(p), exit_code=0, timed_out=False)]
    return run


def test_run_with_fake_executor(live_scope, registry, tmp_path):
    stage, store, _ = _stage(live_scope, registry, tmp_path)
    rid = store.start_run("dns_resolve")
    store.upsert_asset("subdomain", "www.acme.com", rid, attrs={"resolves": True})
    res = stage.run(executor=_executor([
        {"input": "www.acme.com", "url": "https://www.acme.com/", "status_code": 200},
        {"input": "x.acme.com", "url": "https://x.acme.com", "status_code": 302,
         "location": "https://x.aws.amazon.com/"}]))
    assert res.live == 1 and res.dropped_redirect == 1
    assert store.get_run(res.run_id).status == "completed"


def test_run_interrupt_preserves_stored_liveness(live_scope, registry, tmp_path):
    stage, store, audit = _stage(live_scope, registry, tmp_path)

    def boom(hosts, out_dir):
        rid = store.last_run("liveness").id
        stage.ingest_httpx_file(_jsonl(Path(out_dir) / "p.json", [
            {"input": "www.acme.com", "url": "https://www.acme.com/",
             "status_code": 200}]), rid)
        raise KeyboardInterrupt

    res = stage.run(executor=boom)
    assert res.interrupted and res.interrupt_reason == "KeyboardInterrupt"
    assert store.get_run(res.run_id).status == "interrupted"
    assert store.keys_where_flag("subdomain", "live", True) == ["www.acme.com"]
    assert any(r["event"] == "run_interrupted" for r in audit.read_all())


# --------------------------------------------------------------------------- #
# the execution seam goes through the real runner WITH the UA guard (dry-run,
# no network): proves httpx argv carries the engagement User-Agent.
# --------------------------------------------------------------------------- #
def test_httpx_argv_carries_user_agent_via_runner(live_scope, registry, tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl", engagement="t")
    runner = GuardedRunner(live_scope, registry, audit, which=lambda n: "/usr/bin/httpx")
    # conftest scope is acme.com-based; use an in-scope host so the probe is built
    res = runner.run("httpx", ["www.acme.com"], tmp_path / "o", dry_run=True)
    cmd = res.invocations[0].command
    assert "-H" in cmd
    assert any("User-Agent: amazonvrpresearcher_tester" in tok for tok in cmd)
    assert "-json" in cmd              # parser contract: JSONL output
    assert "-fr" not in cmd            # scope safety: redirects are NOT followed


def test_seam_unimplemented_until_wired(live_scope, registry, tmp_path):
    stage, store, _ = _stage(live_scope, registry, tmp_path)
    store.upsert_asset("subdomain", "www.acme.com", store.start_run("dns_resolve"),
                       attrs={"resolves": True})
    # run() without an executor hits the seam -> NotImplementedError surfaces
    with pytest.raises(NotImplementedError):
        stage.run()
