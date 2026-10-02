"""dns_resolve: dnsx output parsing + resolution-status storage. No network."""

import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.config import load_tools
from reconpilot.stages import DnsResolveStage, parse_dnsx
from reconpilot.store import Store

REPO_TOOLS = Path(__file__).resolve().parent.parent / "tools.yaml"


@pytest.fixture
def dns_scope(scope):
    # conftest scope allowlists subfinder/httpx/nuclei; add dnsx for this stage
    return dataclasses.replace(
        scope, allowed_tools=frozenset(scope.allowed_tools | {"dnsx"}))


@pytest.fixture
def registry():
    return load_tools(REPO_TOOLS)


def _stage(dns_scope, registry, tmp_path):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement="t")
    stage = DnsResolveStage(dns_scope, registry, store, audit, runner=None,
                            output_dir=tmp_path / "out")
    return stage, store, audit


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def test_parse_dnsx_text_format(tmp_path):
    f = tmp_path / "dnsx.out"
    f.write_text(
        "www.amazon.com [A] [1.2.3.4]\n"
        "www.amazon.com [A] [1.2.3.5]\n"                 # second A, same host
        "www.amazon.com [AAAA] [2600:9000::1]\n"
        "cdn.amazon.com [CNAME] [d123.cloudfront.net.]\n"  # trailing dot stripped
        "\n# comment line ignored\n"
        "dead.amazon.com\n")                             # no records -> excluded
    res = {r.host: r for r in parse_dnsx(f)}
    assert set(res) == {"www.amazon.com", "cdn.amazon.com"}   # dead host absent
    assert res["www.amazon.com"].a == ["1.2.3.4", "1.2.3.5"]
    assert res["www.amazon.com"].aaaa == ["2600:9000::1"]
    assert res["www.amazon.com"].ips == ["1.2.3.4", "1.2.3.5", "2600:9000::1"]
    assert res["cdn.amazon.com"].cname == ["d123.cloudfront.net"]
    assert res["cdn.amazon.com"].resolves and res["cdn.amazon.com"].a == []


def test_parse_dnsx_jsonl_format(tmp_path):
    f = tmp_path / "dnsx.json"
    f.write_text(
        json.dumps({"host": "api.amazon.com", "a": ["9.9.9.9"], "cname": ["x.elb.com"]}) + "\n"
        + json.dumps({"host": "ipv6.amazon.com", "aaaa": ["2600::1"]}) + "\n"
        + "not json, skipped\n")
    res = {r.host: r for r in parse_dnsx(f)}
    assert res["api.amazon.com"].a == ["9.9.9.9"]
    assert res["api.amazon.com"].cname == ["x.elb.com"]
    assert res["ipv6.amazon.com"].ips == ["2600::1"]


def test_parse_dnsx_missing_file_is_empty(tmp_path):
    assert parse_dnsx(tmp_path / "nope.out") == []


# --------------------------------------------------------------------------- #
# ingest + storage
# --------------------------------------------------------------------------- #
def test_ingest_marks_resolution_status_on_assets(dns_scope, registry, tmp_path):
    stage, store, _ = _stage(dns_scope, registry, tmp_path)
    # three known subdomains; only two will resolve
    rid0 = store.start_run("passive_recon")
    for h in ("www.amazon.com", "cdn.amazon.com", "dead.amazon.com"):
        store.upsert_asset("subdomain", h, rid0)

    f = tmp_path / "dnsx.out"
    f.write_text("www.amazon.com [A] [1.2.3.4]\n"
                 "cdn.amazon.com [CNAME] [d1.cloudfront.net]\n")
    rid = store.start_run("dns_resolve")
    resolved, ips = stage.ingest_dnsx_file(f, rid)
    assert resolved == 2 and ips == {"1.2.3.4"}

    rows = {a["key"]: a["attrs"] for a in store.list_assets(kind="subdomain", limit=100)}
    assert rows["www.amazon.com"]["resolves"] is True
    assert rows["www.amazon.com"]["a"] == ["1.2.3.4"]
    assert rows["www.amazon.com"]["resolved_at_run"] == rid
    assert rows["cdn.amazon.com"]["resolves"] is True
    # dead host was never in dnsx output -> no resolution attrs added
    assert "resolves" not in rows["dead.amazon.com"]


def test_hosts_to_resolve_reads_subdomains_from_db(dns_scope, registry, tmp_path):
    stage, store, _ = _stage(dns_scope, registry, tmp_path)
    rid = store.start_run("passive_recon")
    for h in ("b.amazon.com", "a.amazon.com"):
        store.upsert_asset("subdomain", h, rid)
    assert stage.hosts_to_resolve() == ["a.amazon.com", "b.amazon.com"]


def test_keys_where_flag_selects_resolved_only(dns_scope, registry, tmp_path):
    stage, store, _ = _stage(dns_scope, registry, tmp_path)
    rid = store.start_run("passive_recon")
    store.upsert_asset("subdomain", "up.amazon.com", rid, attrs={"resolves": True})
    store.upsert_asset("subdomain", "down.amazon.com", rid, attrs={"resolves": False})
    store.upsert_asset("subdomain", "unknown.amazon.com", rid)  # no flag
    assert store.keys_where_flag("subdomain", "resolves", True) == ["up.amazon.com"]
    assert store.keys_where_flag("subdomain", "resolves", False) == ["down.amazon.com"]


# --------------------------------------------------------------------------- #
# run() via a FAKE executor (no real dnsx)
# --------------------------------------------------------------------------- #
def _fake_executor(outfile_text):
    def run(hosts, out_dir):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        p = Path(out_dir) / "dnsx.out"
        p.write_text(outfile_text)
        return [SimpleNamespace(output_path=str(p), exit_code=0, timed_out=False)]
    return run


def test_run_with_fake_executor_resolves_and_completes(dns_scope, registry, tmp_path):
    stage, store, _ = _stage(dns_scope, registry, tmp_path)
    rid0 = store.start_run("passive_recon")
    for h in ("www.amazon.com", "cdn.amazon.com", "dead.amazon.com"):
        store.upsert_asset("subdomain", h, rid0)

    res = stage.run(executor=_fake_executor(
        "www.amazon.com [A] [1.2.3.4]\ncdn.amazon.com [A] [5.6.7.8]\n"))
    assert res.input_hosts == 3 and res.resolved == 2 and res.unresolved == 1
    assert res.new_ips == 2
    assert store.get_run(res.run_id).status == "completed"
    assert sorted(store.keys_where_flag("subdomain", "resolves", True)) == \
        ["cdn.amazon.com", "www.amazon.com"]


def test_run_interrupt_preserves_resolved_so_far(dns_scope, registry, tmp_path):
    stage, store, audit = _stage(dns_scope, registry, tmp_path)
    rid0 = store.start_run("passive_recon")
    store.upsert_asset("subdomain", "www.amazon.com", rid0)

    def boom(hosts, out_dir):
        # resolve one host, persist it, THEN get interrupted
        rid = store.last_run("dns_resolve").id
        stage.ingest_dnsx_file(
            _write(tmp_path / "partial.out", "www.amazon.com [A] [1.1.1.1]"), rid)
        raise KeyboardInterrupt

    res = stage.run(executor=boom)
    assert res.interrupted and res.interrupt_reason == "KeyboardInterrupt"
    assert store.get_run(res.run_id).status == "interrupted"
    assert store.keys_where_flag("subdomain", "resolves", True) == ["www.amazon.com"]


def test_dnsx_not_allowlisted_raises(scope, registry, tmp_path):
    # plain conftest scope does NOT allowlist dnsx
    with pytest.raises(ValueError):
        DnsResolveStage(scope, registry, Store(":memory:"),
                        AuditLog(tmp_path / "a.jsonl", engagement="t"),
                        runner=None, output_dir=tmp_path / "o")


def _write(path, text):
    Path(path).write_text(text)
    return path
