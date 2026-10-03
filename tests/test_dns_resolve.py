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


# --------------------------------------------------------------------------- #
# dnsx must NOT be throttled to the Amazon per-host rate (queries resolvers)
# --------------------------------------------------------------------------- #
def test_dnsx_args_have_no_rate_flag(registry):
    args = registry["dnsx"].args
    assert "-rl" not in args and "{rps}" not in args
    assert registry["dnsx"].resolver is True


def test_timeout_ingests_partial_output_from_sidecar(dns_scope, registry, tmp_path):
    """A timed-out dnsx may never flush its own -o file; the partial results it
    printed are in the captured-stdout sidecar '<out>.log'. They must be stored."""
    stage, store, _ = _stage(dns_scope, registry, tmp_path)
    rid0 = store.start_run("passive_recon")
    for h in ("www.amazon.com", "cdn.amazon.com"):
        store.upsert_asset("subdomain", h, rid0)

    def killed(hosts, out_dir):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        out = Path(out_dir) / "dnsx.out"
        out.write_text("")                              # -o never flushed: empty
        (Path(out_dir) / "dnsx.out.log").write_text(    # captured stdout: partial
            "www.amazon.com [A] [1.2.3.4]\ncdn.amazon.com [A] [5.6.7.8]\n")
        return [SimpleNamespace(output_path=str(out), exit_code=-1, timed_out=True)]

    res = stage.run(executor=killed)
    assert res.resolved == 2                            # recovered from the sidecar
    assert sorted(store.keys_where_flag("subdomain", "resolves", True)) == \
        ["cdn.amazon.com", "www.amazon.com"]
    assert store.get_run(res.run_id).status == "completed"


# --------------------------------------------------------------------------- #
# REAL dnsx output: ANSI color escapes + CRLF (the gap the \n fixtures missed).
# dnsx -a -resp colorizes its -o file by default: "[<esc>35mA<esc>0m] [<esc>32mIP<esc>0m]".
# --------------------------------------------------------------------------- #
def test_parse_dnsx_real_colored_crlf_output(tmp_path):
    ESC = "\x1b"
    def rec(host, rtype, val, tcol, vcol):
        return (f"{host} [{ESC}[{tcol}m{rtype}{ESC}[0m] "
                f"[{ESC}[{vcol}m{val}{ESC}[0m] \r\n")   # trailing space + CRLF, like dnsx
    f = tmp_path / "dnsx.out"
    f.write_bytes((
        rec("154-60.amazon.com", "A", "204.177.154.60", "35", "32")
        + rec("154-60.amazon.com", "A", "204.177.154.61", "35", "32")   # 2nd A, same host
        + rec("cdn.amazon.com", "CNAME", "d1.cloudfront.net", "35", "36")
        + rec("ipv6.amazon.com", "AAAA", "2600:9000::1", "35", "32")
    ).encode("utf-8"))
    res = {r.host: r for r in parse_dnsx(f)}
    assert set(res) == {"154-60.amazon.com", "cdn.amazon.com", "ipv6.amazon.com"}
    assert res["154-60.amazon.com"].a == ["204.177.154.60", "204.177.154.61"]
    assert res["cdn.amazon.com"].cname == ["d1.cloudfront.net"]
    assert res["ipv6.amazon.com"].aaaa == ["2600:9000::1"]
    # no escape bytes leaked into stored values
    assert all("\x1b" not in v for r in res.values() for v in r.a + r.aaaa + r.cname)


def test_dnsx_args_disable_color(registry):
    assert "-nc" in registry["dnsx"].args.split()


# --------------------------------------------------------------------------- #
# chunked execution
# --------------------------------------------------------------------------- #
def _chunk_scope(dns_scope, size):
    return dataclasses.replace(dns_scope, limits=dataclasses.replace(
        dns_scope.limits, chunk_sizes={"dns_resolve": size}))


class _ChunkDnsRunner:
    def __init__(self, fail_after=None):
        self.chunks = []
        self.fail_after = fail_after

    def __call__(self, hosts, out_dir):            # executor signature
        self.chunks.append(list(hosts))
        if self.fail_after is not None and len(self.chunks) > self.fail_after:
            raise KeyboardInterrupt
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        p = Path(out_dir) / "dnsx.out"
        p.write_text("".join(f"{h} [A] [10.0.0.{i}]\n" for i, h in enumerate(hosts)))
        return [SimpleNamespace(output_path=str(p), exit_code=0, timed_out=False)]


def test_dns_runs_multiple_chunks_and_ingests_all(dns_scope, registry, tmp_path):
    scope = _chunk_scope(dns_scope, 2)
    stage, store, audit = _stage(scope, registry, tmp_path)
    rid = store.start_run("passive_recon")
    hosts = [f"h{i}.amazon.com" for i in range(5)]
    for h in hosts:
        store.upsert_asset("subdomain", h, rid)
    runner = _ChunkDnsRunner()
    res = stage.run(executor=runner)
    assert [len(c) for c in runner.chunks] == [2, 2, 1]
    assert res.resolved == 5
    assert sum(r["event"] == "chunk_completed" for r in audit.read_all()) == 3


def test_dns_interrupt_after_first_chunk_keeps_chunk_one(dns_scope, registry, tmp_path):
    scope = _chunk_scope(dns_scope, 2)
    stage, store, _ = _stage(scope, registry, tmp_path)
    rid = store.start_run("passive_recon")
    hosts = [f"h{i}.amazon.com" for i in range(5)]
    for h in hosts:
        store.upsert_asset("subdomain", h, rid)
    res = stage.run(executor=_ChunkDnsRunner(fail_after=1))
    assert res.interrupted and res.resolved == 2
    assert store.get_run(res.run_id).status == "interrupted"
    assert len(store.keys_where_flag("subdomain", "resolves", True)) == 2
