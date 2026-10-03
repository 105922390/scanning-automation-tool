"""signal_scan (nuclei) plumbing: parse, scope-filter, leads store, chunk/interrupt,
UA + -no-interactsh argv, seam. Fakes only — no nuclei, no network."""

import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.config import Http, load_tools
from reconpilot.runner import GuardedRunner
from reconpilot.stages import NucleiStage, parse_nuclei_jsonl
from reconpilot.stages.signal_scan import LEAD_LABEL
from reconpilot.store import Store

REPO_TOOLS = Path(__file__).resolve().parent.parent / "tools.yaml"


@pytest.fixture
def registry():
    return load_tools(REPO_TOOLS)


@pytest.fixture
def sig_scope(scope):
    # conftest scope allowlists nuclei; add the Amazon-style http policy
    return dataclasses.replace(scope, http=Http(
        user_agent="amazonvrpresearcher_tester", require_user_agent=True,
        no_third_party_oob=True))


def _stage(sig_scope, registry, tmp_path, runner=None):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement="t")
    stage = NucleiStage(sig_scope, registry, store, audit, runner, tmp_path / "out")
    return stage, store, audit


# --------------------------------------------------------------------------- #
# parser: real-format nuclei jsonl, ANSI + CRLF
# --------------------------------------------------------------------------- #
def test_parse_nuclei_jsonl_real_colored_crlf(tmp_path):
    ESC = "\x1b"
    rec1 = {"template-id": "tech-detect", "info": {"name": "Tech Detect", "severity": "info"},
            "host": "www.acme.com", "matched-at": "https://www.acme.com", "type": "http"}
    rec2 = {"templateID": "CVE-2021-1234", "info": {"name": "Some CVE", "severity": "high"},
            "host": "api.acme.com", "matched_at": "https://api.acme.com/x", "type": "http"}
    f = tmp_path / "nuclei.out"
    f.write_bytes((
        f"{ESC}[36m" + json.dumps(rec1) + f"{ESC}[0m\r\n"     # colored + CRLF
        "banner line, not json\r\n"
        + json.dumps(rec2) + "\r\n").encode())
    out = parse_nuclei_jsonl(f)
    assert [o["template_id"] for o in out] == ["tech-detect", "CVE-2021-1234"]
    assert out[0]["name"] == "Tech Detect" and out[0]["severity"] == "info"
    assert out[1]["host"] == "api.acme.com" and out[1]["matched_at"] == "https://api.acme.com/x"
    assert all("\x1b" not in o["template_id"] for o in out)


# --------------------------------------------------------------------------- #
# nuclei argv carries UA + -no-interactsh (via the real runner, dry-run, no net)
# --------------------------------------------------------------------------- #
def test_nuclei_argv_has_ua_and_disables_interactsh(sig_scope, registry, tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl", engagement="t")
    runner = GuardedRunner(sig_scope, registry, audit, which=lambda n: "/usr/bin/nuclei")
    res = runner.run("nuclei", ["www.acme.com"], tmp_path / "o", dry_run=True)
    cmd = res.invocations[0].command
    assert "-H" in cmd and any("User-Agent: amazonvrpresearcher_tester" in t for t in cmd)
    assert "-no-interactsh" in cmd          # third-party OOB disabled
    assert "-nc" in cmd and "-jsonl" in cmd
    assert "-b" not in cmd                   # no blind/OOB callback server configured


# --------------------------------------------------------------------------- #
# ingest: store LEADS, scope-filter drops out-of-scope findings
# --------------------------------------------------------------------------- #
def test_ingest_stores_leads_and_drops_out_of_scope(sig_scope, registry, tmp_path):
    stage, store, audit = _stage(sig_scope, registry, tmp_path)
    rid = store.start_run("signal_scan")
    recs = [
        {"template-id": "t1", "info": {"name": "A", "severity": "low"},
         "host": "www.acme.com", "matched-at": "https://www.acme.com/a", "type": "http"},
        {"template-id": "t2", "info": {"name": "B", "severity": "high"},
         "host": "evil.com", "matched-at": "https://evil.com/b", "type": "http"},   # OOS
    ]
    f = tmp_path / "n.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    stored, dropped, examples = stage.ingest_nuclei_file(f, rid)
    assert stored == 1 and dropped == 1
    findings = store.list_findings()
    assert len(findings) == 1
    fnd = findings[0]
    assert fnd["target"] == "www.acme.com" and fnd["severity"] == "low"
    assert fnd["attrs"]["lead"] is True and fnd["attrs"]["label"] == LEAD_LABEL
    assert fnd["attrs"]["template_id"] == "t1"
    # out-of-scope finding audited as dropped, not stored
    drops = [r for r in audit.read_all() if r["event"] == "finding_dropped"]
    assert drops and drops[0]["host"] == "evil.com"


# --------------------------------------------------------------------------- #
# chunking + interrupt preserves stored findings
# --------------------------------------------------------------------------- #
def _chunk_scope(sig_scope, size):
    return dataclasses.replace(sig_scope, limits=dataclasses.replace(
        sig_scope.limits, chunk_sizes={"signal_scan": size}))


class _ChunkRunner:
    """One call per chunk; emits a finding per host. Can raise after N chunks."""
    def __init__(self, fail_after=None):
        self.chunks = []
        self.fail_after = fail_after

    def run(self, tool, hosts, out_dir, **kw):
        self.chunks.append(list(hosts))
        if self.fail_after is not None and len(self.chunks) > self.fail_after:
            raise KeyboardInterrupt
        recs = [{"template-id": "t", "info": {"name": "F", "severity": "info"},
                 "host": h, "matched-at": f"https://{h}/", "type": "http"} for h in hosts]
        p = Path(out_dir); p.mkdir(parents=True, exist_ok=True)
        fp = p / "nuclei.jsonl"
        fp.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        return SimpleNamespace(invocations=[
            SimpleNamespace(output_path=str(fp), exit_code=0, timed_out=False)])


def _seed_live(store, hosts):
    rid = store.start_run("liveness")
    for h in hosts:
        store.upsert_asset("subdomain", h, rid, attrs={"resolves": True, "live": True})


def test_multiple_chunks_store_all_findings(sig_scope, registry, tmp_path):
    scope = _chunk_scope(sig_scope, 2)
    stage, store, audit = _stage(scope, registry, tmp_path, runner=None)
    hosts = [f"h{i}.acme.com" for i in range(5)]
    _seed_live(store, hosts)
    runner = _ChunkRunner()
    stage.runner = None
    res = stage.run(executor=lambda h, o: runner.run("nuclei", h, o).invocations)
    assert [len(c) for c in runner.chunks] == [2, 2, 1]
    assert res.findings == 5 and res.hosts_scanned == 5
    assert len(store.list_findings()) == 5
    assert sum(r["event"] == "chunk_completed" for r in audit.read_all()) == 3


def test_interrupt_after_first_chunk_keeps_findings(sig_scope, registry, tmp_path):
    scope = _chunk_scope(sig_scope, 2)
    stage, store, _ = _stage(scope, registry, tmp_path)
    hosts = [f"h{i}.acme.com" for i in range(5)]
    _seed_live(store, hosts)
    runner = _ChunkRunner(fail_after=1)
    res = stage.run(executor=lambda h, o: runner.run("nuclei", h, o).invocations)
    assert res.interrupted and res.findings == 2
    assert store.get_run(res.run_id).status == "interrupted"
    assert len(store.list_findings()) == 2
    # the two scanned hosts are marked so a resume skips them
    assert len(store.keys_flagged("subdomain", true_flag="live",
                                  null_flag="signal_scanned_at_run")) == 3


def test_hosts_to_scan_are_live_and_unscanned(sig_scope, registry, tmp_path):
    stage, store, _ = _stage(sig_scope, registry, tmp_path)
    rid = store.start_run("liveness")
    store.upsert_asset("subdomain", "live1.acme.com", rid, attrs={"live": True})
    store.upsert_asset("subdomain", "live2.acme.com", rid,
                       attrs={"live": True, "signal_scanned_at_run": 1})   # already scanned
    store.upsert_asset("subdomain", "dead.acme.com", rid, attrs={"live": False})
    assert stage.hosts_to_scan() == ["live1.acme.com"]


# --------------------------------------------------------------------------- #
# seam: unwired until implemented
# --------------------------------------------------------------------------- #
def test_seam_raises_until_wired(sig_scope, registry, tmp_path):
    stage, store, _ = _stage(sig_scope, registry, tmp_path)
    store.upsert_asset("subdomain", "www.acme.com", store.start_run("liveness"),
                       attrs={"live": True})
    with pytest.raises(NotImplementedError):
        stage.run()           # no executor -> invoke_tool seam


def test_nuclei_not_allowlisted_raises(scope, registry, tmp_path):
    # a scope without nuclei allowlisted
    s = dataclasses.replace(scope, allowed_tools=frozenset({"httpx"}))
    with pytest.raises(ValueError):
        NucleiStage(s, registry, Store(":memory:"),
                    AuditLog(tmp_path / "a.jsonl", engagement="t"), None, tmp_path / "o")
