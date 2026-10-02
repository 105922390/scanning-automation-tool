"""Store + diff engine: upsert/dedup, run deltas, since-timestamp, triage, concurrency."""

import threading

import pytest

from reconpilot.store import Store, finding_fingerprint


class SeqClock:
    """Monotonic ISO timestamps: 2026-01-01T00:00:00+00:00, :01, :02, ..."""
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return f"2026-01-01T00:00:{self.n:02d}+00:00"


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


# --------------------------------------------------------------------------- #
# schema / runs
# --------------------------------------------------------------------------- #
def test_schema_init_is_idempotent():
    s = Store(":memory:")
    s._init_schema()   # second call must not raise
    assert s.counts() == {"assets": {}, "findings": 0, "runs": 0}
    s.close()


def test_run_context_marks_ok_and_error(store):
    with store.run("liveness", "httpx") as rid:
        assert store.get_run(rid).status == "running"
    assert store.get_run(rid).status == "ok"
    assert store.get_run(rid).ended_at is not None

    with pytest.raises(ValueError):
        with store.run("port_scan", "naabu") as rid2:
            raise ValueError("boom")
    r = store.get_run(rid2)
    assert r.status == "error" and "boom" in r.note


def test_last_run_filters_by_stage(store):
    store.start_run("passive_recon", "subfinder")
    r2 = store.start_run("liveness", "httpx")
    assert store.last_run().id == r2
    assert store.last_run("passive_recon").tool == "subfinder"


# --------------------------------------------------------------------------- #
# asset upsert / dedup
# --------------------------------------------------------------------------- #
def test_upsert_new_then_duplicate(store):
    rid = store.start_run("passive_recon")
    _id, is_new = store.upsert_asset("subdomain", "Foo.ACME.com", rid)
    assert is_new
    _id2, is_new2 = store.upsert_asset("subdomain", "foo.acme.com", rid)
    assert not is_new2 and _id == _id2        # case-insensitive dedup
    assert store.counts()["assets"]["subdomain"] == 1


def test_attrs_merge_and_last_seen_advances():
    clk = SeqClock()
    s = Store(":memory:", now=clk)
    r1 = s.start_run("liveness")
    aid, _ = s.upsert_asset("host", "a.acme.com", r1, {"status": 200, "title": "A"})
    r2 = s.start_run("liveness")
    s.upsert_asset("host", "a.acme.com", r2, {"title": "A2", "tech": "nginx"})
    row = s.list_assets(kind="host")[0]
    assert row["attrs"] == {"status": 200, "title": "A2", "tech": "nginx"}
    assert row["first_seen_run"] == r1 and row["last_seen_run"] == r2
    assert row["first_seen_at"] < row["last_seen_at"]
    s.close()


# --------------------------------------------------------------------------- #
# the diff engine
# --------------------------------------------------------------------------- #
def test_new_assets_in_run_is_the_delta(store):
    r1 = store.start_run("passive_recon")
    assert store.record_assets("subdomain", ["a.acme.com", "b.acme.com"], r1) == \
        ["a.acme.com", "b.acme.com"]
    r2 = store.start_run("passive_recon")
    new = store.record_assets("subdomain", ["b.acme.com", "c.acme.com"], r2)
    assert new == ["c.acme.com"]                       # only c is new
    delta = store.new_assets_in_run(r2, kind="subdomain")
    assert [d["key"] for d in delta] == ["c.acme.com"]
    assert store.new_assets_in_run(r1, kind="subdomain") == \
        store.new_assets_in_run(r1)                    # both a,b first-seen in r1
    assert len(store.new_assets_in_run(r1)) == 2


def test_new_assets_since_timestamp():
    clk = SeqClock()
    s = Store(":memory:", now=clk)
    r1 = s.start_run("passive_recon")       # ts :02 for the insert below
    s.record_assets("subdomain", ["old.acme.com"], r1)
    cutoff = clk()                          # capture a timestamp AFTER old insert
    r2 = s.start_run("passive_recon")
    s.record_assets("subdomain", ["new.acme.com"], r2)
    recent = s.new_assets_since(cutoff, kind="subdomain")
    assert [r["key"] for r in recent] == ["new.acme.com"]
    s.close()


def test_finding_dedup_and_run_delta(store):
    r1 = store.start_run("signal_scan", "nuclei")
    _, new1 = store.upsert_finding(tool="nuclei", name="CVE-2024-0001",
                                   target="a.acme.com", severity="High",
                                   matched_at="https://a.acme.com/x", run_id=r1)
    assert new1
    # same hit again -> not new (dedup by fingerprint), severity stored lowercased
    _, new1b = store.upsert_finding(tool="nuclei", name="CVE-2024-0001",
                                    target="a.acme.com", severity="High",
                                    matched_at="https://a.acme.com/x", run_id=r1)
    assert not new1b
    r2 = store.start_run("signal_scan", "nuclei")
    store.upsert_finding(tool="nuclei", name="CVE-2024-0001", target="a.acme.com",
                         severity="high", matched_at="https://a.acme.com/x", run_id=r2)
    store.upsert_finding(tool="nuclei", name="exposed-env", target="b.acme.com",
                         severity="medium", matched_at="https://b.acme.com/.env", run_id=r2)
    delta = store.new_findings_in_run(r2)
    assert [f["name"] for f in delta] == ["exposed-env"]   # the CVE already existed
    assert delta[0]["severity"] == "medium"


def test_findings_severity_ordering(store):
    r = store.start_run("signal_scan")
    for sev, nm in [("low", "l"), ("critical", "c"), ("info", "i"), ("high", "h")]:
        store.upsert_finding(tool="nuclei", name=nm, target="t", severity=sev,
                             matched_at=nm, run_id=r)
    order = [f["severity"] for f in store.new_findings_in_run(r)]
    assert order == ["critical", "high", "low", "info"]


def test_diff_summary(store):
    r = store.start_run("signal_scan")
    store.record_assets("subdomain", ["a.acme.com", "b.acme.com"], r)
    store.record_assets("host", ["a.acme.com"], r)
    store.upsert_finding(tool="nuclei", name="x", target="a", severity="high",
                         matched_at="1", run_id=r)
    store.upsert_finding(tool="nuclei", name="y", target="a", severity="high",
                         matched_at="2", run_id=r)
    d = store.diff_summary(r)
    assert d["new_assets"] == {"subdomain": 2, "host": 1}
    assert d["new_assets_total"] == 3
    assert d["new_findings_total"] == 2
    assert d["new_findings_by_severity"] == {"high": 2}


# --------------------------------------------------------------------------- #
# triage + browse
# --------------------------------------------------------------------------- #
def test_triage_update(store):
    r = store.start_run("signal_scan")
    fid, _ = store.upsert_finding(tool="nuclei", name="x", target="t",
                                  matched_at="1", run_id=r)
    assert store.get_finding(fid)["triage_status"] == "new"
    store.set_triage(fid, "reported", "submitted to program")
    f = store.get_finding(fid)
    assert f["triage_status"] == "reported" and f["triage_note"] == "submitted to program"


def test_list_assets_search_pagination_and_is_new_flag(store):
    r1 = store.start_run("passive_recon")
    store.record_assets("subdomain", ["old.acme.com"], r1)
    r2 = store.start_run("passive_recon")
    store.record_assets("subdomain", ["api.acme.com", "www.acme.com"], r2)

    hits = store.list_assets(kind="subdomain", search="api")
    assert [h["key"] for h in hits] == ["api.acme.com"]

    tagged = store.list_assets(kind="subdomain", new_in_run=r2)
    flags = {h["key"]: h["is_new"] for h in tagged}
    assert flags == {"api.acme.com": True, "www.acme.com": True, "old.acme.com": False}

    page = store.list_assets(kind="subdomain", limit=1, offset=0)
    assert len(page) == 1


def test_fingerprint_is_stable_and_discriminating():
    a = finding_fingerprint("nuclei", "CVE-1", "a.acme.com", "https://a/x")
    b = finding_fingerprint("NUCLEI", "cve-1", "A.ACME.COM", "HTTPS://A/X")
    c = finding_fingerprint("nuclei", "CVE-1", "a.acme.com", "https://a/y")
    assert a == b          # case-insensitive, stable
    assert a != c          # different matched_at -> different finding


# --------------------------------------------------------------------------- #
# concurrency
# --------------------------------------------------------------------------- #
def test_concurrent_upserts_are_consistent(store):
    r = store.start_run("passive_recon")
    n_threads, per = 20, 50

    def worker(k):
        for i in range(per):
            store.upsert_asset("subdomain", f"host-{i}.acme.com", r)  # heavy overlap
            store.upsert_asset("subdomain", f"t{k}-{i}.acme.com", r)  # unique per thread

    ts = [threading.Thread(target=worker, args=(k,)) for k in range(n_threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    # `per` shared keys + n_threads*per unique keys, all distinct & deduped
    assert store.counts()["assets"]["subdomain"] == per + n_threads * per
