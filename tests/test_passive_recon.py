"""Stage 1 passive_recon: roots, parsing, scope-filter, dedup, diff. No network."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.config import load_tools
from reconpilot.engagement import load_engagement
from reconpilot.scope_guard import ScopeGuard
from reconpilot.seeds import check_seed
from reconpilot.stages import PassiveReconStage, parse_hosts
from reconpilot.store import Store

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_ENGAGEMENTS = REPO_ROOT / "engagements"
REPO_TOOLS = REPO_ROOT / "tools.yaml"


@pytest.fixture
def amazon():
    return load_engagement("amazon-vrp", REPO_ENGAGEMENTS)


@pytest.fixture
def registry():
    return load_tools(REPO_TOOLS)


class FakeRunner:
    """Stands in for GuardedRunner: gates seeds/targets with the same functions
    the real one uses and writes canned tool output. No subprocess, no network."""
    def __init__(self, scope, outputs: dict[str, list[str]]):
        self.scope = scope
        self.guard = ScopeGuard(scope)
        self.outputs = outputs
        self.calls = []

    def run(self, tool, targets, output_dir, *, dry_run=False, seeds=False, **kw):
        self.calls.append((tool, list(targets), seeds))
        ok = ((lambda t: check_seed(self.scope, t).allowed) if seeds
              else self.guard.is_allowed)
        allowed = [t for t in targets if ok(t)]
        rejected = [t for t in targets if not ok(t)]
        invs = []
        if not dry_run:
            d = Path(output_dir)
            d.mkdir(parents=True, exist_ok=True)
            p = d / f"{tool}.out"
            p.write_text("\n".join(self.outputs.get(tool, [])) + "\n")
            invs = [SimpleNamespace(output_path=str(p), exit_code=0, command=[tool])]
        else:
            invs = [SimpleNamespace(output_path="", exit_code=None,
                                    command=[tool, "-d", t]) for t in allowed]
        return SimpleNamespace(invocations=invs, allowed=allowed, rejected=rejected,
                               skipped_reason="")


def _stage(amazon, registry, tmp_path, outputs):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement=amazon.engagement.name)
    runner = FakeRunner(amazon, outputs)
    return PassiveReconStage(amazon, registry, store, audit, runner, tmp_path / "out"), store, audit


# --------------------------------------------------------------------------- #
# roots + tool selection + parsing
# --------------------------------------------------------------------------- #
def test_enumeration_roots(amazon, registry, tmp_path):
    stage, *_ = _stage(amazon, registry, tmp_path, {})
    roots = stage.enumeration_roots()
    assert "amazon.com" in roots and "amazon.co.uk" in roots
    assert "amazon.com.au" in roots                # multi-part public suffix kept whole
    assert "amazonalexa.com" in roots              # wildcard base -> seed
    # plain host entry collapses onto its registrable domain (no separate root)
    assert "api.amazonalexa.com" not in roots
    assert not any(r.startswith("*.") for r in roots)   # no wildcards
    assert len(roots) == len(set(roots))
    # regression: com.be is not in the PSL; the root must not collapse to it
    assert "amazon.com.be" in roots and "com.be" not in roots
    assert len(roots) == 27                        # 26 marketplaces + amazonalexa.com


def test_underived_seed_is_dropped_and_audited(amazon, registry, tmp_path, monkeypatch):
    import reconpilot.stages.passive_recon as pr
    monkeypatch.setattr(pr, "enumeration_seeds", lambda scope: ["amazon.com", "com.be"])
    stage, _, audit = _stage(amazon, registry, tmp_path, {})
    assert stage.enumeration_roots() == ["amazon.com"]
    errs = [r for r in audit.read_all() if r["event"] == "seed_derivation_error"]
    assert [e["seed"] for e in errs] == ["com.be"]


def test_only_passive_subdomain_tools_selected(amazon, registry, tmp_path):
    stage, *_ = _stage(amazon, registry, tmp_path, {})
    assert set(stage.tools) == {"subfinder", "amass"}   # not httpx/gau/etc.


def test_parse_hosts_amass_graph_takes_every_fqdn_node(tmp_path):
    f = tmp_path / "amass.out"
    f.write_text(
        "a.amazon.cn (FQDN) --> cname_record --> B.amazon.cn (FQDN)\n"
        "amazon.cn (FQDN) --> ns_record --> ns1.amzndns-cn.com (FQDN)\n"
        "c.amazon.cn (FQDN) --> a_record --> 54.222.0.1 (IPAddress)\n"
        "a.amazon.cn (FQDN) --> cname_record --> elb.amazonaws.com (FQDN)\n")
    assert parse_hosts(f) == ["a.amazon.cn", "b.amazon.cn", "amazon.cn",
                              "ns1.amzndns-cn.com", "c.amazon.cn", "elb.amazonaws.com"]


def test_parse_hosts_handles_messy_output(tmp_path):
    f = tmp_path / "o.txt"
    f.write_text("www.amazon.com\n"
                 "# a comment\n"
                 "\n"
                 "api.amazon.com (FQDN) --> 1.2.3.4\n"
                 "  DEV.amazon.com  \n")
    assert parse_hosts(f) == ["www.amazon.com", "api.amazon.com", "dev.amazon.com"]


# --------------------------------------------------------------------------- #
# scope filtering of RESULTS (the critical bit)
# --------------------------------------------------------------------------- #
def test_results_scope_filtered_and_rejections_audited(amazon, registry, tmp_path):
    outputs = {"subfinder": [
        "www.amazon.com",          # keep
        "aws-internal.amazon.com", # drop: label_contains:aws
        "test.amazon.com",         # drop: label_equals:test
        "foo.dev",                 # drop: *.dev
        "shop.amazon.co.uk",       # keep
    ], "amass": []}
    stage, store, audit = _stage(amazon, registry, tmp_path, outputs)
    res = stage.run()
    assert res.total_found == 5
    assert res.in_scope_kept == 2
    assert res.out_of_scope_dropped == 3
    kept = {a["key"] for a in store.list_assets(kind="subdomain")}
    assert kept == {"www.amazon.com", "shop.amazon.co.uk"}
    # rejections recorded with matched_rule in the audit log
    rejects = [r for r in audit.read_all()
               if r.get("event") == "scope_decision" and not r.get("allowed")]
    rules = {r["host"]: r["matched_rule"] for r in rejects}
    assert rules["aws-internal.amazon.com"] == "label_contains:aws"
    assert rules["test.amazon.com"] == "label_equals:test"
    assert rules["foo.dev"] == "*.dev"


# --------------------------------------------------------------------------- #
# dedup
# --------------------------------------------------------------------------- #
def test_dedup_across_tools(amazon, registry, tmp_path):
    outputs = {"subfinder": ["www.amazon.com", "WWW.amazon.com"],
               "amass": ["www.amazon.com"]}
    stage, store, _ = _stage(amazon, registry, tmp_path, outputs)
    res = stage.run()
    assert res.in_scope_kept == 1
    assert store.counts()["assets"]["subdomain"] == 1


# --------------------------------------------------------------------------- #
# diff on a simulated second run
# --------------------------------------------------------------------------- #
def test_diff_reports_only_new_on_second_run(amazon, registry, tmp_path):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement=amazon.engagement.name)

    r1 = FakeRunner(amazon, {"subfinder": ["www.amazon.com", "api.amazon.com"], "amass": []})
    s1 = PassiveReconStage(amazon, registry, store, audit, r1, tmp_path / "o1")
    res1 = s1.run()
    assert sorted(res1.new_subdomains) == ["api.amazon.com", "www.amazon.com"]

    # second run: one repeat + one genuinely new host
    r2 = FakeRunner(amazon, {"subfinder": ["www.amazon.com", "new.amazon.com"], "amass": []})
    s2 = PassiveReconStage(amazon, registry, store, audit, r2, tmp_path / "o2")
    res2 = s2.run()
    assert res2.total_found == 2
    assert res2.new_subdomains == ["new.amazon.com"]     # only the new one
    assert store.counts()["assets"]["subdomain"] == 3


# --------------------------------------------------------------------------- #
# wildcard-only root is a SEED (amazonalexa.com apex is not a target)
# --------------------------------------------------------------------------- #
def test_wildcard_only_root_is_enumerated(amazon, registry, tmp_path):
    stage, _, _ = _stage(amazon, registry, tmp_path, {"subfinder": [], "amass": []})
    # precondition: the apex really is NOT an in-scope target
    assert not ScopeGuard(amazon).is_allowed("amazonalexa.com")
    res = stage.run()
    assert "amazonalexa.com" in res.roots_enumerated
    assert "amazon.com" in res.roots_enumerated
    assert res.roots_dropped == []
    # every call is seed mode, one root per call; each tool got the wildcard base
    assert all(seeds and len(t) == 1 for _, t, seeds in stage.runner.calls)
    assert {tool for tool, t, _ in stage.runner.calls if t == ["amazonalexa.com"]} \
        == {"amass", "subfinder"}


def test_discovered_hosts_under_seed_still_scope_filtered(amazon, registry, tmp_path):
    outputs = {"subfinder": [
        "amazonalexa.com",               # drop: apex is not an in-scope target
        "skills.amazonalexa.com",        # keep: *.amazonalexa.com
        "aws.amazonalexa.com",           # drop: label_contains:aws
        "beta.api.amazonalexa.com",      # drop: label_equals:beta
        "alexa.example.net",             # drop: unrelated host a dataset returned
    ], "amass": []}
    stage, store, audit = _stage(amazon, registry, tmp_path, outputs)
    res = stage.run()
    kept = {a["key"] for a in store.list_assets(kind="subdomain")}
    assert kept == {"skills.amazonalexa.com"}
    assert res.out_of_scope_dropped == 4
    rejects = {r["host"]: r for r in audit.read_all()
               if r.get("event") == "scope_decision" and not r.get("allowed")}
    assert rejects["amazonalexa.com"]["reason"] == "not in scope"
    assert rejects["aws.amazonalexa.com"]["matched_rule"] == "label_contains:aws"
    assert rejects["beta.api.amazonalexa.com"]["matched_rule"] == "label_equals:beta"
    assert "alexa.example.net" in rejects


def test_dry_run_plans_without_storing(amazon, registry, tmp_path):
    stage, store, _ = _stage(amazon, registry, tmp_path, {"subfinder": ["x.amazon.com"]})
    res = stage.run(dry_run=True)
    assert res.dry_run and res.planned_commands
    assert store.counts()["assets"] == {}        # nothing written
    assert "amazonalexa.com" in res.roots_enumerated
    assert any(c.endswith("amazonalexa.com") for c in res.planned_commands)


def test_partial_output_of_timed_out_tool_is_ingested(amazon, registry, tmp_path):
    class TimingOutRunner(FakeRunner):
        def run(self, *a, **kw):
            res = super().run(*a, **kw)
            for iv in res.invocations:
                iv.exit_code, iv.timed_out = -1, True
            return res

    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement=amazon.engagement.name)
    runner = TimingOutRunner(amazon, {"amass": ["www.amazon.com", "aws.amazon.com"],
                                      "subfinder": []})
    stage = PassiveReconStage(amazon, registry, store, audit, runner, tmp_path / "o")
    res = stage.run()
    assert res.by_tool["amass"] == 2
    # partial results are still scope-filtered: aws.amazon.com dropped
    assert {a["key"] for a in store.list_assets(kind="subdomain")} == {"www.amazon.com"}


# --------------------------------------------------------------------------- #
# --only: narrow the passive tools (e.g. subfinder without amass)
# --------------------------------------------------------------------------- #
def test_only_runs_just_the_named_tool(amazon, registry, tmp_path):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement=amazon.engagement.name)
    runner = FakeRunner(amazon, {"subfinder": ["www.amazon.com"], "amass": ["x.amazon.com"]})
    stage = PassiveReconStage(amazon, registry, store, audit, runner, tmp_path / "o",
                              only=["subfinder"])
    res = stage.run()
    assert {tool for tool, _, _ in runner.calls} == {"subfinder"}
    assert res.by_tool == {"subfinder": 1}
    assert {a["key"] for a in store.list_assets(kind="subdomain")} == {"www.amazon.com"}


@pytest.mark.parametrize("only", [["httpx"], ["nuclei"], ["bogus"], [""]])
def test_only_cannot_widen_past_passive_allowlist(amazon, registry, tmp_path, only):
    with pytest.raises(ValueError):
        PassiveReconStage(amazon, registry, Store(":memory:"),
                          AuditLog(tmp_path / "a.jsonl", engagement="x"),
                          FakeRunner(amazon, {}), tmp_path / "o", only=only)


# --------------------------------------------------------------------------- #
# incremental persistence + interrupt handling (handoff 5.2)
# --------------------------------------------------------------------------- #
class PerRootRunner(FakeRunner):
    """Emits www.<root> for each root; can blow up on the Nth real call and
    records what was already in the DB when each call started."""
    def __init__(self, scope, store, fail_on_call=None, exc=KeyboardInterrupt):
        super().__init__(scope, {})
        self.store, self.fail_on_call, self.exc = store, fail_on_call, exc
        self.stored_at_call = []

    def run(self, tool, targets, output_dir, *, dry_run=False, seeds=False, **kw):
        self.stored_at_call.append(
            {a["key"] for a in self.store.list_assets(kind="subdomain", limit=1000)})
        if self.fail_on_call is not None and len(self.calls) + 1 == self.fail_on_call:
            self.calls.append((tool, list(targets), seeds))
            raise self.exc("boom") if self.exc is not KeyboardInterrupt else self.exc()
        self.outputs = {tool: [f"www.{t}" for t in targets]}
        return super().run(tool, targets, output_dir, dry_run=dry_run, seeds=seeds, **kw)


def _per_root_stage(amazon, registry, tmp_path, **kw):
    store = Store(":memory:")
    audit = AuditLog(tmp_path / "audit.jsonl", engagement=amazon.engagement.name)
    runner = PerRootRunner(amazon, store, **kw)
    stage = PassiveReconStage(amazon, registry, store, audit, runner, tmp_path / "o",
                              only=["subfinder"])
    return stage, store, audit, runner


def test_results_are_stored_per_root_not_at_the_end(amazon, registry, tmp_path):
    stage, store, _, runner = _per_root_stage(amazon, registry, tmp_path)
    roots = stage.enumeration_roots()
    res = stage.run()
    # by the time root #3 starts, roots #1 and #2 are already in the DB
    assert runner.stored_at_call[2] == {f"www.{r}" for r in roots[:2]}
    assert store.get_run(res.run_id).status == "completed"
    assert not res.interrupted and res.in_scope_kept == len(roots)


def test_interrupt_mid_run_preserves_stored_assets(amazon, registry, tmp_path):
    stage, store, audit, _ = _per_root_stage(amazon, registry, tmp_path, fail_on_call=4)
    roots = stage.enumeration_roots()
    res = stage.run()                       # Ctrl-C is handled, not raised
    assert res.interrupted and res.interrupt_reason == "KeyboardInterrupt"
    done = roots[:3]
    assert res.completed_roots == {"subfinder": done}
    assert {a["key"] for a in store.list_assets(kind="subdomain")} == {f"www.{r}" for r in done}
    run = store.get_run(res.run_id)
    assert run.status == "interrupted" and run.ended_at
    note = json.loads(run.note)
    assert note["completed_roots"] == {"subfinder": done}
    assert note["reason"] == "KeyboardInterrupt"
    assert any(r["event"] == "run_interrupted" for r in audit.read_all())
    assert "INTERRUPTED" in res.summary_text()


def test_unhandled_error_finalizes_interrupted_and_reraises(amazon, registry, tmp_path):
    stage, store, _, _ = _per_root_stage(amazon, registry, tmp_path, fail_on_call=2,
                                         exc=RuntimeError)
    roots = stage.enumeration_roots()
    with pytest.raises(RuntimeError):
        stage.run()
    run = store.last_run("passive_recon")
    assert run.status == "interrupted" and "RuntimeError: boom" in run.note
    assert {a["key"] for a in store.list_assets(kind="subdomain")} == {f"www.{roots[0]}"}


def test_ingest_output_recovers_files_from_disk(amazon, registry, tmp_path):
    stage, store, audit = _stage(amazon, registry, tmp_path, {})
    f = tmp_path / "amass-amazon.cn.out"
    f.write_text("amazon.cn (FQDN) --> ns_record --> ns1.amzndns-cn.com (FQDN)\n"
                 "https-sedi.amazon.cn (FQDN) --> cname_record --> x.amazon.cn (FQDN)\n"
                 "aws.amazon.cn (FQDN) --> cname_record --> y.amazon.cn (FQDN)\n")
    rid = store.start_run("passive_recon", tool="amass")
    kept, dropped = stage.ingest_output(f, "amass", rid)
    assert {a["key"] for a in store.list_assets(kind="subdomain")} == \
        {"amazon.cn", "https-sedi.amazon.cn", "x.amazon.cn", "y.amazon.cn"}
    assert (kept, dropped) == (4, 2)      # ns1.amzndns-cn.com + aws.amazon.cn dropped
