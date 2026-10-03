"""Prompt-to-plan interpreter + plan builder. Deterministic, no execution, no network."""

import pytest

from reconpilot.store import Store
from reconpilot.web import planner
from reconpilot.web.planner import KeywordInterpreter, plan
from reconpilot.web.service import UnknownEngagement


# --------------------------------------------------------------------------- #
# interpreter (engagement-independent)
# --------------------------------------------------------------------------- #
I = KeywordInterpreter()


@pytest.mark.parametrize("prompt,stage", [
    ("enumerate subdomains", "passive_recon"),
    ("run passive recon", "passive_recon"),
    ("find subdomains with subfinder", "passive_recon"),
    ("resolve DNS for everything", "dns_resolve"),
    ("run dnsx resolution", "dns_resolve"),
    ("probe live hosts", "liveness"),
    ("which hosts are alive over http", "liveness"),
    ("httpx probe", "liveness"),
])
def test_interpret_stage_detection(prompt, stage):
    it = I.interpret(prompt)
    assert not it.needs_clarification and it.stage == stage


def test_interpret_single_host_implies_liveness():
    it = I.interpret("probe www.amazon.com")
    assert it.stage == "liveness" and it.params == {"host": "www.amazon.com"}


def test_interpret_host_lowercased():
    assert I.interpret("check WWW.Amazon.COM").params["host"] == "www.amazon.com"


@pytest.mark.parametrize("prompt,limit", [
    ("probe live hosts limit 100", 100),
    ("liveness first 50", 50),
    ("resolve dns top 10", 10),
    ("probe 25 hosts", 25),
    ("liveness one host", 1),
])
def test_interpret_limit(prompt, limit):
    assert I.interpret(prompt).params.get("limit") == limit


def test_limit_ignored_for_passive():
    assert "limit" not in I.interpret("enumerate subdomains limit 100").params


@pytest.mark.parametrize("prompt", ["", "   ", "do the thing", "make it fast"])
def test_interpret_unknown_asks_to_clarify(prompt):
    it = I.interpret(prompt)
    assert it.needs_clarification and it.stage is None and it.message


def test_interpret_ambiguous_multiple_stages():
    it = I.interpret("resolve dns and probe live hosts")
    assert it.needs_clarification and "mbiguous" in it.message


def test_interpret_host_with_conflicting_stage_clarifies():
    it = I.interpret("resolve dns for www.amazon.com")
    assert it.needs_clarification and "liveness" in it.message


# --------------------------------------------------------------------------- #
# plan() builder (needs an engagement + store)
# --------------------------------------------------------------------------- #
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
    store.upsert_asset("subdomain", "www.demo.com", rid,
                       attrs={"resolves": True, "live": True, "probed_at_run": rid})
    store.upsert_asset("subdomain", "api.demo.com", rid, attrs={"resolves": True})  # unprobed
    store.upsert_asset("subdomain", "dead.demo.com", rid, attrs={"resolves": False})
    store.close()
    return d


def test_plan_liveness_preview(engdir):
    p = plan(engdir, "demo", "probe live hosts")
    assert p.ok and p.stage == "liveness"
    v = p.preview
    assert v["sends_traffic"] is True
    assert v["tools"] == ["httpx"]
    assert v["hosts"] == 1                       # only api.demo.com resolved & unprobed
    assert "rps/host" in v["rate_cap"] and "safe mode" in v["rate_cap"]


def test_plan_dns_preview_no_traffic(engdir):
    p = plan(engdir, "demo", "resolve dns")
    assert p.ok and p.stage == "dns_resolve"
    assert p.preview["sends_traffic"] is False
    assert p.preview["tools"] == ["dnsx"]
    assert p.preview["hosts"] == 3              # all subdomains
    assert p.preview["rate_cap"] == "n/a (no traffic to target)"


def test_plan_passive_preview(engdir):
    p = plan(engdir, "demo", "enumerate subdomains")
    assert p.ok and p.stage == "passive_recon"
    assert set(p.preview["tools"]) == {"subfinder", "amass"}
    assert p.preview["sends_traffic"] is False
    assert p.preview["hosts"] == 1             # one registrable seed: demo.com


def test_plan_host_in_scope(engdir):
    p = plan(engdir, "demo", "probe app.demo.com")
    assert p.ok and p.params["host"] == "app.demo.com"
    assert p.preview["hosts"] == 1 and p.preview["sends_traffic"] is True


def test_plan_host_out_of_scope_is_blocked(engdir):
    p = plan(engdir, "demo", "probe www.google.com")
    assert not p.ok and not p.needs_clarification
    assert "out of scope" in p.message and "google.com" in p.message


def test_plan_limit_caps_host_estimate(engdir):
    p = plan(engdir, "demo", "resolve dns limit 2")
    assert p.ok and p.params["limit"] == 2 and p.preview["hosts"] == 2


def test_plan_clarify_passthrough(engdir):
    p = plan(engdir, "demo", "do the thing")
    assert not p.ok and p.needs_clarification and p.stage is None


def test_plan_unknown_engagement_raises(engdir):
    with pytest.raises(UnknownEngagement):
        plan(engdir, "nope", "probe live hosts")


def test_plan_unknown_engagement_blocks_traversal(engdir):
    with pytest.raises(UnknownEngagement):
        plan(engdir, "../../etc/passwd", "probe live hosts")
