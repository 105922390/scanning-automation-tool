"""Item 3: http: block parsing, UA validity, and the drop_on_redirect_to filter."""

import dataclasses
from pathlib import Path

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.config import Http, load_tools
from reconpilot.engagement import load_engagement
from reconpilot.errors import RunnerError
from reconpilot.http_policy import filter_on_redirect, final_host
from reconpilot.runner import GuardedRunner

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_ENGAGEMENTS = REPO_ROOT / "engagements"
REPO_TOOLS = REPO_ROOT / "tools.yaml"


# --------------------------------------------------------------------------- #
# config parsing + UA validity
# --------------------------------------------------------------------------- #
def test_amazon_vrp_http_block_parsed():
    http = load_engagement("amazon-vrp", REPO_ENGAGEMENTS).http
    assert http.user_agent == "amazonvrpresearcher_floopy"
    assert http.require_user_agent is True
    assert http.no_third_party_oob is True
    assert http.drop_on_redirect_to == ("*.aws.amazon.com", "midway-auth.amazon.com",
                                        "federate.amazon.com")
    assert http.user_agent_is_valid()


@pytest.mark.parametrize("ua,valid", [
    ("amazonvrpresearcher_floopy", True),
    ("", False),
    ("   ", False),
    ("amazonvrpresearcher_YOUR_H1_USERNAME", False),  # placeholder marker
    ("YOUR_H1_USERNAME", False),
])
def test_user_agent_validity(ua, valid):
    assert Http(user_agent=ua).user_agent_is_valid() is valid


def test_missing_http_block_defaults_are_inert():
    # an engagement with no http: block -> empty policy, nothing enforced
    from reconpilot.config import Scope
    s = Scope.__init__  # noqa: F841  (just asserting defaults below)
    h = Http()
    assert h.user_agent == "" and not h.require_user_agent and not h.no_third_party_oob
    assert h.drop_on_redirect_to == ()


# --------------------------------------------------------------------------- #
# drop_on_redirect_to
# --------------------------------------------------------------------------- #
def test_final_host_extraction_prefers_final_url():
    assert final_host({"url": "https://a.amazon.com", "final_url": "https://x.aws.amazon.com/y"}) \
        == "x.aws.amazon.com"
    assert final_host({"url": "https://a.amazon.com:443/p"}) == "a.amazon.com"
    assert final_host({}) == ""


def test_filter_drops_redirects_to_patterns():
    patterns = ("*.aws.amazon.com", "midway-auth.amazon.com")
    records = [
        {"input": "a.amazon.com", "final_url": "https://a.amazon.com/ok"},
        {"input": "b.amazon.com", "final_url": "https://console.aws.amazon.com/x"},
        {"input": "c.amazon.com", "final_url": "https://midway-auth.amazon.com/login"},
        {"input": "d.amazon.com", "url": "https://d.amazon.com"},
    ]
    kept, dropped = filter_on_redirect(records, patterns)
    assert [r["input"] for r in kept] == ["a.amazon.com", "d.amazon.com"]
    assert [r["input"] for r in dropped] == ["b.amazon.com", "c.amazon.com"]
    assert dropped[0]["_dropped_by"] == "drop_on_redirect_to:*.aws.amazon.com"
    assert dropped[1]["_dropped_by"] == "drop_on_redirect_to:midway-auth.amazon.com"


def test_filter_no_patterns_keeps_everything():
    recs = [{"url": "https://console.aws.amazon.com"}]
    kept, dropped = filter_on_redirect(recs, ())
    assert kept == recs and dropped == []


def test_apex_not_dropped_by_wildcard():
    # *.aws.amazon.com must NOT match the apex aws.amazon.com (wildcard semantics)
    kept, dropped = filter_on_redirect(
        [{"url": "https://aws.amazon.com"}], ("*.aws.amazon.com",))
    assert len(kept) == 1 and not dropped


# --------------------------------------------------------------------------- #
# GUARDRAIL CONFIRMATIONS against the real engagement + real tools.yaml
# --------------------------------------------------------------------------- #
def _real_runner(scope, tmp_path):
    # which() makes every tool "available" so we exercise policy, not detection.
    return GuardedRunner(scope, load_tools(REPO_TOOLS),
                         AuditLog(tmp_path / "a.jsonl"), which=lambda n: "/usr/bin/true")


def test_amazon_vrp_nuclei_argv_disables_interactsh_and_sets_ua(tmp_path):
    scope = load_engagement("amazon-vrp", REPO_ENGAGEMENTS)
    res = _real_runner(scope, tmp_path).run(
        "nuclei", ["www.amazon.com"], tmp_path / "o", dry_run=True)
    cmd = res.invocations[0].command
    assert "-no-interactsh" in cmd                                   # third-party OOB off
    assert "User-Agent: amazonvrpresearcher_floopy" in cmd          # UA present


def test_amazon_vrp_dalfox_argv_has_no_blind_server_and_sets_ua(tmp_path):
    scope = load_engagement("amazon-vrp", REPO_ENGAGEMENTS)
    res = _real_runner(scope, tmp_path).run(
        "dalfox", ["https://www.amazon.com/s?q=1"], tmp_path / "o", dry_run=True)
    cmd = res.invocations[0].command
    joined = " ".join(cmd).lower()
    # no public blind-XSS callback configured
    assert "-b" not in cmd and "--blind" not in cmd and "blind" not in joined
    assert "User-Agent: amazonvrpresearcher_floopy" in cmd


@pytest.mark.parametrize("bad_ua", ["", "   ", "amazonvrpresearcher_YOUR_H1_USERNAME",
                                    "YOUR_H1_USERNAME"])
def test_amazon_vrp_refuses_active_tool_when_ua_missing(tmp_path, bad_ua):
    """The ban-protection guardrail: with require_user_agent set and the UA
    blank/placeholder, an active tool is REFUSED — never run without the header."""
    scope = load_engagement("amazon-vrp", REPO_ENGAGEMENTS)
    scope = dataclasses.replace(scope, http=dataclasses.replace(scope.http, user_agent=bad_ua))
    runner = _real_runner(scope, tmp_path)
    with pytest.raises(RunnerError) as e:
        runner.run("httpx", ["www.amazon.com"], tmp_path / "o")   # real run
    assert "require_user_agent" in str(e.value)
    # and it was recorded, not silent
    assert any(r["event"] == "tool_refused" for r in runner.audit.read_all())


def test_amazon_vrp_passive_tool_unaffected_by_missing_ua(tmp_path):
    # refusal is scoped to UA-capable active tools; a passive tool still runs
    scope = load_engagement("amazon-vrp", REPO_ENGAGEMENTS)
    scope = dataclasses.replace(scope, http=dataclasses.replace(scope.http, user_agent=""))
    res = _real_runner(scope, tmp_path).run(
        "subfinder", ["amazon.com"], tmp_path / "o", dry_run=True)
    assert not res.skipped_reason and res.invocations


# --------------------------------------------------------------------------- #
# redirect-target extraction + filter on the TARGET host (no-follow model)
# --------------------------------------------------------------------------- #
def test_redirect_target_host_reads_location_only():
    from reconpilot.http_policy import redirect_target_host
    # url/input are the PROBED host, never the target
    assert redirect_target_host(
        {"input": "a.acme.com", "url": "https://a.acme.com",
         "location": "https://x.aws.amazon.com/y"}) == "x.aws.amazon.com"
    assert redirect_target_host({"url": "https://a.acme.com"}) == ""   # no redirect
    assert redirect_target_host(
        {"location": "/relative/path"}) == ""                         # relative = same host


def test_filter_on_redirect_targets_the_location_not_the_probed_url():
    from reconpilot.http_policy import redirect_target_host
    recs = [
        {"input": "a.acme.com", "url": "https://a.acme.com", "location": "https://y.aws.amazon.com/"},
        {"input": "b.acme.com", "url": "https://b.aws.amazon.com"},   # probed url only, no Location
    ]
    kept, dropped = filter_on_redirect(recs, ("*.aws.amazon.com",),
                                       host_of=redirect_target_host)
    # only the Location-bearing record is dropped; the probed-url one is kept
    assert [r["input"] for r in dropped] == ["a.acme.com"]
    assert [r["input"] for r in kept] == ["b.acme.com"]
