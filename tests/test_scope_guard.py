"""The safety-critical tests. If these pass, nothing out-of-scope gets scanned."""

import dataclasses
from pathlib import Path

import pytest

from reconpilot.engagement import load_engagement
from reconpilot.errors import ScopeViolation
from reconpilot.scope_guard import ScopeGuard, normalize_target

REPO_ENGAGEMENTS = Path(__file__).resolve().parent.parent / "engagements"


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("ACME.com", "acme.com"),
    ("acme.com.", "acme.com"),
    ("https://foo.acme.com/path?x=1", "foo.acme.com"),
    ("http://user:pw@foo.acme.com:8443/a", "foo.acme.com"),
    ("foo.acme.com:8080", "foo.acme.com"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("  bar.acme.com  ", "bar.acme.com"),
    ("", ""),
    (None, ""),
    # trailing dot must be stripped AFTER the port is removed (fix #1)
    ("acme.com.:443", "acme.com"),
    ("https://foo.acme.com./path", "foo.acme.com"),
    ("foo.acme.com.", "foo.acme.com"),
    # leading dot is NOT stripped — the guard rejects it as an empty label
    (".acme.com", ".acme.com"),
])
def test_normalize(raw, expected):
    assert normalize_target(raw) == expected


# --------------------------------------------------------------------------- #
# domain scoping
# --------------------------------------------------------------------------- #
def test_apex_explicitly_in_scope(scope):
    assert ScopeGuard(scope).is_allowed("acme.com")


def test_wildcard_matches_subdomain_any_depth(scope):
    g = ScopeGuard(scope)
    assert g.is_allowed("foo.acme.com")
    assert g.is_allowed("a.b.c.acme.com")


def test_wildcard_only_domain_does_not_cover_apex(scope):
    # acme-api.com has only a wildcard entry, no apex entry → apex rejected.
    g = ScopeGuard(scope)
    assert g.is_allowed("x.acme-api.com")
    assert not g.is_allowed("acme-api.com")


def test_out_of_scope_sub_beats_in_scope_wildcard(scope):
    g = ScopeGuard(scope)
    # all three match in-scope *.acme.com, but out_of_scope wins
    assert not g.is_allowed("x.internal.acme.com")   # out-of-scope wildcard
    assert not g.is_allowed("legacy.acme.com")       # out-of-scope exact
    assert not g.is_allowed("blog.acme.com")         # out-of-scope exact


def test_lookalikes_rejected(scope):
    g = ScopeGuard(scope)
    assert not g.is_allowed("notacme.com")
    assert not g.is_allowed("acme.com.evil.com")
    assert not g.is_allowed("xacme.com")


def test_unrelated_domain_rejected(scope):
    assert not ScopeGuard(scope).is_allowed("example.org")


# --------------------------------------------------------------------------- #
# label-based out_of_scope rules (item 2)
# --------------------------------------------------------------------------- #
@pytest.fixture
def label_scope(scope):
    return dataclasses.replace(
        scope,
        in_scope_domains=("amazon.com", "*.amazon.com"),
        out_of_scope_domains=(),
        out_of_scope_host_label_contains=("aws",),
        out_of_scope_host_label_equals=("test", "qa", "integ", "preprod", "gamma", "beta"))


def test_label_contains_rejects(label_scope):
    g = ScopeGuard(label_scope)
    d = g.check("aws-internal.amazon.com")
    assert not d.allowed and d.matched_rule == "label_contains:aws"
    # substring inside a label, not just a whole label
    assert not g.is_allowed("my-aws-thing.amazon.com")


def test_label_equals_rejects_whole_label_only(label_scope):
    g = ScopeGuard(label_scope)
    assert g.check("qa.amazon.com").matched_rule == "label_equals:qa"
    assert g.check("test.amazon.com").matched_rule == "label_equals:test"
    # "latest" contains "test" as a substring but is not a whole-label match
    assert g.is_allowed("latest.amazon.com")


def test_label_rules_do_not_over_reject(label_scope):
    g = ScopeGuard(label_scope)
    assert g.is_allowed("latest.amazon.com")
    assert g.is_allowed("developer.amazon.com")


def test_out_of_scope_label_beats_in_scope_wildcard(label_scope):
    # aws.amazon.com matches in_scope *.amazon.com but the label rule wins
    g = ScopeGuard(label_scope)
    d = g.check("aws.amazon.com")
    assert not d.allowed and d.matched_rule == "label_contains:aws"


def test_label_matching_is_case_insensitive(label_scope):
    assert not ScopeGuard(label_scope).is_allowed("AWS-Internal.AMAZON.com")


def test_amazon_vrp_integration():
    # the real shipped engagement file, through config parsing + the guard
    g = ScopeGuard(load_engagement("amazon-vrp", REPO_ENGAGEMENTS))
    for host in ["aws-internal.amazon.com", "qa.amazon.com", "test.amazon.com",
                 "beta.amazon.co.uk", "preprod.amazon.de"]:
        assert not g.is_allowed(host), host
    for host in ["latest.amazon.com", "developer.amazon.com", "www.amazon.co.jp"]:
        assert g.is_allowed(host), host


def test_trailing_dot_with_port_still_matches(scope):
    # fix #1: "acme.com.:443" must normalize to the in-scope apex, not false-reject
    g = ScopeGuard(scope)
    assert g.is_allowed("acme.com.:443")
    assert g.is_allowed("https://foo.acme.com./login")
    # and out-of-scope precedence survives the trailing dot too
    assert not g.is_allowed("legacy.acme.com.:443")


def test_empty_label_hosts_rejected(scope):
    # fix #2: these pass a naive endswith(".acme.com") but are malformed → reject
    g = ScopeGuard(scope)
    d1 = g.check(".acme.com")
    d2 = g.check("sub..acme.com")
    assert not d1.allowed and "empty label" in d1.reason
    assert not d2.allowed and "empty label" in d2.reason


# --------------------------------------------------------------------------- #
# IP / CIDR scoping
# --------------------------------------------------------------------------- #
def test_ip_in_scope_cidr_allowed(scope):
    assert ScopeGuard(scope).is_allowed("203.0.113.5")


def test_ip_in_out_of_scope_cidr_rejected(scope):
    # 203.0.113.200 is inside in-scope /24 but also inside out-of-scope /25
    assert not ScopeGuard(scope).is_allowed("203.0.113.200")


def test_ip_outside_all_cidrs_rejected(scope):
    assert not ScopeGuard(scope).is_allowed("198.51.100.9")


def test_domain_rules_never_apply_to_literal_ip(scope):
    # even an in-scope-looking string that is an IP uses only CIDR rules
    assert not ScopeGuard(scope).is_allowed("10.0.0.1")


# --------------------------------------------------------------------------- #
# invalid input
# --------------------------------------------------------------------------- #
def test_unparseable_rejected(scope):
    d = ScopeGuard(scope).check("   ")
    assert not d.allowed and d.host == ""


# --------------------------------------------------------------------------- #
# auditing + require + filter
# --------------------------------------------------------------------------- #
def test_every_decision_is_audited(scope):
    log = []
    g = ScopeGuard(scope, audit=log.append)
    for t in ["acme.com", "evil.com", "foo.acme.com", "legacy.acme.com"]:
        g.check(t)
    assert len(log) == 4
    assert [d.allowed for d in log] == [True, False, True, False]


def test_require_raises_on_reject(scope):
    g = ScopeGuard(scope)
    g.require("foo.acme.com")  # no raise
    with pytest.raises(ScopeViolation):
        g.require("evil.com")


def test_filter_partitions_and_audits(scope):
    log = []
    g = ScopeGuard(scope, audit=log.append)
    allowed, rejected = g.filter(
        ["acme.com", "evil.com", "x.internal.acme.com", "x.acme-api.com"])
    assert sorted(d.host for d in allowed) == ["acme.com", "x.acme-api.com"]
    assert sorted(d.host for d in rejected) == ["evil.com", "x.internal.acme.com"]
    assert len(log) == 4
