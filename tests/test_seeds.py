"""Enumeration seeds: literal derivation from in_scope + the seed gate. No network."""

import dataclasses

import pytest

from reconpilot.seeds import check_seed, enumeration_seeds, is_public_suffix


def test_enumeration_seeds_from_scope(scope):
    # conftest scope: acme.com, *.acme.com, *.acme-api.com
    assert enumeration_seeds(scope) == ["acme-api.com", "acme.com"]


def test_wildcard_base_is_a_valid_seed_even_though_apex_is_not_a_target(scope):
    d = check_seed(scope, "acme-api.com")          # only *.acme-api.com is in scope
    assert d.allowed and d.matched_rule == "seed:*.acme-api.com"


# --------------------------------------------------------------------------- #
# regression: com.be is NOT in the Public Suffix List, so a registrable-domain
# reduction collapsed amazon.com.be -> com.be. The wildcard names the root.
# --------------------------------------------------------------------------- #
def test_wildcard_base_not_reduced_when_suffix_missing_from_psl(scope):
    assert not is_public_suffix("com.be")          # precondition: PSL lacks com.be
    s = dataclasses.replace(scope, in_scope_domains=("*.amazon.com.be",))
    assert enumeration_seeds(s) == ["amazon.com.be"]
    assert check_seed(s, "amazon.com.be").allowed
    d = check_seed(s, "com.be")
    assert not d.allowed and "derivation error" in d.reason


@pytest.mark.parametrize("entry,seed", [
    ("*.amazon.com.au", "amazon.com.au"),
    ("*.amazon.co.uk", "amazon.co.uk"),
    ("*.foo.acme.com", "foo.acme.com"),            # deeper wildcard: no shortening
    ("api.widgets.io", "api.widgets.io"),          # plain entry is its own seed
])
def test_seed_is_exactly_the_declared_base(scope, entry, seed):
    s = dataclasses.replace(scope, in_scope_domains=(entry,))
    assert enumeration_seeds(s) == [seed]
    assert check_seed(s, seed).allowed


def test_plain_entry_under_a_wildcard_seed_is_not_a_separate_seed(scope):
    s = dataclasses.replace(scope, in_scope_domains=("api.alexa.com", "*.alexa.com"))
    assert enumeration_seeds(s) == ["alexa.com"]


@pytest.mark.parametrize("seed,reason_part", [
    ("evil.com", "derivation error"),
    ("com", "derivation error"),
    ("foo.acme.com", "derivation error"),         # under a seed, but not declared
    ("203.0.113.5", "IP"),
    ("", "invalid"),
])
def test_bad_seeds_rejected(scope, seed, reason_part):
    d = check_seed(scope, seed)
    assert not d.allowed and reason_part in d.reason


def test_public_suffix_wildcard_refused(scope):
    s = dataclasses.replace(scope, in_scope_domains=("*.co.uk",))
    d = check_seed(s, "co.uk")
    assert not d.allowed and "public suffix" in d.reason


def test_covering_out_of_scope_wildcard_rejects_seed(scope):
    s = dataclasses.replace(scope, in_scope_domains=("*.acme.dev",),
                            out_of_scope_domains=("*.dev",))
    d = check_seed(s, "acme.dev")
    assert not d.allowed and d.matched_rule == "*.dev"


def test_out_of_scope_label_on_seed_rejects_it(scope):
    s = dataclasses.replace(scope, in_scope_domains=("*.awsthing.com",),
                            out_of_scope_host_label_contains=("aws",))
    d = check_seed(s, "awsthing.com")
    assert not d.allowed and d.matched_rule == "label_contains:aws"


def test_exact_out_of_scope_apex_does_not_block_seed(scope):
    # apex excluded as a TARGET, but its subdomains are in scope -> still a seed
    s = dataclasses.replace(scope, in_scope_domains=("*.acme.com",),
                            out_of_scope_domains=("acme.com",))
    assert check_seed(s, "acme.com").allowed
