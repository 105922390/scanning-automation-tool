"""Enumeration seeds: the search keys handed to PASSIVE subdomain tools.

A seed is not a target. ``subfinder -d amazonalexa.com`` asks third-party
datasets "what subdomains of amazonalexa.com do you know about?" — it sends no
traffic to amazonalexa.com. So a ``*.amazonalexa.com`` wildcard must contribute
``amazonalexa.com`` as a seed even though the apex itself is not an in-scope
target. Every host a passive tool DISCOVERS still goes through ScopeGuard.check
before it is stored; seeds never bypass that.

Derivation is literal, never inferred: ``*.X`` yields exactly X, and a plain
entry yields itself. No public-suffix / registrable-domain reduction — the
Public Suffix List is incomplete (``com.be`` is not in it, so a reduction turns
``amazon.com.be`` into ``com.be``), and the wildcard already names the root.

Seeds get their own gate (``check_seed``) instead of the target gate:
  - the seed must be DECLARED: equal to a plain in_scope entry, or to the base X
    of an in_scope ``*.X`` entry. Anything else is a derivation error.
  - it must not be a known public suffix (``*.co.uk`` in scope would otherwise
    enumerate an entire TLD)
  - an out_of_scope rule that would exclude EVERY subdomain of the seed (a
    covering wildcard like ``*.dev``, or a host-label rule matching one of the
    seed's own labels) rejects it. An exact out_of_scope apex does not: the apex
    is excluded as a target, its subdomains are not.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from .config import Scope
from .scope_guard import ScopeDecision, _domain_matches, _is_ip, normalize_target


@lru_cache(maxsize=1)
def _psl():
    # Bundled snapshot of the Public Suffix List — no network access, ever.
    from publicsuffixlist import PublicSuffixList
    return PublicSuffixList()


def is_public_suffix(host: str) -> bool:
    """True if ``host`` is itself a known public suffix (``com``, ``co.uk``).
    Used only as a refusal check — never to derive or shorten a seed."""
    h = normalize_target(host)
    return bool(h) and _psl().privatesuffix(h) is None


def _entry_base(entry: str) -> str:
    d = entry.strip().lower().rstrip(".")
    return d[2:] if d.startswith("*.") else d


def declared_seed_rule(scope: Scope, seed: str) -> Optional[str]:
    """The in_scope entry that declares ``seed`` (a plain entry equal to it, or a
    ``*.seed`` wildcard), or None. Wildcards are preferred — they are the rule
    that makes a seed necessary."""
    host = normalize_target(seed)
    if not host:
        return None
    entries = sorted(scope.in_scope_domains, key=lambda e: not e.strip().startswith("*."))
    for entry in entries:
        if _entry_base(entry) == host:
            return entry
    return None


def enumeration_seeds(scope: Scope) -> list[str]:
    """Seeds for an engagement: X for every ``*.X`` entry, plus each plain entry
    not already under another seed (``api.amazonalexa.com`` is covered by
    enumerating ``amazonalexa.com``). Deduped, sorted. No suffix reduction."""
    bases = {b for b in (_entry_base(e) for e in scope.in_scope_domains) if b}
    return sorted(b for b in bases
                  if not any(b != o and b.endswith("." + o) for o in bases))


def check_seed(scope: Scope, seed: str) -> ScopeDecision:
    """Decide whether ``seed`` may be used as a passive enumeration key."""
    host = normalize_target(seed)
    if not host or host.startswith(".") or ".." in host:
        return ScopeDecision(seed, host, False, "invalid seed", "")
    if _is_ip(host) is not None:
        return ScopeDecision(seed, host, False, "IP is not an enumeration seed", "")

    rule = declared_seed_rule(scope, host)
    if rule is None:
        return ScopeDecision(seed, host, False,
                             "seed derivation error: not an in_scope entry or *.X base", "")
    if is_public_suffix(host):
        return ScopeDecision(seed, host, False,
                             "public suffix: refusing to enumerate a TLD", rule)

    # out_of_scope rules that would exclude every subdomain of the seed
    for pat in scope.out_of_scope_domains:
        if pat.strip().startswith("*.") and _domain_matches(host, pat):
            return ScopeDecision(seed, host, False,
                                 "seed covered by out_of_scope wildcard", pat)
    labels = host.split(".")
    for needle in scope.out_of_scope_host_label_contains:
        if any(needle in lbl for lbl in labels):
            return ScopeDecision(seed, host, False, "seed matches out_of_scope host label "
                                 "(contains)", f"label_contains:{needle}")
    for needle in scope.out_of_scope_host_label_equals:
        if any(lbl == needle for lbl in labels):
            return ScopeDecision(seed, host, False, "seed matches out_of_scope host label "
                                 "(equals)", f"label_equals:{needle}")

    return ScopeDecision(seed, host, True,
                         "enumeration seed declared by in_scope entry", f"seed:{rule}")
