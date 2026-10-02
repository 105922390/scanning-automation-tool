"""The scope gate. No tool runs against a host until it passes through here.

Pure and deterministic (no network): a target string in, a ScopeDecision out.
Out-of-scope always beats in-scope. Every decision is handed to the audit sink.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .config import Scope
from .errors import ScopeViolation


@dataclass(frozen=True)
class ScopeDecision:
    target: str          # the raw input, as given
    host: str            # normalized host (or "" if it could not be parsed)
    allowed: bool
    reason: str          # human-readable justification, logged
    matched_rule: str    # the rule that decided it (e.g. "*.acme.com", "cidr:203.0.113.0/24")


def normalize_target(raw: str) -> str:
    """Reduce any target form (URL, host:port, FQDN., UPPER) to a bare host.

    Returns "" for anything that cannot be parsed to a host.
    """
    if raw is None:
        return ""
    s = str(raw).strip().lower()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    # drop path / query / fragment
    for sep in ("/", "?", "#"):
        s = s.split(sep, 1)[0]
    # drop userinfo
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if not s:
        return ""
    # bracketed IPv6 literal, optionally with :port
    if s.startswith("["):
        host = s[1:].split("]", 1)[0]
    else:
        # strip a single trailing :port (leave bare IPv6, which has many colons)
        if s.count(":") == 1:
            left, right = s.rsplit(":", 1)
            if right.isdigit():
                s = left
        host = s
    # Trailing-dot stripping happens LAST — after port/bracket handling — so a
    # FQDN like "acme.com.:443" or "foo.acme.com./path" still normalizes to a
    # dotless host that _domain_matches can match. Leading dots are intentionally
    # NOT stripped; an empty leading label is rejected as invalid by the guard.
    return host.rstrip(".")


def _is_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _domain_matches(host: str, pattern: str) -> bool:
    """Exact match, or wildcard. ``*.acme.com`` matches any subdomain at any
    depth but NOT the apex ``acme.com``."""
    pattern = pattern.strip().lower().rstrip(".")
    if pattern.startswith("*."):
        apex = pattern[2:]          # "acme.com"
        suffix = pattern[1:]        # ".acme.com"
        return host.endswith(suffix) and host != apex
    return host == pattern


def host_matches_patterns(host: str, patterns: Iterable[str]) -> Optional[str]:
    """Return the first domain/wildcard pattern that matches ``host`` (after
    normalization), or None. Reuses the same matcher the scope gate uses, so
    callers like the redirect-drop filter stay consistent with scope semantics."""
    h = normalize_target(host)
    if not h:
        return None
    for p in patterns:
        if _domain_matches(h, p):
            return p
    return None


def _cidr_contains(ip: ipaddress._BaseAddress, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return False
    return ip.version == net.version and ip in net


class ScopeGuard:
    """Validates targets against a :class:`Scope`. Construct once per engagement.

    ``audit`` is any callable taking a :class:`ScopeDecision`; pass the audit
    logger's ``log_scope_decision`` in production, or a list's ``append`` in
    tests. Decoupled on purpose so the guard stays pure and testable.

    Thread-safety: the guard is stateless and holds no lock, so ``check()`` may
    be called concurrently from pipeline workers (up to ``max_global_concurrency``).
    It makes NO serialization guarantees around the audit sink — the sink itself
    must be thread-safe. ``AuditLog`` is; a plain ``list.append`` is (GIL-atomic);
    a bespoke file writer must add its own lock.
    """

    def __init__(self, scope: Scope, audit: Optional[Callable[[ScopeDecision], None]] = None):
        self.scope = scope
        self._audit = audit

    def _emit(self, decision: ScopeDecision) -> ScopeDecision:
        if self._audit is not None:
            self._audit(decision)
        return decision

    def check(self, target: str) -> ScopeDecision:
        """Return a decision for a single target. Always audited."""
        host = normalize_target(target)
        if not host:
            return self._emit(ScopeDecision(target, "", False, "unparseable target", ""))

        # Reject malformed hosts with an empty DNS label (leading dot or a double
        # dot, e.g. ".acme.com" / "sub..acme.com"). These would otherwise slip
        # past a wildcard's endswith() check — the one place the guard could
        # accept something it shouldn't. (Literal IPs never contain empty labels.)
        if host.startswith(".") or ".." in host:
            return self._emit(ScopeDecision(target, host, False, "invalid host: empty label", ""))

        ip = _is_ip(host)
        if ip is not None:
            # Literal IP: only CIDR rules apply. out_of_scope wins.
            for cidr in self.scope.out_of_scope_cidrs:
                if _cidr_contains(ip, cidr):
                    return self._emit(ScopeDecision(
                        target, host, False, "matched out_of_scope CIDR", f"cidr:{cidr}"))
            for cidr in self.scope.in_scope_cidrs:
                if _cidr_contains(ip, cidr):
                    return self._emit(ScopeDecision(
                        target, host, True, "matched in_scope CIDR", f"cidr:{cidr}"))
            return self._emit(ScopeDecision(
                target, host, False, "IP not in any in_scope CIDR", ""))

        # Domain: out_of_scope wins, then in_scope, else reject.
        for pat in self.scope.out_of_scope_domains:
            if _domain_matches(host, pat):
                return self._emit(ScopeDecision(
                    target, host, False, "matched out_of_scope domain", pat))
        # Label-based out_of_scope rules — evaluated with the same precedence,
        # still BEFORE in_scope, so they override an in_scope wildcard.
        labels = host.split(".")
        for needle in self.scope.out_of_scope_host_label_contains:
            if any(needle in lbl for lbl in labels):
                return self._emit(ScopeDecision(
                    target, host, False, "matched out_of_scope host label (contains)",
                    f"label_contains:{needle}"))
        for needle in self.scope.out_of_scope_host_label_equals:
            if any(lbl == needle for lbl in labels):
                return self._emit(ScopeDecision(
                    target, host, False, "matched out_of_scope host label (equals)",
                    f"label_equals:{needle}"))
        for pat in self.scope.in_scope_domains:
            if _domain_matches(host, pat):
                return self._emit(ScopeDecision(
                    target, host, True, "matched in_scope domain", pat))
        return self._emit(ScopeDecision(
            target, host, False, "not in scope", ""))

    def is_allowed(self, target: str) -> bool:
        return self.check(target).allowed

    def require(self, target: str) -> ScopeDecision:
        """Like :meth:`check` but raises :class:`ScopeViolation` on reject.
        Use at the last moment before invoking a tool against a single host."""
        d = self.check(target)
        if not d.allowed:
            raise ScopeViolation(f"{target!r} rejected: {d.reason}")
        return d

    def filter(self, targets: Iterable[str]) -> tuple[list[ScopeDecision], list[ScopeDecision]]:
        """Partition a batch into (allowed, rejected). Every item is audited."""
        allowed: list[ScopeDecision] = []
        rejected: list[ScopeDecision] = []
        for t in targets:
            d = self.check(t)
            (allowed if d.allowed else rejected).append(d)
        return allowed, rejected
