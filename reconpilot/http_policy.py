"""HTTP-policy helpers for the ``http:`` engagement block.

The ``drop_on_redirect_to`` filter. For scope safety the liveness stage runs
httpx WITHOUT following redirects, so no request is ever issued to a redirect
target. Instead we read the ``Location`` header from httpx ``-json`` output and
decide on that redirect-target host: if it matches a drop pattern
(``*.aws.amazon.com`` / ``midway-auth.amazon.com``) it is dropped and audited
without being followed. The matcher is the scope guard's own domain/wildcard
matcher, so "what counts as that host" matches scope semantics exactly.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

from .scope_guard import host_matches_patterns, normalize_target

# Keys that may carry a record's own probed URL / input (NOT a redirect target).
_FINAL_URL_KEYS = ("final_url", "url", "location", "input")
# Keys that carry a REDIRECT TARGET (a Location header), best first. Deliberately
# excludes ``url``/``input`` — those are the host we probed, not where it points.
_REDIRECT_KEYS = ("location", "redirect_url")


def final_host(record: dict[str, Any]) -> str:
    """Best-effort extraction of a record's host, normalized to a bare host.
    Falls back through probed-URL keys; used for display/audit context."""
    for key in _FINAL_URL_KEYS:
        val = record.get(key)
        if val:
            host = normalize_target(str(val))
            if host:
                return host
    return ""


def redirect_target_host(record: dict[str, Any]) -> str:
    """The host a record REDIRECTS to (from its Location header), normalized, or
    "" if the record is not a redirect or the Location is relative (same host).

    A relative Location (``/login``) normalizes to "" — same host, nothing to
    check — so only cross-host redirects are ever evaluated/dropped.
    """
    for key in _REDIRECT_KEYS:
        val = record.get(key)
        if val:
            host = normalize_target(str(val))
            if host:
                return host
    return ""


def filter_on_redirect(records: Iterable[dict[str, Any]], patterns: Iterable[str],
                       host_of: Callable[[dict[str, Any]], str] = final_host
                       ) -> tuple[list[dict], list[dict]]:
    """Partition records into (kept, dropped). A record is dropped if the host
    returned by ``host_of(record)`` matches any drop pattern; the dropped copy is
    tagged with ``_dropped_by`` = ``drop_on_redirect_to:<pattern>`` for the audit
    trail. The liveness stage passes ``host_of=redirect_target_host`` so the
    decision is made on the redirect target, never a followed final URL.

    With no patterns, nothing is dropped.
    """
    patterns = list(patterns)
    kept: list[dict] = []
    dropped: list[dict] = []
    for rec in records:
        matched: Optional[str] = host_matches_patterns(host_of(rec), patterns) \
            if patterns else None
        if matched:
            dropped.append({**rec, "_dropped_by": f"drop_on_redirect_to:{matched}"})
        else:
            kept.append(rec)
    return kept, dropped
