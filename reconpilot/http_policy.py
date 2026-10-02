"""HTTP-policy helpers for the ``http:`` engagement block.

So far: the ``drop_on_redirect_to`` filter. httpx (liveness stage) resolves final
URLs; after it runs we discard any result whose *final* host matches one of the
engagement's drop patterns (e.g. a probe that redirects to ``*.aws.amazon.com``
or ``midway-auth.amazon.com``). It reuses the scope guard's domain/wildcard
matcher so "what counts as that host" matches scope semantics exactly.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .scope_guard import host_matches_patterns, normalize_target

# Keys an httpx/other JSON record may carry for the post-redirect URL, best first.
_FINAL_URL_KEYS = ("final_url", "url", "location", "input")


def final_host(record: dict[str, Any]) -> str:
    """Best-effort extraction of a record's final host, normalized to a bare host."""
    for key in _FINAL_URL_KEYS:
        val = record.get(key)
        if val:
            host = normalize_target(str(val))
            if host:
                return host
    return ""


def filter_on_redirect(records: Iterable[dict[str, Any]],
                       patterns: Iterable[str]) -> tuple[list[dict], list[dict]]:
    """Partition records into (kept, dropped). A record is dropped if its final
    host matches any drop pattern; the dropped copy is tagged with
    ``_dropped_by`` = ``drop_on_redirect_to:<pattern>`` for the audit trail.

    With no patterns, nothing is dropped.
    """
    patterns = list(patterns)
    kept: list[dict] = []
    dropped: list[dict] = []
    for rec in records:
        matched: Optional[str] = host_matches_patterns(final_host(rec), patterns) \
            if patterns else None
        if matched:
            dropped.append({**rec, "_dropped_by": f"drop_on_redirect_to:{matched}"})
        else:
            kept.append(rec)
    return kept, dropped
