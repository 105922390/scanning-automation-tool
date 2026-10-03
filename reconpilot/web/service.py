"""Read-only data services for the dashboard.

All DB access goes through ``store.py`` (no schema knowledge is duplicated here):
this layer only shapes stored rows into the dicts the API returns. Pure and
synchronous, so it is unit-tested directly against a temp DB with no HTTP.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..audit_log import AuditLog
from ..engagement import list_engagements
from ..store import Store

# Asset filters the UI exposes -> how the store should constrain the query.
_FILTERS = {
    "all": {},
    "resolved": {"flag_true": "resolves"},
    "live": {"flag_true": "live"},
    "dropped": {"flag_present": "dropped_by_redirect"},
}
_SORTS = ("recent", "host", "host_desc", "status", "status_asc")

# Redirect-drop audit events the dashboard surfaces.
_REDIRECT_EVENTS = {"drop_on_redirect"}


class UnknownEngagement(LookupError):
    """Requested engagement is not one of the known engagement files."""


def available_engagements(base_dir: str | Path) -> list[str]:
    return list_engagements(base_dir)


def _open(base_dir: str | Path, name: str) -> Store:
    """Open the engagement's store, but only for a KNOWN engagement name — this
    both validates input and blocks any path traversal via the name."""
    if name not in list_engagements(base_dir):
        raise UnknownEngagement(name)
    return Store.open_for_engagement(name, base_dir=base_dir)


def _audit_for(store: Store) -> AuditLog:
    # audit.jsonl sits next to the engagement's recon.sqlite
    return AuditLog(Path(store.path).with_name("audit.jsonl"), engagement="")


def stats(base_dir: str | Path, name: str) -> dict:
    store = _open(base_dir, name)
    try:
        return {
            "engagement": name,
            "subdomains": store.count_assets("subdomain"),
            "resolved": store.count_assets("subdomain", flag_true="resolves"),
            "live": store.count_assets("subdomain", flag_true="live"),
            "dropped_on_redirect": store.count_assets("subdomain",
                                                      flag_present="dropped_by_redirect"),
            "distinct_ips": store.distinct_array_values("subdomain", "ips"),
        }
    finally:
        store.close()


def _asset_row(r: dict) -> dict:
    a = r.get("attrs") or {}
    return {
        "host": r["key"],
        "resolves": bool(a.get("resolves")),
        "live": a.get("live"),                      # True / False / None (not probed)
        "status_code": a.get("status_code"),
        "title": a.get("title") or "",
        "tech": a.get("tech") or [],
        "redirect_target": a.get("redirect_target") or "",
        "dropped_by_redirect": a.get("dropped_by_redirect") or "",
        "ips": a.get("ips") or [],
        "last_seen_at": r.get("last_seen_at"),
    }


def assets(base_dir: str | Path, name: str, *, filter: str = "all",
           search: Optional[str] = None, sort: str = "recent",
           limit: int = 100, offset: int = 0) -> dict:
    if filter not in _FILTERS:
        raise ValueError(f"unknown filter {filter!r}; choose from {sorted(_FILTERS)}")
    if sort not in _SORTS:
        raise ValueError(f"unknown sort {sort!r}; choose from {list(_SORTS)}")
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    constraint = _FILTERS[filter]
    store = _open(base_dir, name)
    try:
        rows = store.list_assets("subdomain", search=search, limit=limit, offset=offset,
                                 sort=sort, **constraint)
        total = store.count_assets("subdomain", search=search, **constraint)
    finally:
        store.close()
    return {
        "engagement": name, "filter": filter, "sort": sort, "search": search or "",
        "limit": limit, "offset": offset, "total": total,
        "rows": [_asset_row(r) for r in rows],
    }


def redirect_events(base_dir: str | Path, name: str, *, limit: int = 200) -> dict:
    limit = max(1, min(int(limit), 2000))
    store = _open(base_dir, name)
    try:
        audit = _audit_for(store)
    finally:
        store.close()
    events = [r for r in audit.read_all() if r.get("event") in _REDIRECT_EVENTS]
    events.reverse()                                # newest first
    rows = [{
        "ts": e.get("ts"),
        "input_host": e.get("input_host"),
        "final_host": e.get("final_host"),
        "matched_rule": e.get("matched_rule"),
        "status_code": e.get("status_code"),
        "run": e.get("run"),
    } for e in events[:limit]]
    return {"engagement": name, "total": len(events), "rows": rows}
