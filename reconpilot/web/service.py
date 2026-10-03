"""Read-only data services for the dashboard.

All DB access goes through ``store.py`` (no schema knowledge is duplicated here):
this layer only shapes stored rows into the dicts the API returns. Pure and
synchronous, so it is unit-tested directly against a temp DB with no HTTP.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import hashlib
import re

import yaml

from .. import report
from ..audit_log import AuditLog
from ..config import build_scope
from ..engagement import list_engagements, load_engagement
from ..errors import ConfigError
from ..store import Store

# Upload guardrails.
MAX_UPLOAD_BYTES = 256 * 1024
_SLUG_RE = re.compile(r"[^A-Za-z0-9_-]")

# Triage states a user can set on a lead (free-text column, validated here).
TRIAGE_STATES = ("new", "reviewing", "promising", "dismissed", "false-positive")
_FINDING_SORTS = ("recent", "severity", "host")

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


class UnknownFinding(LookupError):
    """Requested finding id does not exist for this engagement."""


class UploadError(ValueError):
    """An uploaded engagement failed validation (safe-parse, schema, name, size)."""


class EngagementExists(Exception):
    """Target engagement file exists and overwrite was not requested."""


def _engagements_dir(base_dir: str | Path) -> Path:
    return Path(base_dir)


def validate_engagement_yaml(base_dir: str | Path, yaml_text: str) -> dict:
    """Validate an uploaded engagement WITHOUT saving. Returns
    {name, slug, exists}. Raises UploadError (listing the problem) on any failure.

    Safety: parsed with yaml.safe_load ONLY (no arbitrary object construction / code
    execution); schema-validated via config.build_scope (requires authorized_by,
    authorized_date and >=1 in_scope entry); name slugified to [A-Za-z0-9_-] and the
    target path confined to the engagements dir (no traversal)."""
    if yaml_text is None:
        raise UploadError("empty upload")
    if len(yaml_text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise UploadError(f"upload too large (>{MAX_UPLOAD_BYTES} bytes)")

    try:
        raw = yaml.safe_load(yaml_text)       # safe_load: rejects !!python/... constructs
    except yaml.YAMLError as e:
        raise UploadError(f"invalid YAML: {e}")
    if not isinstance(raw, dict):
        raise UploadError("engagement YAML must be a mapping at the top level")

    try:
        scope = build_scope(raw)              # full schema validation (ConfigError)
    except ConfigError as e:
        raise UploadError(str(e))

    name = scope.engagement.name
    slug = _SLUG_RE.sub("", name.strip().replace(" ", "-"))
    if not slug:
        raise UploadError(f"engagement name {name!r} has no filename-safe characters "
                          "(use letters, digits, '-' or '_')")

    base = _engagements_dir(base_dir).resolve()
    target = (base / f"{slug}.yaml").resolve()
    if target.parent != base:                 # defense-in-depth: no path escape
        raise UploadError("resolved engagement path escapes the engagements directory")

    return {"name": name, "slug": slug, "exists": target.exists()}


def upload_core(slug: str, yaml_text: str) -> dict:
    """Confirm-token core binding the write to this exact slug + content."""
    digest = hashlib.sha256((yaml_text or "").encode("utf-8")).hexdigest()
    return {"kind": "engagement_upload", "slug": slug, "sha256": digest}


def save_engagement_yaml(base_dir: str | Path, yaml_text: str, *,
                         overwrite: bool = False) -> dict:
    """Validate (again) and write the uploaded engagement into the engagements dir.
    Raises UploadError on validation failure, EngagementExists if the file exists
    and ``overwrite`` is False."""
    info = validate_engagement_yaml(base_dir, yaml_text)   # re-validate server-side
    base = _engagements_dir(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    target = (base / f"{info['slug']}.yaml")
    if target.exists() and not overwrite:
        raise EngagementExists(info["slug"])
    target.write_text(yaml_text, encoding="utf-8")
    return {"name": info["name"], "slug": info["slug"],
            "overwritten": bool(info["exists"]), "engagements": list_engagements(base_dir)}


def _finding_row(f: dict) -> dict:
    a = f.get("attrs") or {}
    return {
        "id": f["id"],
        "template_id": a.get("template_id") or "",
        "name": f.get("name") or "",
        "severity": f.get("severity") or "unknown",
        "host": f.get("target") or "",
        "matched_at": a.get("matched_at") or f.get("matched_at") or "",
        "triage_status": f.get("triage_status") or "new",
        "triage_note": f.get("triage_note") or "",
        "lead": bool(a.get("lead")),
        "label": a.get("label") or "",
        "tool": f.get("tool") or "",
    }


def findings(base_dir: str | Path, name: str, *, severity: Optional[str] = None,
             triage: Optional[str] = None, search: Optional[str] = None,
             sort: str = "severity", limit: int = 100, offset: int = 0) -> dict:
    if sort not in _FINDING_SORTS:
        raise ValueError(f"unknown sort {sort!r}; choose from {list(_FINDING_SORTS)}")
    if triage and triage not in TRIAGE_STATES:
        raise ValueError(f"unknown triage state {triage!r}; choose from {list(TRIAGE_STATES)}")
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    store = _open(base_dir, name)
    try:
        rows = store.list_findings(severity=severity, triage_status=triage, search=search,
                                   sort=sort, limit=limit, offset=offset)
        total = store.count_findings(severity=severity, triage_status=triage, search=search)
    finally:
        store.close()
    return {
        "engagement": name, "severity": severity or "", "triage": triage or "",
        "search": search or "", "sort": sort, "limit": limit, "offset": offset,
        "total": total, "triage_states": list(TRIAGE_STATES),
        "label": "leads — need manual PoC",
        "rows": [_finding_row(f) for f in rows],
    }


def set_triage(base_dir: str | Path, name: str, finding_id: int, status: str) -> dict:
    """Persist a triage state on a lead (a write to our OWN DB, not a scan)."""
    if status not in TRIAGE_STATES:
        raise ValueError(f"unknown triage state {status!r}; choose from {list(TRIAGE_STATES)}")
    store = _open(base_dir, name)
    try:
        f = store.get_finding(finding_id)
        if not f:
            raise UnknownFinding(finding_id)
        store.set_triage(finding_id, status, note=f.get("triage_note") or "")
        return _finding_row(store.get_finding(finding_id))
    finally:
        store.close()


def export_lead(base_dir: str | Path, name: str, finding_id: int) -> dict:
    """Build a Markdown scaffold for one lead — observed fields + empty placeholders
    only. No submission; no fabricated impact (see reconpilot.report)."""
    store = _open(base_dir, name)
    try:
        f = store.get_finding(finding_id)
    finally:
        store.close()
    if not f:
        raise UnknownFinding(finding_id)
    scope = load_engagement(name, base_dir)
    audit = AuditLog(Store.engagement_db_path(name, base_dir).with_name("audit.jsonl"),
                     engagement="").read_all()
    md = report.lead_markdown(
        f, engagement_name=name, program_url=scope.engagement.program_url,
        command=report.nuclei_command(audit), audit_slice=report.audit_slice(audit))
    return {"engagement": name, "finding_id": finding_id,
            "filename": report.lead_filename(f), "markdown": md}


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
