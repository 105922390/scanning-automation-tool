"""SQLite-backed engagement state + the diff engine.

Every run gets a row in ``runs``. Every asset (subdomain, host, ip, port,
endpoint, screenshot, secret) and every finding carries ``first_seen_run`` /
``last_seen_run`` + timestamps. That makes the deltas the whole tool exists for
trivial to query:

    * "new X in this run"     -> first_seen_run == <run_id>
    * "new X since yesterday" -> first_seen_at >= <iso timestamp>

One SQLite file per engagement. All access is serialized behind a lock (the
pipeline runs concurrent workers), and the clock is injectable for deterministic
tests.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

SCHEMA_VERSION = 1

# Asset kinds whose keys are case-insensitive hostnames/IPs -> stored lowercased.
_HOST_KINDS = {"subdomain", "host", "ip", "port"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    stage      TEXT NOT NULL,
    tool       TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'running',   -- running | ok | error | completed | interrupted
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    note       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,
    key            TEXT NOT NULL,
    attrs          TEXT NOT NULL DEFAULT '{}',    -- JSON
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    first_seen_run INTEGER NOT NULL,
    last_seen_run  INTEGER NOT NULL,
    UNIQUE(kind, key),
    FOREIGN KEY(first_seen_run) REFERENCES runs(id),
    FOREIGN KEY(last_seen_run)  REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_assets_kind       ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_first_run  ON assets(first_seen_run);
CREATE INDEX IF NOT EXISTS idx_assets_first_seen ON assets(first_seen_at);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint    TEXT NOT NULL UNIQUE,
    tool           TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'unknown',
    target         TEXT NOT NULL DEFAULT '',
    matched_at     TEXT NOT NULL DEFAULT '',
    attrs          TEXT NOT NULL DEFAULT '{}',    -- JSON
    triage_status  TEXT NOT NULL DEFAULT 'new',   -- new | triaged | reported | dismissed
    triage_note    TEXT NOT NULL DEFAULT '',
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    first_seen_run INTEGER NOT NULL,
    last_seen_run  INTEGER NOT NULL,
    FOREIGN KEY(first_seen_run) REFERENCES runs(id),
    FOREIGN KEY(last_seen_run)  REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_first_run ON findings(first_seen_run);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
"""


# --------------------------------------------------------------------------- #
# return types
# --------------------------------------------------------------------------- #
@dataclass
class Run:
    id: int
    stage: str
    tool: str
    status: str
    started_at: str
    ended_at: Optional[str]
    note: str


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_fingerprint(tool: str, name: str, target: str, matched_at: str = "") -> str:
    """Stable id for a finding so the same hit on re-run dedupes instead of
    piling up. matched_at (the exact URL/param) distinguishes otherwise-identical
    template hits on different endpoints."""
    raw = "|".join([tool.strip().lower(), name.strip().lower(),
                    target.strip().lower(), matched_at.strip().lower()])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: str | Path, *, now: Callable[[], str] = _iso_now):
        self.path = str(path)
        self._now = now
        self._lock = threading.RLock()
        is_mem = self.path == ":memory:"
        if not is_mem:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if not is_mem:
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    @staticmethod
    def engagement_slug(engagement_name: str) -> str:
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in engagement_name)

    @classmethod
    def engagement_db_path(cls, engagement_name: str,
                           base_dir: str | Path = "engagements") -> Path:
        """The engagement's recon.sqlite path WITHOUT opening it — lets callers
        resolve the sibling audit.jsonl without a DB side effect."""
        return Path(base_dir) / cls.engagement_slug(engagement_name) / "recon.sqlite"

    @classmethod
    def open_for_engagement(cls, engagement_name: str, base_dir: str | Path = "engagements",
                            **kw) -> "Store":
        return cls(cls.engagement_db_path(engagement_name, base_dir), **kw)

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- runs ---------------------------------------------------------------- #
    def start_run(self, stage: str, tool: str = "", note: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO runs(stage, tool, status, started_at, note) "
                "VALUES(?,?, 'running', ?, ?)",
                (stage, tool, self._now(), note))
            self._conn.commit()
            return cur.lastrowid

    def finish_run(self, run_id: int, status: str = "ok", note: Optional[str] = None) -> None:
        with self._lock:
            if note is None:
                self._conn.execute(
                    "UPDATE runs SET status=?, ended_at=? WHERE id=?",
                    (status, self._now(), run_id))
            else:
                self._conn.execute(
                    "UPDATE runs SET status=?, ended_at=?, note=? WHERE id=?",
                    (status, self._now(), note, run_id))
            self._conn.commit()

    @contextmanager
    def run(self, stage: str, tool: str = "", note: str = ""):
        """``with store.run('liveness', 'httpx') as rid:`` — marks ok on clean
        exit, error on exception (and re-raises)."""
        rid = self.start_run(stage, tool, note)
        try:
            yield rid
        except Exception as e:  # noqa: BLE001 - record then re-raise
            self.finish_run(rid, status="error", note=f"{type(e).__name__}: {e}")
            raise
        else:
            self.finish_run(rid, status="ok")

    def get_run(self, run_id: int) -> Optional[Run]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return Run(**dict(r)) if r else None

    def last_run(self, stage: Optional[str] = None) -> Optional[Run]:
        q = "SELECT * FROM runs"
        args: tuple = ()
        if stage:
            q += " WHERE stage=?"
            args = (stage,)
        q += " ORDER BY id DESC LIMIT 1"
        with self._lock:
            r = self._conn.execute(q, args).fetchone()
        return Run(**dict(r)) if r else None

    # -- assets -------------------------------------------------------------- #
    @staticmethod
    def _norm_key(kind: str, key: str) -> str:
        key = key.strip()
        return key.lower() if kind in _HOST_KINDS else key

    def upsert_asset(self, kind: str, key: str, run_id: int,
                     attrs: Optional[dict] = None) -> tuple[int, bool]:
        """Insert or update an asset. Returns ``(asset_id, is_new)`` where
        is_new is True only the first time this (kind,key) is ever seen."""
        key = self._norm_key(kind, key)
        now = self._now()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, attrs FROM assets WHERE kind=? AND key=?", (kind, key)).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO assets(kind,key,attrs,first_seen_at,last_seen_at,"
                    "first_seen_run,last_seen_run) VALUES(?,?,?,?,?,?,?)",
                    (kind, key, json.dumps(attrs or {}, sort_keys=True),
                     now, now, run_id, run_id))
                self._conn.commit()
                return cur.lastrowid, True
            merged = self._merge(row["attrs"], attrs)
            self._conn.execute(
                "UPDATE assets SET attrs=?, last_seen_at=?, last_seen_run=? WHERE id=?",
                (merged, now, run_id, row["id"]))
            self._conn.commit()
            return row["id"], False

    def record_assets(self, kind: str, keys: Iterable[str], run_id: int,
                      attrs: Optional[dict] = None) -> list[str]:
        """Bulk-upsert simple keys (e.g. a subdomain list). Returns the keys
        that were NEW to the DB this call — the per-kind delta."""
        new = []
        for k in keys:
            if not k or not k.strip():
                continue
            _, is_new = self.upsert_asset(kind, k, run_id, attrs)
            if is_new:
                new.append(self._norm_key(kind, k))
        return new

    # -- findings ------------------------------------------------------------ #
    def upsert_finding(self, *, tool: str, name: str, target: str, severity: str = "unknown",
                       matched_at: str = "", attrs: Optional[dict] = None,
                       run_id: int, fingerprint: Optional[str] = None) -> tuple[int, bool]:
        fp = fingerprint or finding_fingerprint(tool, name, target, matched_at)
        now = self._now()
        sev = (severity or "unknown").strip().lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, attrs FROM findings WHERE fingerprint=?", (fp,)).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO findings(fingerprint,tool,name,severity,target,matched_at,"
                    "attrs,first_seen_at,last_seen_at,first_seen_run,last_seen_run) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (fp, tool, name, sev, target, matched_at,
                     json.dumps(attrs or {}, sort_keys=True), now, now, run_id, run_id))
                self._conn.commit()
                return cur.lastrowid, True
            merged = self._merge(row["attrs"], attrs)
            self._conn.execute(
                "UPDATE findings SET attrs=?, last_seen_at=?, last_seen_run=?, severity=? "
                "WHERE id=?", (merged, now, run_id, sev, row["id"]))
            self._conn.commit()
            return row["id"], False

    def set_triage(self, finding_id: int, status: str, note: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET triage_status=?, triage_note=? WHERE id=?",
                (status, note, finding_id))
            self._conn.commit()

    # -- the diff engine ----------------------------------------------------- #
    def new_assets_in_run(self, run_id: int, kind: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM assets WHERE first_seen_run=?"
        args: list = [run_id]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        q += " ORDER BY kind, key"
        return self._rows(q, args)

    # -- attribute queries (resolution / liveness flags live in attrs JSON) -- #
    def keys(self, kind: str, limit: Optional[int] = None) -> list[str]:
        """All asset keys of a kind (e.g. every in-scope subdomain), sorted."""
        q = "SELECT key FROM assets WHERE kind=? ORDER BY key"
        args: list = [kind]
        if limit is not None:
            q += " LIMIT ?"; args.append(limit)
        with self._lock:
            return [r["key"] for r in self._conn.execute(q, args).fetchall()]

    def keys_where_flag(self, kind: str, flag: str, value: bool = True,
                        limit: Optional[int] = None) -> list[str]:
        """Keys whose attrs JSON has boolean ``flag`` set to ``value``. Used to
        pass only resolved hosts to liveness without loading every attrs blob."""
        q = ("SELECT key FROM assets WHERE kind=? "
             "AND json_extract(attrs, '$.' || ?) = ? ORDER BY key")
        args: list = [kind, flag, 1 if value else 0]
        if limit is not None:
            q += " LIMIT ?"; args.append(limit)
        with self._lock:
            return [r["key"] for r in self._conn.execute(q, args).fetchall()]

    def keys_flagged(self, kind: str, *, true_flag: Optional[str] = None,
                     null_flag: Optional[str] = None,
                     limit: Optional[int] = None) -> list[str]:
        """Keys filtered by attrs flags: ``true_flag`` must be boolean-true, and
        ``null_flag`` must be absent/null. Lets liveness select resolved hosts that
        have NOT yet been probed (``probed_at_run`` still null) so a resume
        continues with the remaining hosts instead of restarting."""
        q = "SELECT key FROM assets WHERE kind=?"
        args: list = [kind]
        if true_flag is not None:
            q += " AND json_extract(attrs, '$.' || ?) = 1"; args.append(true_flag)
        if null_flag is not None:
            q += " AND json_extract(attrs, '$.' || ?) IS NULL"; args.append(null_flag)
        q += " ORDER BY key"
        if limit is not None:
            q += " LIMIT ?"; args.append(limit)
        with self._lock:
            return [r["key"] for r in self._conn.execute(q, args).fetchall()]

    def new_findings_in_run(self, run_id: int) -> list[dict]:
        return self._rows(
            "SELECT * FROM findings WHERE first_seen_run=? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, id",
            [run_id])

    def new_assets_since(self, since_iso: str, kind: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM assets WHERE first_seen_at >= ?"
        args: list = [since_iso]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        q += " ORDER BY first_seen_at, kind, key"
        return self._rows(q, args)

    def diff_summary(self, run_id: int) -> dict:
        """Compact delta for a run: new assets per kind + new findings by severity."""
        with self._lock:
            akinds = self._conn.execute(
                "SELECT kind, COUNT(*) n FROM assets WHERE first_seen_run=? GROUP BY kind",
                (run_id,)).fetchall()
            sevs = self._conn.execute(
                "SELECT severity, COUNT(*) n FROM findings WHERE first_seen_run=? "
                "GROUP BY severity", (run_id,)).fetchall()
        new_assets = {r["kind"]: r["n"] for r in akinds}
        by_sev = {r["severity"]: r["n"] for r in sevs}
        return {
            "run_id": run_id,
            "new_assets": new_assets,
            "new_assets_total": sum(new_assets.values()),
            "new_findings_total": sum(by_sev.values()),
            "new_findings_by_severity": by_sev,
        }

    # -- browse (for the GUI) ------------------------------------------------ #
    # Safe ORDER BY clauses for asset listing (no user SQL ever interpolated).
    _ASSET_SORTS = {
        "recent": "last_seen_at DESC, kind, key",
        "host": "key ASC",
        "host_desc": "key DESC",
        "status": "CAST(json_extract(attrs, '$.status_code') AS INTEGER) DESC, key",
        "status_asc": "CAST(json_extract(attrs, '$.status_code') AS INTEGER) ASC, key",
    }

    def _asset_filter_sql(self, kind, search, flag_true, flag_present, flag_absent=None):
        q = " WHERE 1=1"
        args: list = []
        if kind:
            q += " AND kind=?"; args.append(kind)
        if search:
            q += " AND key LIKE ?"; args.append(f"%{search}%")
        if flag_true:
            q += " AND json_extract(attrs, '$.' || ?) = 1"; args.append(flag_true)
        if flag_present:
            q += " AND json_extract(attrs, '$.' || ?) IS NOT NULL"; args.append(flag_present)
        if flag_absent:
            q += " AND json_extract(attrs, '$.' || ?) IS NULL"; args.append(flag_absent)
        return q, args

    def list_assets(self, kind: Optional[str] = None, search: Optional[str] = None,
                    limit: int = 100, offset: int = 0,
                    new_in_run: Optional[int] = None, flag_true: Optional[str] = None,
                    flag_present: Optional[str] = None, sort: str = "recent") -> list[dict]:
        where, args = self._asset_filter_sql(kind, search, flag_true, flag_present)
        order = self._ASSET_SORTS.get(sort, self._ASSET_SORTS["recent"])
        q = f"SELECT * FROM assets{where} ORDER BY {order} LIMIT ? OFFSET ?"
        rows = self._rows(q, args + [limit, offset])
        if new_in_run is not None:
            for r in rows:
                r["is_new"] = (r["first_seen_run"] == new_in_run)
        return rows

    def count_assets(self, kind: Optional[str] = None, search: Optional[str] = None,
                     flag_true: Optional[str] = None, flag_present: Optional[str] = None,
                     flag_absent: Optional[str] = None) -> int:
        """Count assets matching the same filters as :meth:`list_assets` (for
        pagination totals, stat tiles, and plan host estimates). ``flag_absent``
        counts rows where that attr is unset — e.g. resolved-but-not-yet-probed."""
        where, args = self._asset_filter_sql(kind, search, flag_true, flag_present, flag_absent)
        with self._lock:
            return self._conn.execute(f"SELECT COUNT(*) n FROM assets{where}", args).fetchone()["n"]

    def distinct_array_values(self, kind: str, attr: str) -> int:
        """Count DISTINCT values across a JSON-array attribute of a kind — e.g. the
        number of distinct IPs across every subdomain's attrs.ips list."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT je.value) n FROM assets, "
                "json_each(json_extract(attrs, '$.' || ?)) je WHERE kind=?",
                (attr, kind)).fetchone()
        return row["n"] if row else 0

    def list_findings(self, severity: Optional[str] = None, triage_status: Optional[str] = None,
                      search: Optional[str] = None, limit: int = 100, offset: int = 0,
                      new_in_run: Optional[int] = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE 1=1"
        args: list = []
        if severity:
            q += " AND severity=?"; args.append(severity.lower())
        if triage_status:
            q += " AND triage_status=?"; args.append(triage_status)
        if search:
            q += " AND (name LIKE ? OR target LIKE ? OR matched_at LIKE ?)"
            args += [f"%{search}%"] * 3
        q += " ORDER BY last_seen_at DESC, id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        rows = self._rows(q, args)
        if new_in_run is not None:
            for r in rows:
                r["is_new"] = (r["first_seen_run"] == new_in_run)
        return rows

    def get_finding(self, finding_id: int) -> Optional[dict]:
        rows = self._rows("SELECT * FROM findings WHERE id=?", [finding_id])
        return rows[0] if rows else None

    def counts(self) -> dict:
        with self._lock:
            arows = self._conn.execute(
                "SELECT kind, COUNT(*) n FROM assets GROUP BY kind").fetchall()
            f = self._conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
            runs = self._conn.execute("SELECT COUNT(*) n FROM runs").fetchone()["n"]
        return {"assets": {r["kind"]: r["n"] for r in arows},
                "findings": f, "runs": runs}

    # -- internals ----------------------------------------------------------- #
    @staticmethod
    def _merge(old_json: str, new_attrs: Optional[dict]) -> str:
        d = json.loads(old_json) if old_json else {}
        for k, v in (new_attrs or {}).items():
            if v is not None:
                d[k] = v
        return json.dumps(d, sort_keys=True)

    def _rows(self, q: str, args: list) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if "attrs" in d:
                d["attrs"] = json.loads(d["attrs"]) if d["attrs"] else {}
            out.append(d)
        return out
