"""Append-only JSONL audit log — the reproducibility record for an engagement.

Every scope decision, tool invocation, and tool result is one JSON line. The
file is only ever appended to and each write is flushed, so a crash mid-run
still leaves a complete record up to that point. Thread-safe.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .scope_guard import ScopeDecision


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    def __init__(self, path: str | Path, engagement: str = ""):
        self.path = Path(path)
        self.engagement = engagement
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _write(self, record: dict[str, Any]) -> None:
        record.setdefault("ts", _utcnow())
        record.setdefault("engagement", self.engagement)
        line = json.dumps(record, sort_keys=True, default=str)
        with self._lock:
            # Open-append-close per write: cheap at recon volumes and robust to
            # concurrent writers / crashes. O_APPEND keeps lines from interleaving.
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    # -- high-level events --------------------------------------------------- #
    def log_scope_decision(self, decision: ScopeDecision) -> None:
        self._write({
            "event": "scope_decision",
            "target": decision.target,
            "host": decision.host,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        })

    def log_tool_start(self, tool: str, target: str, command: list[str],
                       stage: str = "", extra: Optional[dict] = None) -> str:
        run_id = f"{tool}-{target}-{_utcnow()}"
        rec = {
            "event": "tool_start",
            "run_id": run_id,
            "tool": tool,
            "stage": stage,
            "target": target,
            "command": command,
        }
        if extra:
            rec.update(extra)
        self._write(rec)
        return run_id

    def log_tool_end(self, run_id: str, tool: str, target: str, exit_code: int,
                     duration_s: float, output_path: str = "",
                     extra: Optional[dict] = None) -> None:
        rec = {
            "event": "tool_end",
            "run_id": run_id,
            "tool": tool,
            "target": target,
            "exit_code": exit_code,
            "duration_s": round(duration_s, 3),
            "output_path": output_path,
        }
        if extra:
            rec.update(extra)
        self._write(rec)

    def log_event(self, event: str, **fields: Any) -> None:
        """Escape hatch for any other auditable event (run_start, errors, …)."""
        rec = {"event": event}
        rec.update(fields)
        self._write(rec)

    # -- reading back -------------------------------------------------------- #
    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
