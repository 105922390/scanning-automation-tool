"""Background job tracking for web-triggered stage runs (phase 2b).

A submitted plan runs in a daemon thread (stages take minutes-to-hours), with its
status tracked (running -> completed | interrupted | failed). The actual work is
the injected ``executor`` — ``run_exec.execute_plan`` in production (a seam), or a
fake in tests. Log tailing reads the engagement's audit.jsonl for events since the
job started, offset-paged for simple polling.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..audit_log import AuditLog
from ..runner import _kill_tree
from ..store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Canceller:
    """Cooperative cancellation for a running job: holds the live child process so
    a Stop (on the request thread) can kill its whole tree, and a flag the runner
    checks to abort the rest of the run."""
    def __init__(self):
        self._ev = threading.Event()
        self._proc = None
        self._lock = threading.Lock()

    def cancelled(self) -> bool:
        return self._ev.is_set()

    def wait(self, timeout=None) -> bool:
        return self._ev.wait(timeout)

    def register(self, proc) -> None:
        """Called by the runner with the live subprocess. If cancel already fired,
        kill it immediately (no tool should keep running past a Stop)."""
        with self._lock:
            self._proc = proc
        if self._ev.is_set() and proc is not None:
            self._kill(proc)

    def cancel(self) -> None:
        """Request cancellation and kill the current child process TREE (Windows
        taskkill /F /T; POSIX process-group signals) via the runner's killer."""
        self._ev.set()
        with self._lock:
            proc = self._proc
        if proc is not None:
            self._kill(proc)

    @staticmethod
    def _kill(proc) -> None:
        try:
            _kill_tree(proc)
        except Exception:        # noqa: BLE001 - best-effort kill; never raise from Stop
            pass


@dataclass
class Job:
    id: str
    engagement: str
    stage: str
    params: dict
    status: str = "running"            # running | completed | interrupted | cancelled | failed
    started_at: str = field(default_factory=_now)
    ended_at: Optional[str] = None
    error: str = ""
    result: Optional[dict] = None
    canceller: Canceller = field(default_factory=Canceller, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_status(self) -> dict:
        return {"run_id": self.id, "engagement": self.engagement, "stage": self.stage,
                "params": self.params, "status": self.status, "started_at": self.started_at,
                "ended_at": self.ended_at, "error": self.error, "result": self.result,
                "done": self.status != "running", "stopping": self.canceller.cancelled()}

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._done.wait(timeout)


class JobManager:
    def __init__(self, executor: Callable[[dict], Optional[dict]]):
        self._executor = executor
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, engagement: str, stage: str, params: dict) -> Job:
        job = Job(id=uuid.uuid4().hex, engagement=engagement, stage=stage, params=dict(params))
        with self._lock:
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def get(self, run_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(run_id)

    def stop_all(self) -> int:
        """Cancel every running job (and kill its child tool process tree). Returns
        how many were cancelled. Used on desktop-window / server shutdown."""
        with self._lock:
            running = [j for j in self._jobs.values() if j.status == "running"]
        for job in running:
            job.canceller.cancel()
        return len(running)

    def stop(self, run_id: str) -> Optional[Job]:
        """Request cancellation of a running job and kill its child tool process
        tree. Idempotent; returns the job (or None if unknown)."""
        job = self.get(run_id)
        if job is None:
            return None
        if job.status == "running":
            job.canceller.cancel()
        return job

    def _run(self, job: Job) -> None:
        try:
            job.result = self._executor(
                {"engagement": job.engagement, "stage": job.stage, "params": job.params},
                job.canceller)
            job.status = "cancelled" if job.canceller.cancelled() else "completed"
        except KeyboardInterrupt:
            job.status = "cancelled" if job.canceller.cancelled() else "interrupted"
            job.error = "cancelled" if job.canceller.cancelled() else "interrupted"
        except NotImplementedError as e:
            job.status = "failed"
            job.error = f"not wired: {e}"
        except BaseException as e:  # noqa: BLE001 - record any failure on the job
            job.status = "cancelled" if job.canceller.cancelled() else "failed"
            job.error = f"{type(e).__name__}: {e}"
        finally:
            job.ended_at = _now()
            job._done.set()


def job_log(base_dir: str | Path, job: Job, offset: int = 0, limit: int = 1000) -> dict:
    """Tail the engagement's audit events emitted since this job started, paged by
    ``offset`` for polling. Returns the window plus the next offset and job status."""
    audit_path = Store.engagement_db_path(job.engagement, base_dir).with_name("audit.jsonl")
    records = AuditLog(audit_path, engagement="").read_all()
    events = [r for r in records if (r.get("ts") or "") >= job.started_at]
    offset = max(0, offset)
    window = events[offset:offset + max(1, limit)]
    return {"run_id": job.id, "status": job.status, "done": job.status != "running",
            "offset": offset, "next_offset": offset + len(window),
            "total": len(events), "events": window}
