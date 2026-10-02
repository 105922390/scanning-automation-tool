"""Audit log: append-only, valid JSONL, thread-safe, round-trips."""

import json
import threading

from reconpilot.audit_log import AuditLog
from reconpilot.scope_guard import ScopeDecision


def test_scope_decision_round_trips(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", engagement="e1")
    log.log_scope_decision(ScopeDecision("foo.acme.com", "foo.acme.com",
                                         True, "matched in_scope domain", "*.acme.com"))
    rows = log.read_all()
    assert len(rows) == 1
    r = rows[0]
    assert r["event"] == "scope_decision"
    assert r["allowed"] is True
    assert r["engagement"] == "e1"
    assert "ts" in r


def test_tool_start_end_recorded(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", engagement="e1")
    rid = log.log_tool_start("httpx", "foo.acme.com",
                             ["httpx", "-l", "targets.txt"], stage="liveness")
    log.log_tool_end(rid, "httpx", "foo.acme.com", exit_code=0,
                     duration_s=1.234, output_path="out.txt")
    rows = log.read_all()
    assert [r["event"] for r in rows] == ["tool_start", "tool_end"]
    assert rows[0]["command"] == ["httpx", "-l", "targets.txt"]
    assert rows[1]["exit_code"] == 0
    assert rows[1]["run_id"] == rid


def test_is_append_only_across_instances(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).log_event("run_start", note="first")
    AuditLog(p).log_event("run_start", note="second")   # fresh instance appends
    rows = AuditLog(p).read_all()
    assert [r["note"] for r in rows] == ["first", "second"]


def test_every_line_is_valid_json(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(10):
        log.log_event("tick", i=i)
    for line in p.read_text().splitlines():
        json.loads(line)   # raises if malformed


def test_concurrent_writes_are_atomic(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    n = 50

    def worker(k):
        for i in range(10):
            log.log_event("w", worker=k, i=i)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = p.read_text().splitlines()
    assert len(lines) == n * 10
    for line in lines:        # none interleaved / corrupted
        json.loads(line)
