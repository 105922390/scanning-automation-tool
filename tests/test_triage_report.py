"""Triage state + lead report export. Display/formatting only — no execution."""

import asyncio
import json
from pathlib import Path

import pytest

from reconpilot import report
from reconpilot.audit_log import AuditLog
from reconpilot.store import Store
from reconpilot.web import service
from reconpilot.web.app import create_app

# phrases that would be DISHONEST if they ever appeared auto-filled in a draft
_FABRICATION_MARKERS = [
    "vulnerability confirmed", "confirmed vulnerable", "exploit successful",
    "proven impact", "is vulnerable", "successfully exploited", "impact demonstrated:",
]


@pytest.fixture
def engdir(tmp_path):
    d = tmp_path / "engagements"
    d.mkdir()
    (d / "demo.yaml").write_text(
        "engagement:\n  name: demo\n  program_url: https://hackerone.com/demo\n"
        "  authorized_by: t\n  authorized_date: 2026-10-01\n"
        "in_scope:\n  domains: [demo.com, '*.demo.com']\n"
        "allowed_tools: [nuclei]\n")
    store = Store.open_for_engagement("demo", base_dir=d)
    rid = store.start_run("signal_scan")
    store.upsert_finding(
        tool="nuclei", name="Exposed .git config", target="www.demo.com",
        severity="medium", matched_at="https://www.demo.com/.git/config", run_id=rid,
        attrs={"lead": True, "label": "lead — needs manual PoC",
               "template_id": "exposed-git-config", "type": "http",
               "matched_at": "https://www.demo.com/.git/config"})
    store.upsert_finding(
        tool="nuclei", name="Low thing", target="api.demo.com", severity="low",
        matched_at="https://api.demo.com/x", run_id=rid,
        attrs={"lead": True, "label": "lead — needs manual PoC",
               "template_id": "low-thing", "type": "http"})
    store.close()
    # audit: a recorded nuclei command for reproducibility
    audit = AuditLog(Store.engagement_db_path("demo", d).with_name("audit.jsonl"),
                     engagement="demo")
    audit.log_tool_start("nuclei", "batch:2",
                         ["nuclei", "-l", "in.txt", "-silent", "-nc", "-jsonl",
                          "-H", "User-Agent: amazonvrpresearcher_x", "-no-interactsh"],
                         stage="signal_scan")
    audit.log_event("chunk_completed", stage="signal_scan", run=rid, chunk=0)
    return d


def _fid(engdir, host):
    s = Store.open_for_engagement("demo", base_dir=engdir)
    try:
        return next(f["id"] for f in s.list_findings() if f["target"] == host)
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# report scaffold: observed fields + EMPTY placeholders, no fabricated impact
# --------------------------------------------------------------------------- #
def test_report_contains_observed_fields_and_empty_placeholders(engdir):
    s = Store.open_for_engagement("demo", base_dir=engdir)
    f = next(x for x in s.list_findings() if x["target"] == "www.demo.com")
    s.close()
    md = report.lead_markdown(
        f, engagement_name="demo", program_url="https://hackerone.com/demo",
        command=["nuclei", "-l", "in.txt", "-jsonl"],
        audit_slice=[{"ts": "2026-10-03T00:00:00", "event": "chunk_completed",
                      "stage": "signal_scan"}])
    # observed fields present
    assert "www.demo.com" in md
    assert "https://www.demo.com/.git/config" in md
    assert "exposed-git-config" in md
    assert "Exposed .git config" in md
    assert "medium" in md and "nuclei -l in.txt -jsonl" in md
    assert "https://hackerone.com/demo" in md
    # the four required EMPTY placeholders exist as headings
    for ph in ("Manual verification", "Demonstrated impact", "Proof of concept",
               "Reproduction steps"):
        assert f"### {ph}" in md
    # honesty header present
    assert "Automated scanner LEAD" in md and "Do not" in md and "submit" in md.lower()
    # NEVER a fabricated impact/proof claim
    low = md.lower()
    for marker in _FABRICATION_MARKERS:
        assert marker not in low


def test_report_states_when_no_command_recorded(engdir):
    s = Store.open_for_engagement("demo", base_dir=engdir)
    f = s.list_findings()[0]
    s.close()
    md = report.lead_markdown(f, engagement_name="demo", command=None, audit_slice=None)
    assert "No scanner command was recorded" in md     # stated, not invented


def test_nuclei_command_and_slice_extraction(engdir):
    audit = AuditLog(Store.engagement_db_path("demo", engdir).with_name("audit.jsonl"),
                     engagement="").read_all()
    cmd = report.nuclei_command(audit)
    assert cmd and cmd[0] == "nuclei" and "-no-interactsh" in cmd
    sl = report.audit_slice(audit)
    assert any(e["event"] == "chunk_completed" for e in sl)


# --------------------------------------------------------------------------- #
# triage: persistence + round-trip
# --------------------------------------------------------------------------- #
def test_triage_persists_and_round_trips(engdir):
    fid = _fid(engdir, "www.demo.com")
    row = service.set_triage(engdir, "demo", fid, "promising")
    assert row["triage_status"] == "promising"
    # reflected in the listing
    listed = {r["id"]: r for r in service.findings(engdir, "demo")["rows"]}
    assert listed[fid]["triage_status"] == "promising"
    # survives "restart" (fresh store/service reads)
    again = service.findings(engdir, "demo")["rows"]
    assert {r["id"]: r["triage_status"] for r in again}[fid] == "promising"


def test_triage_rejects_unknown_state(engdir):
    fid = _fid(engdir, "www.demo.com")
    with pytest.raises(ValueError):
        service.set_triage(engdir, "demo", fid, "exploited")   # not an allowed state


def test_triage_unknown_finding(engdir):
    with pytest.raises(service.UnknownFinding):
        service.set_triage(engdir, "demo", 9999, "reviewing")


# --------------------------------------------------------------------------- #
# findings service: filter/sort + lead labelling
# --------------------------------------------------------------------------- #
def test_findings_labelled_leads_and_sorted_by_severity(engdir):
    d = service.findings(engdir, "demo", sort="severity")
    assert d["label"] == "leads — need manual PoC"
    assert [r["severity"] for r in d["rows"]] == ["medium", "low"]   # severity rank
    assert all(r["lead"] for r in d["rows"])


def test_findings_filter_by_severity(engdir):
    d = service.findings(engdir, "demo", severity="low")
    assert d["total"] == 1 and d["rows"][0]["host"] == "api.demo.com"


# --------------------------------------------------------------------------- #
# endpoints over raw ASGI
# --------------------------------------------------------------------------- #
async def _asgi(app, method, path, body_obj=None, host="127.0.0.1:8000"):
    raw = json.dumps(body_obj).encode() if body_obj is not None else b""
    headers = [(b"host", host.encode())]
    if body_obj is not None:
        headers += [(b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "path": path, "raw_path": path.encode(),
             "query_string": b"", "scheme": "http", "root_path": "",
             "headers": headers, "client": ("127.0.0.1", 5), "server": ("127.0.0.1", 8000)}
    out, body = {}, bytearray()

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            body.extend(msg.get("body", b""))

    await app(scope, receive, send)
    out["json"] = json.loads(bytes(body) or b"null")
    return out


def test_endpoints_findings_triage_export(engdir):
    app = create_app(base_dir=engdir)
    fid = _fid(engdir, "www.demo.com")

    lst = asyncio.run(_asgi(app, "GET", "/api/engagements/demo/findings"))
    assert lst["status"] == 200 and lst["json"]["total"] == 2

    tr = asyncio.run(_asgi(app, "POST", f"/api/engagements/demo/findings/{fid}/triage",
                           {"status": "dismissed"}))
    assert tr["status"] == 200 and tr["json"]["triage_status"] == "dismissed"

    bad = asyncio.run(_asgi(app, "POST", f"/api/engagements/demo/findings/{fid}/triage",
                            {"status": "pwned"}))
    assert bad["status"] == 400

    ex = asyncio.run(_asgi(app, "GET", f"/api/engagements/demo/findings/{fid}/export"))
    assert ex["status"] == 200
    assert ex["json"]["filename"].endswith(".md")
    assert "### Proof of concept" in ex["json"]["markdown"]

    nf = asyncio.run(_asgi(app, "GET", "/api/engagements/demo/findings/9999/export"))
    assert nf["status"] == 404
