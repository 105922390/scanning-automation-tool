"""Markdown report SCAFFOLD for a lead. Pure formatting — no execution, no network.

Hard honesty constraint: this renders ONLY what the scanner actually observed plus
EMPTY placeholders the human must fill. It never claims a vulnerability is proven and
never fabricates impact/evidence. A nuclei hit is a lead, not a report — on programs
like Amazon's, raw scanner output is explicitly out of scope as a submission.
"""

from __future__ import annotations

from typing import Optional

LEAD_DISCLAIMER = (
    "> **Automated scanner LEAD — NOT a validated finding.**\n"
    "> This was produced by an automated scanner (nuclei). It has **not** been "
    "verified by a human and does **not** demonstrate impact.\n"
    "> Raw scanner output is **not** an acceptable report on this program. **Do not "
    "submit** until you have manually reproduced the issue and demonstrated real, "
    "in-scope impact in the sections below.")

# Sections the human must complete. They are rendered EMPTY — never auto-filled.
_PLACEHOLDERS = [
    ("Manual verification", "Did you reproduce it by hand? What exactly did you confirm?"),
    ("Demonstrated impact", "What concrete, in-scope impact did you prove? (no impact = no report)"),
    ("Proof of concept", "Minimal PoC (request/response, payload) that a triager can replay."),
    ("Reproduction steps", "1.\n2.\n3."),
]


def nuclei_command(audit_records: list) -> Optional[list]:
    """The most recent recorded nuclei command (argv) from the audit log, or None
    if no nuclei run was recorded — never invented."""
    cmds = [r.get("command") for r in audit_records
            if r.get("event") == "tool_start" and r.get("tool") == "nuclei" and r.get("command")]
    return cmds[-1] if cmds else None


def audit_slice(audit_records: list, n: int = 15) -> list:
    """The last ``n`` signal_scan / nuclei audit events, for reproducibility context."""
    rel = [r for r in audit_records
           if r.get("stage") == "signal_scan" or r.get("tool") == "nuclei"]
    return rel[-n:]


def _observed_table(finding: dict) -> list[str]:
    attrs = finding.get("attrs") or {}
    rows = [
        ("Target host", finding.get("target") or ""),
        ("Matched at", attrs.get("matched_at") or finding.get("matched_at") or ""),
        ("Template ID", attrs.get("template_id") or ""),
        ("Template name", finding.get("name") or ""),
        ("Scanner-reported severity", (finding.get("severity") or "unknown")),
        ("Tool", finding.get("tool") or ""),
        ("First seen (run)", finding.get("first_seen_run")),
        ("Last seen (run)", finding.get("last_seen_run")),
    ]
    out = ["| Field | Observed value |", "| --- | --- |"]
    for k, v in rows:
        out.append(f"| {k} | {'' if v is None else v} |")
    return out


def lead_filename(finding: dict) -> str:
    attrs = finding.get("attrs") or {}
    tid = (attrs.get("template_id") or "lead").replace("/", "-")
    host = (finding.get("target") or "host").replace("/", "-")
    return f"lead-{host}-{tid}-{finding.get('id', 'x')}.md"


def lead_markdown(finding: dict, *, engagement_name: str, program_url: str = "",
                  command: Optional[list] = None, audit_slice: Optional[list] = None) -> str:
    """Render a lead as a Markdown scaffold. ``command``/``audit_slice`` are what
    actually ran (for reproducibility); when absent, that is stated plainly rather
    than invented."""
    name = finding.get("name") or "(unnamed template)"
    sev = finding.get("severity") or "unknown"
    lines: list[str] = []
    lines.append(f"# Lead: {name} — {finding.get('target') or ''}")
    lines.append("")
    lines.append(LEAD_DISCLAIMER)
    lines.append("")
    lines.append(f"- **Engagement:** {engagement_name}")
    if program_url:
        lines.append(f"- **Program:** {program_url}")
    lines.append(f"- **Scanner-reported severity:** {sev}  "
                 f"_(reported by the tool; not confirmed)_")
    lines.append("")

    lines.append("## What the scanner observed")
    lines += _observed_table(finding)
    lines.append("")

    lines.append("## What ran (for reproducibility)")
    if command:
        lines.append("Exact command:")
        lines.append("")
        lines.append("```")
        lines.append(" ".join(str(c) for c in command))
        lines.append("```")
    else:
        lines.append("_No scanner command was recorded in the audit log for this lead._")
    if audit_slice:
        lines.append("")
        lines.append("Audit trail (slice):")
        lines.append("")
        lines.append("```")
        for e in audit_slice:
            ts = str(e.get("ts") or "")[:19]
            ev = e.get("event") or ""
            extra = e.get("target") or e.get("host") or e.get("root") or ""
            lines.append(f"{ts}  {ev}  {e.get('tool') or e.get('stage') or ''} {extra}".rstrip())
        lines.append("```")
    lines.append("")

    lines.append("## Human verification (REQUIRED before any submission)")
    lines.append("")
    for title, hint in _PLACEHOLDERS:
        lines.append(f"### {title}")
        lines.append(f"_{hint}_")
        lines.append("")          # intentionally empty — the human fills this in
    lines.append("---")
    lines.append("_This scaffold contains no claim of a proven vulnerability. "
                 "Submitting it as-is would be raw scanner output, which this program "
                 "does not accept._")
    return "\n".join(lines) + "\n"
