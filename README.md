# ReconPilot

A **local, prompt-driven orchestration layer** that automates tedious bug-bounty
reconnaissance against programs you are **authorized** to test. ReconPilot shells
out to best-of-breed open-source recon CLIs, enforces scope and rate limits in
code, records everything for reproducibility, and surfaces **what changed since
last time** — so you spend your effort on exploitation and reporting, not on
re-running the same enumeration by hand.

> **For authorized bug-bounty / VDP work only.** You are responsible for staying
> within the written rules of each program. ReconPilot is built so that
> authorization and scope are **enforced by the code**, not left to discipline —
> but it is a safety net, not permission. Only point it at assets a program
> explicitly authorizes you to test, at a rate the program permits.

---

## The safety model (why you can trust it to stay in its lane)

Five hard rules are baked into the architecture. None is "best effort" — each is
a module every tool invocation must pass through.

### 1. Scope gate — nothing runs against a host until it's proven in-scope
Every engagement has a [`scope.yaml`](scope.yaml) that is the **single source of
truth** for what may be touched. The `scope_guard` module validates **every**
target against it before any tool runs:

- `in_scope` and `out_of_scope` each accept apex domains, wildcards
  (`*.example.com`), explicit hosts, and CIDRs.
- **`out_of_scope` always wins.** Anything not explicitly in scope is rejected.
- **Wildcards cover subdomains only.** `*.acme.com` matches `foo.acme.com` and
  `a.b.acme.com`, but **not** the apex `acme.com` — list the apex separately if
  you want it. Lookalikes (`acme.com.evil.com`, `notacme.com`) are rejected by
  the dot-boundary.
- Literal IPs are judged **only** by CIDR rules; domain rules never apply to an
  IP. DNS-resolved IPs re-enter the pipeline as new targets and are re-checked.
- Every decision — allow and reject — is written to the audit log.

### 2. Rate / politeness — no tool runs uncapped
A global concurrency limit and a **per-host token-bucket** rate limiter enforce
`max_rps_per_host` from `scope.yaml`. A global **`--safe-mode`** halves rates and
concurrency again. A run-wide circuit breaker aborts if `max_requests_per_run` is
exceeded. Defaults are deliberately conservative.

### 3. Read-only posture — recon only, exploitation stays manual
The pipeline does passive recon, enumeration, and **templated signal detection**
(httpx / nuclei / etc.). It does **not** auto-exploit, auto-submit forms,
brute-force credentials, or generate DoS-style load. The `posture` flags in
`scope.yaml` (`allow_active_exploitation`, `allow_bruteforce`,
`allow_form_submission`) default to `false`. Exploitation is yours to do, by hand.

### 4. Audit log — full reproducibility
Every command, target, timestamp, and exit code is appended to a per-engagement
**append-only JSONL** log (each line flushed + fsynced). You can reconstruct
exactly what ran where, and the report exporter can slice the log as evidence.

### 5. Tool allowlist — no silent skips or substitutions
A tool runs only if it is (a) defined in [`tools.yaml`](tools.yaml), (b) listed
in the engagement's `allowed_tools`, **and** (c) found on your `PATH`. If a tool
is missing, ReconPilot tells you the exact install command — it never silently
skips it or swaps in something else.

---

## Architecture

```
scope.yaml ─┐
            ├─► config  ─► Scope / ToolSpec (validated, typed)
tools.yaml ─┘
                     │
   ┌─────────────────┼───────────────────────────────┐
   ▼                 ▼                                 ▼
scope_guard     rate_limiter                      tool_detect
(in/out scope)  (per-host + global + breaker)     (allowlist + PATH)
   └──────────────── every tool run passes through all three ───────┘
                                 │
                            audit_log  (append-only JSONL)
```

Pipeline stages (each a module, chainable, resumable, idempotent):

```
passive_recon → dns_resolve → liveness → port_scan → content_discovery → signal_scan → triage
```

Each stage reads the prior stage's output from SQLite, runs its tools through
`scope_guard` + the rate limiter, writes normalized results back, and logs
everything. A **diff engine** surfaces new subdomains / live hosts / endpoints /
findings since the last run — the whole point of re-running.

The **local GUI** (FastAPI, `127.0.0.1` only — never `0.0.0.0`) adds a chat-style
prompt that compiles natural-language intent into a **plan you confirm before it
runs**, a live job/log view, an asset browser, a findings view with diff
highlights and inline screenshots, and a one-click markdown report exporter.

---

## Status / build order

- [x] **1. Scaffold, requirements, README** (this).
- [x] **2. `scope_guard` + rate limiter + audit logger + tool detection, with
      unit tests** — proven *before* any tool is wired in. **46 tests passing.**
- [ ] 3. `tools.yaml` registry + generic guarded runner.
- [ ] 4. SQLite schema + diff engine.
- [ ] 5. Pipeline stages, one at a time.
- [ ] 6. FastAPI backend.
- [ ] 7. GUI + prompt-to-plan interpreter (confirm-before-run).
- [ ] 8. Markdown report exporter.

The plan-interpreter will sit behind an interface so it can later call a local
model or an API without touching the rest of the system.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the safety-module test suite:

```bash
pytest
```

Inspect how your current `scope.yaml` scopes some targets:

```bash
python -c "from reconpilot.config import load_scope; \
from reconpilot.scope_guard import ScopeGuard; \
g=ScopeGuard(load_scope('scope.yaml')); \
print(g.check('admin.acme.com')); print(g.check('blog.acme.com'))"
```

---

## Configuring an engagement

Edit [`scope.yaml`](scope.yaml) per program. Key fields:

| Field | Meaning |
|---|---|
| `engagement.*` | Program name, URL, platform, **who authorized it and when** |
| `in_scope` / `out_of_scope` | Domains, wildcards, CIDRs (out-of-scope wins) |
| `limits.max_rps_per_host` | Hard per-host rate cap |
| `limits.safe_mode` | Halves all rates/concurrency when `true` |
| `limits.max_requests_per_run` | Circuit-breaker ceiling |
| `allowed_tools` | Allowlist — remove anything a program forbids |
| `posture.*` | Read-only guarantees; keep `false` |

[`tools.yaml`](tools.yaml) is the data-driven tool registry — add a tool by
describing its binary, args template, and input/output type; no core code
changes needed.

---

## License / responsibility

ReconPilot bundles no scanners — it detects and orchestrates tools you install
yourself. Use it only against targets you are authorized to test. The authors
accept no liability for misuse.
