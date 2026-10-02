# ReconPilot — Handoff

_Snapshot: 2026-10-02. Verified against the repo on the old machine (tests run, files listed, audit log read)._

## 1. Goal

ReconPilot is a local, prompt-driven orchestration layer for **authorized** bug-bounty recon. It runs installed open-source CLIs (subfinder, amass, httpx, nuclei, …), enforces scope and rate limits **in code**, stores and diffs results in SQLite, and will later expose a local GUI bound to 127.0.0.1. Every target passes a scope gate before any tool touches it. Authorized testing only.

Working conventions (from the owner):
- Build one step at a time, then **stop and let the owner test** before starting the next.
- Use conservative defaults for every rate or concurrency knob.
- Safety lives in code (scope gate, rate limits, read-only posture, audit log, tool allowlist) and gets proven with tests before a tool is wired in.
- Keep the prompt-to-plan interpreter behind an interface so it can later call either a local model or an API.
- Python floor is 3.11. The owner runs 3.14.

## 2. Current state

**Tests:** `pytest` → **138 passed** (Python 3.14.7, `.venv`).

**Layout**
```
reconpilot/
  __main__.py, cli.py     CLI: python -m reconpilot -e <name> [--list --safe-mode --run-passive --dry-run --tools --out]
  config.py               parses scope/engagement YAML + tools.yaml into typed dataclasses
  engagement.py           list/resolve/load engagements/<name>.yaml (traversal-safe, fail-closed)
  scope_guard.py          default-deny, out-of-scope-wins, label rules
  rate_limiter.py         per-host token buckets + concurrency semaphore + run request cap (breaker)
  audit_log.py            JSONL audit events
  tool_detect.py          is the binary present + allowed?
  runner.py               tools.yaml-driven GuardedRunner (argv, shell=False, dry-run preview)
  http_policy.py          filter_on_redirect() (utility; not wired into a stage yet)
  store.py                SQLite per engagement: runs/assets/findings, first/last_seen_run diffing
  stages/passive_recon.py stage 1 of the pipeline
tests/                    one test file per module (FakeRunner, no network)
tools.yaml                tool registry
scope.yaml                generic template/example scope (acme-style), not the active engagement
engagements/amazon-vrp.yaml   the active engagement
engagements/amazon-vrp/       runtime data (git-ignored): recon.sqlite, audit.jsonl, runs/
```

**Build order:**
1. Scaffold, requirements, README: done
2. scope_guard + rate_limiter + audit_log + tool_detect: done
3. tools.yaml registry + generic guarded runner: done
4. SQLite store + diff engine: done
5. Pipeline stages: **in progress**. `passive_recon` is built and unit-tested. The remaining stages are not started.
6. FastAPI backend
7. GUI + prompt-to-plan interpreter (shows the plan and waits for confirmation before running)
8. Markdown report exporter

Amazon-VRP extension items: (1) engagement loader/selector: done; (2) `host_label_contains`/`host_label_equals`: done; (3) `http:` block (UA/OOB/redirect): done; (4) verify the rate limit is ONE shared bucket per host across ALL active tools: **not done**; (5) universal invariants that config can tighten but never disable, with a malformed file making things MORE restrictive: **not done**.

**tools.yaml tools:** subfinder, amass, gau, waybackurls (passive); dnsx, tlsx (dns_resolve); httpx, gowitness (liveness); naabu (port_scan); katana, ffuf (content_discovery); nuclei, dalfox, trufflehog, gf (signal_scan). A tool runs only if it is in tools.yaml **and** in the engagement's `allowed_tools` **and** installed.

**Active engagement: `engagements/amazon-vrp.yaml`** (authorized_by Julian, 2026-10-01)
- In scope: `amazon.<tld>` + `*.amazon.<tld>` for 26 marketplaces, plus `api.amazonalexa.com` and `*.amazonalexa.com`. CIDRs are empty (AWS IP space is explicitly out).
- Out of scope (always wins): `*.dev`, `*.a2z`, `host_label_contains: [aws]`, `host_label_equals: [test, qa, integ, preprod, gamma, beta]`.
- `limits`: `max_rps_per_host: 5`, `max_global_concurrency: 5`, `max_requests_per_run: 50000`, `safe_mode: true` (roughly halves the rate).
- `http`: mandatory `user_agent: amazonvrpresearcher_<h1user>`, `require_user_agent: true`, `no_third_party_oob: true`, `drop_on_redirect_to: [*.aws.amazon.com, midway-auth.amazon.com]`.
- `allowed_tools`: subfinder, amass, dnsx, httpx, katana, gau, waybackurls, gowitness, nuclei, ffuf, dalfox, trufflehog, gf. naabu and tlsx are deliberately excluded.
- `posture`: no active exploitation, no brute force, no form submission, plan confirmation required.

**Where it stopped: the first LIVE passive_recon run did NOT complete.**
- Command: `python -m reconpilot -e amazon-vrp --run-passive` (2026-10-01, about 04:39–04:56 UTC).
- amass ran first. **All 17 invocations exited 1 after about 60 s**, and the logs say: `The Amass engine did not respond within the timeout period`. This is amass's own engine/client timeout, not ours. It produced no output.
- The run was interrupted partway through amass's turn (it got as far as amazon.es). **subfinder never ran.**
- In SQLite, run #1 is still marked `status=running` and there are **0 assets**. No summary numbers exist yet.
- The audit log shows the guard working: 196 `scope_decision` events, 18 `tool_start`, 17 `tool_end`.

## 3. Environment / files to recreate (not in git)

```bash
python3 -m venv .venv            # 3.11+, owner uses 3.14
source .venv/bin/activate
pip install -r requirements.txt  # PyYAML, fastapi, uvicorn, jinja2, pytest
pytest                           # expect 138 passed
```

Go recon tools are installed natively and never auto-installed. On macOS use `brew install subfinder amass` (more later: dnsx, httpx, nuclei, …). Elsewhere use the `install:` line for each tool in tools.yaml (`go install …`) and put Go's bin directory on PATH: `export PATH="$PATH:$(go env GOPATH)/bin"`.

⚠️ **httpx name clash:** the Python `httpx` package (pip or conda) also installs a CLI called `httpx`. On the old machine, `which httpx` pointed at miniconda's Python httpx, **not** ProjectDiscovery's. Make sure the PD binary comes first on PATH (`httpx -version` should print the PD banner) before building or running the liveness stage.

**Git-ignored, so regenerate or copy over by hand:**
- `.venv/`: recreate as shown above.
- `engagements/amazon-vrp/` (`recon.sqlite`, `audit.jsonl`, `runs/`): created automatically on the first run. Its current contents are only one failed run, so it's safe to start fresh.

**Secret-ish value:** the HackerOne username sits inside `http.user_agent` in `engagements/amazon-vrp.yaml` (`amazonvrpresearcher_<h1user>`). If that value is missing or left as the placeholder (`YOUR_H1_USERNAME`), the runner treats the UA as invalid and **refuses to launch every active tool that declares a `ua_arg`**. That failure is intentional and closed-by-default.

## 4. What worked (proven by tests)

- **scope_guard:** default-deny, out-of-scope always wins, wildcard matching, and label rules (`label_contains:aws`, `label_equals:test`, …) checked before in_scope. Every decision is audited along with the `matched_rule`.
- **UA refusal:** active tools that have a `ua_arg` get the UA header injected. With `require_user_agent` set and an invalid UA, a real run raises `RunnerError` and a dry run skips the tool, with a `tool_refused` audit event either way.
- **OOB off:** nuclei gets `-no-interactsh` appended (`no_oob_arg`). dalfox never gets `-b`, so it makes no external callback, and nothing needs to be appended. A tool marked `requires_oob` would be skipped and logged.
- **Rate limiting:** a `RateLimiter` inside each `GuardedRunner` keeps one token bucket per host, shared by all of that runner's per-target tool calls, plus a global concurrency semaphore and a run-wide request cap. Batch/file tools (`-l {targets_file}`) self-limit through the `{rps}` argument and only count against the cap. *Whether this is truly one shared per-host budget across concurrently running active tools is extension item 4. It has not been verified yet.*
- **Passive stage:** scope-filters every discovered subdomain (audited) before upserting it, and computes "new since last run" as a diff. Verified with FakeRunner, not yet live.
- **Store:** dedup, first/last-seen diffing, finding fingerprints, triage fields.

## 5. What failed / rough edges

1. **amass times out on every target** (engine did not respond within 60 s, exit 1). Possible fixes: get the amass engine running or configured properly, or make passive_recon fall back to subfinder alone. Investigate before trusting amass output.
2. **Interrupted runs stay `running`.** passive_recon catches `Exception` but not `KeyboardInterrupt`, so pressing Ctrl-C leaves the run row open. Use `try/finally` or catch `BaseException` to mark it `interrupted` or `error`.
3. **amazonalexa.com seed dropped:** `enumeration_roots()` turns `*.amazonalexa.com` into the root `amazonalexa.com`, but the runner then scope-gates that seed. The bare apex isn't in scope, so it gets rejected (audit: `amazonalexa.com … not in scope`) and the wildcard's subdomains are never enumerated. Fix: treat the base of a `*.X` wildcard as an **enumeration seed**, independent of whether the apex is itself a valid target. Results must still go through scope filtering. The owner has a prompt drafted for this.
4. **Per-tool timeout isn't configurable.** `GuardedRunner` already has a hardcoded `default_timeout_s=1800` (`subprocess.TimeoutExpired` → `exit_code=-1`, and `error="timeout after Ns"` lands in `tool_end`). What's missing is a configurable `max_tool_seconds` (engagement/tools.yaml) and a dedicated `tool_timeout` audit event. amass at Amazon scale could otherwise tie up a run for 30 min per root.
5. The httpx PATH clash (see §3).
6. Liveness TODO already designed: run httpx with redirect following (`-fr`), pass the **final** URL/host to `http_policy.filter_on_redirect()`, and write an audit line for every dropped result explaining why (for example a redirect to `*.aws.amazon.com`). Nothing may be dropped silently.

## 6. Next steps (in order, stop and test after each)

a. Wildcard-seed fix (§5.3), plus marking interrupted runs correctly (§5.2), then a subfinder live run to get real summary numbers. Investigate amass.
b. Configurable per-tool timeout plus the `tool_timeout` audit event (§5.4).
c. `dns_resolve` (dnsx), then **liveness** (httpx).
   ⚠️ **Liveness is the first stage that sends real traffic to Amazon.** Before running it live, verify on a dry run and then on a tiny live sample: the UA header is present in the argv, the global per-host rate limit (finish extension item 4), and `filter_on_redirect` dropping and auditing redirects to AWS/midway.
d. `content_discovery` (katana, ffuf), `signal_scan` (nuclei, ffuf, dalfox: **leads only**, never raw reports; Amazon treats raw scanner output as out of scope), then `triage`. Extension item 5 (non-disableable invariants) belongs in here too.
e. FastAPI backend.
f. Local GUI on 127.0.0.1 only: prompt box → plan preview → explicit confirm → live log/results.
g. Markdown report exporter.
