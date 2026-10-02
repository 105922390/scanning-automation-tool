"""GuardedRunner: command building, scope filtering, exec, rate/breaker, audit."""

import dataclasses
import os
import stat
import sys

import pytest

from reconpilot.audit_log import AuditLog
from reconpilot.config import Http, Limits, ToolSpec
from reconpilot.errors import CircuitBreakerTripped, RunnerError, ToolNotAvailable
from reconpilot.rate_limiter import RateLimiter
from reconpilot.runner import GuardedRunner, build_command


# --------------------------------------------------------------------------- #
# build_command (pure)
# --------------------------------------------------------------------------- #
def _spec(name, args, **kw):
    base = dict(stage="s", binary=name, input="x", output="y",
                active=True, args=args, install="")
    base.update(kw)
    return ToolSpec(name=name, **base)


def test_build_substitutes_target_inside_token():
    spec = _spec("ffuf", "-u {target}/FUZZ -w {wordlist} -rate {rps} -o {output}")
    cmd = build_command(spec, "/bin/ffuf", target="https://foo.acme.com",
                        wordlist="/wl.txt", rps=3, output="/out.json")
    assert cmd == ["/bin/ffuf", "-u", "https://foo.acme.com/FUZZ",
                   "-w", "/wl.txt", "-rate", "3", "-o", "/out.json"]


def test_build_maps_all_file_keys_to_input_file():
    for key in ("targets_file", "urls_file", "hosts_file"):
        spec = _spec("t", f"-l {{{key}}} -o {{output}}")
        cmd = build_command(spec, "t", input_file="/in.txt", output="/o")
        assert cmd == ["t", "-l", "/in.txt", "-o", "/o"]


def test_build_missing_required_value_raises():
    spec = _spec("ffuf", "-w {wordlist}")
    with pytest.raises(RunnerError):
        build_command(spec, "ffuf")  # no wordlist provided


def test_build_leftover_placeholder_raises():
    spec = _spec("t", "-x {bogus}")
    with pytest.raises(RunnerError):
        build_command(spec, "t")


# --------------------------------------------------------------------------- #
# fixtures: a scope that allowlists our fake tools + fake tool scripts
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_scope(scope):
    return dataclasses.replace(
        scope, allowed_tools=frozenset({"echotool", "filetool", "urltool"}))


@pytest.fixture
def fake_tools(tmp_path):
    """Create two executable fake tools and a which() that resolves them.

    echotool: prints its single arg (stdout-capture tool, no {output}).
    filetool: reads -l file, writes its line count to -o (self-writing tool).
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()

    bodies = {
        "echotool": "import sys\nprint(sys.argv[1])\n",
        "filetool": (
            "import sys\n"
            "a = sys.argv[1:]\n"
            "inp = a[a.index('-l')+1]; out = a[a.index('-o')+1]\n"
            "n = sum(1 for _ in open(inp))\n"
            "open(out,'w').write(f'lines={n}\\n')\n"
            "print('scanned', n)\n"),
    }
    paths = {name: str(_make_stub(bindir, name, body)) for name, body in bodies.items()}
    return paths, (lambda name: paths.get(name))


def _make_stub(bindir, name, body):
    """Write a fake tool the runner can exec directly on the current OS.

    The logic lives in ``<name>.py``; the returned launcher runs it with the
    interpreter executing the tests (sys.executable), so no python3 on PATH is
    needed. Windows can't exec shebang scripts, so it gets a ``.cmd`` wrapper.
    """
    script = bindir / f"{name}.py"
    script.write_text(body)
    if os.name == "nt":
        launcher = bindir / f"{name}.cmd"
        launcher.write_text(f'@"{sys.executable}" "{script}" %*\r\n')
        return launcher
    launcher = bindir / name
    # shebangs can't contain spaces; fall back to env lookup in that case
    interp = sys.executable if " " not in sys.executable else "/usr/bin/env python3"
    launcher.write_text(f"#!{interp}\n" + body)
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return launcher


@pytest.fixture
def registry_fake():
    return {
        # input defaults to 'x' (a non-url type) -> fed the normalized host
        "echotool": _spec("echotool", "{target}", stage="passive_recon", input="domain"),
        "filetool": _spec("filetool", "-l {targets_file} -o {output} -rl {rps}",
                          stage="liveness", input="targets_file"),
        # url-oriented -> fed the raw target with scheme/path preserved
        "urltool": _spec("urltool", "{target}", stage="content_discovery",
                         input="urls_file"),
    }


def _runner(fake_scope, registry_fake, which, tmp_path, rate_limiter=None):
    audit = AuditLog(tmp_path / "audit.jsonl", engagement="t")
    return GuardedRunner(fake_scope, registry_fake, audit, which=which,
                         rate_limiter=rate_limiter), audit


# --------------------------------------------------------------------------- #
# scope filtering + per-target execution
# --------------------------------------------------------------------------- #
def test_per_target_runs_only_in_scope_and_audits(fake_scope, registry_fake,
                                                  fake_tools, tmp_path):
    _, which = fake_tools
    runner, audit = _runner(fake_scope, registry_fake, which, tmp_path)
    res = runner.run("echotool", ["foo.acme.com", "evil.com", "blog.acme.com"],
                     tmp_path / "out")

    assert res.allowed == ["foo.acme.com"]
    assert sorted(res.rejected) == ["blog.acme.com", "evil.com"]
    assert len(res.invocations) == 1
    inv = res.invocations[0]
    assert inv.exit_code == 0
    assert "foo.acme.com" in open(inv.output_path).read()

    events = [r["event"] for r in audit.read_all()]
    assert events.count("scope_decision") == 3     # every target decided + logged
    assert "tool_start" in events and "tool_end" in events


def test_feed_normalizes_host_for_domain_tools_but_keeps_url_for_url_tools(
        fake_scope, registry_fake, tmp_path):
    runner, _ = _runner(fake_scope, registry_fake, lambda n: None, tmp_path)
    url = "https://api.acme.com/v1?x=1"
    # domain tool: URL/port/trailing-dot collapsed to a bare host
    d = runner.run("echotool", [url, "acme.com.:443"], tmp_path / "o", dry_run=True)
    assert [iv.command[1] for iv in d.invocations] == ["api.acme.com", "acme.com"]
    # url tool: full target preserved
    u = runner.run("urltool", [url], tmp_path / "o", dry_run=True)
    assert u.invocations[0].command == ["urltool", url]


def test_skip_when_no_in_scope_targets(fake_scope, registry_fake, fake_tools, tmp_path):
    _, which = fake_tools
    runner, audit = _runner(fake_scope, registry_fake, which, tmp_path)
    res = runner.run("echotool", ["evil.com", "out.of.scope.net"], tmp_path / "out")
    assert res.skipped_reason == "no in-scope targets"
    assert not res.ran
    assert any(r["event"] == "tool_skipped" for r in audit.read_all())


# --------------------------------------------------------------------------- #
# batch execution (file input, tool self-writes output)
# --------------------------------------------------------------------------- #
def test_batch_builds_input_file_and_runs(fake_scope, registry_fake, fake_tools, tmp_path):
    _, which = fake_tools
    runner, audit = _runner(fake_scope, registry_fake, which, tmp_path)
    res = runner.run("filetool", ["a.acme.com", "b.acme.com", "evil.com"],
                     tmp_path / "out")
    assert res.mode == "batch"
    assert sorted(res.allowed) == ["a.acme.com", "b.acme.com"]
    inv = res.invocations[0]
    assert inv.exit_code == 0
    # the tool wrote the output itself; two in-scope lines went into the input file
    assert open(inv.output_path).read().strip() == "lines=2"
    assert "-rl" in inv.command and "4" in inv.command   # {rps} substituted (eff rps=4)


# --------------------------------------------------------------------------- #
# dry run
# --------------------------------------------------------------------------- #
def test_dry_run_builds_plan_without_executing(fake_scope, registry_fake, tmp_path):
    # which returns None -> tool not installed, but dry-run still plans
    runner, audit = _runner(fake_scope, registry_fake, lambda n: None, tmp_path)
    res = runner.run("echotool", ["foo.acme.com", "evil.com"], tmp_path / "out",
                     dry_run=True)
    assert res.dry_run and not res.tool_available
    assert not res.ran
    inv = res.invocations[0]
    assert inv.exit_code is None
    assert inv.command == ["echotool", "foo.acme.com"]
    # scope was still evaluated + audited; no tool_start in dry-run
    events = [r["event"] for r in audit.read_all()]
    assert "scope_decision" in events and "tool_start" not in events


# --------------------------------------------------------------------------- #
# allowlist / registry enforcement
# --------------------------------------------------------------------------- #
def test_tool_not_in_registry_raises(fake_scope, registry_fake, fake_tools, tmp_path):
    _, which = fake_tools
    runner, _ = _runner(fake_scope, registry_fake, which, tmp_path)
    with pytest.raises(ToolNotAvailable):
        runner.run("ghost", ["foo.acme.com"], tmp_path / "out")


def test_tool_not_allowlisted_raises(scope, registry_fake, fake_tools, tmp_path):
    # 'scope' (not fake_scope) does NOT allowlist echotool
    _, which = fake_tools
    runner, _ = _runner(scope, registry_fake, which, tmp_path)
    with pytest.raises(ToolNotAvailable):
        runner.run("echotool", ["foo.acme.com"], tmp_path / "out")


def test_missing_binary_raises_with_install_hint(fake_scope, registry_fake, tmp_path):
    runner, _ = _runner(fake_scope, registry_fake, lambda n: None, tmp_path)
    with pytest.raises(ToolNotAvailable):
        runner.run("echotool", ["foo.acme.com"], tmp_path / "out")  # not dry-run


# --------------------------------------------------------------------------- #
# rate limiter / circuit breaker wiring
# --------------------------------------------------------------------------- #
def test_batch_charges_circuit_breaker(fake_scope, registry_fake, fake_tools, tmp_path):
    _, which = fake_tools
    rl = RateLimiter(Limits(max_rps_per_host=100, max_global_concurrency=4,
                            max_requests_per_run=1, safe_mode=False))
    runner, _ = _runner(fake_scope, registry_fake, which, tmp_path, rate_limiter=rl)
    # 2 in-scope targets charged against a cap of 1 -> breaker trips
    with pytest.raises(CircuitBreakerTripped):
        runner.run("filetool", ["a.acme.com", "b.acme.com"], tmp_path / "out")


# --------------------------------------------------------------------------- #
# HTTP policy (item 3): UA injection, refuse-if-missing, OOB disable/skip
# --------------------------------------------------------------------------- #
_HTTP_REGISTRY = {
    "act_http": _spec("act_http", "-l {targets_file} -o {output}", stage="liveness",
                      input="targets_file", active=True,
                      ua_arg="-H 'User-Agent: {user_agent}'"),
    "act_oob": _spec("act_oob", "-l {targets_file} -o {output}", stage="signal_scan",
                     input="targets_file", active=True,
                     ua_arg="-H 'User-Agent: {user_agent}'", no_oob_arg="-no-interactsh"),
    "act_needs_oob": _spec("act_needs_oob", "-l {targets_file} -o {output}",
                           stage="signal_scan", input="targets_file", active=True,
                           requires_oob=True),
    "act_nonhttp": _spec("act_nonhttp", "{target}", stage="dns_resolve",
                         input="domain", active=True),           # active but no ua_arg
    "passive_tool": _spec("passive_tool", "{target}", stage="passive_recon",
                          input="domain", active=False, ua_arg="-H 'UA: {user_agent}'"),
}


def _http_scope(base, **http_kw):
    return dataclasses.replace(
        base,
        allowed_tools=frozenset(_HTTP_REGISTRY),
        http=Http(**http_kw))


def _mk(base, tmp_path, **http_kw):
    scope = _http_scope(base, **http_kw)
    audit = AuditLog(tmp_path / "audit.jsonl", engagement="t")
    return GuardedRunner(scope, _HTTP_REGISTRY, audit,
                         which=lambda n: "/usr/bin/true"), audit


def test_user_agent_injected_into_active_tool(scope, tmp_path):
    runner, _ = _mk(scope, tmp_path, user_agent="UA-X")
    res = runner.run("act_http", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    cmd = res.invocations[0].command
    assert "-H" in cmd and "User-Agent: UA-X" in cmd


def test_passive_tool_gets_no_user_agent(scope, tmp_path):
    runner, _ = _mk(scope, tmp_path, user_agent="UA-X")
    res = runner.run("passive_tool", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    assert "User-Agent: UA-X" not in res.invocations[0].command


def test_require_user_agent_missing_refuses_real_run(scope, tmp_path):
    runner, audit = _mk(scope, tmp_path, user_agent="", require_user_agent=True)
    with pytest.raises(RunnerError) as e:
        runner.run("act_http", ["foo.acme.com"], tmp_path / "o")
    assert "require_user_agent" in str(e.value)
    assert any(r["event"] == "tool_refused" for r in audit.read_all())


def test_require_user_agent_missing_skips_in_dry_run(scope, tmp_path):
    runner, _ = _mk(scope, tmp_path, user_agent="YOUR_H1_USERNAME",
                    require_user_agent=True)
    res = runner.run("act_http", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    assert "refusing to launch" in res.skipped_reason
    assert not res.invocations


def test_active_non_http_tool_not_refused_without_ua(scope, tmp_path):
    # act_nonhttp is active but declares no ua_arg -> UA requirement doesn't apply
    runner, _ = _mk(scope, tmp_path, user_agent="", require_user_agent=True)
    res = runner.run("act_nonhttp", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    assert not res.skipped_reason
    # runs normally, no UA header appended
    assert res.invocations[0].command[1:] == ["foo.acme.com"]


def test_no_third_party_oob_appends_disable_flag(scope, tmp_path):
    runner, _ = _mk(scope, tmp_path, user_agent="UA-X", no_third_party_oob=True)
    res = runner.run("act_oob", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    assert "-no-interactsh" in res.invocations[0].command


def test_tool_requiring_oob_is_skipped_and_logged(scope, tmp_path):
    runner, audit = _mk(scope, tmp_path, user_agent="UA-X", no_third_party_oob=True)
    res = runner.run("act_needs_oob", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    assert "third-party OOB" in res.skipped_reason and not res.invocations
    assert any(r["event"] == "tool_skipped" for r in audit.read_all())


def test_oob_flag_absent_when_policy_off(scope, tmp_path):
    runner, _ = _mk(scope, tmp_path, user_agent="UA-X", no_third_party_oob=False)
    res = runner.run("act_oob", ["foo.acme.com"], tmp_path / "o", dry_run=True)
    assert "-no-interactsh" not in res.invocations[0].command


# --------------------------------------------------------------------------- #
# passive seed mode (wildcard-seed fix)
# --------------------------------------------------------------------------- #
def test_seed_mode_accepts_wildcard_base_and_audits_seed_decision(
        fake_scope, registry_fake, fake_tools, tmp_path):
    _, which = fake_tools
    reg = dict(registry_fake, echotool=dataclasses.replace(
        registry_fake["echotool"], active=False))
    runner, audit = _runner(fake_scope, reg, which, tmp_path)
    # acme-api.com is only covered by *.acme-api.com -> not a target, but a seed
    res = runner.run("echotool", ["acme-api.com", "evil.com", "com"],
                     tmp_path / "out", seeds=True)
    assert res.allowed == ["acme-api.com"]
    assert sorted(res.rejected) == ["com", "evil.com"]
    assert res.invocations[0].exit_code == 0
    recs = audit.read_all()
    seeds = {r["seed"]: r["allowed"] for r in recs if r["event"] == "seed_decision"}
    assert seeds == {"acme-api.com": True, "evil.com": False, "com": False}
    # seeds are NOT run through the target gate
    assert not any(r["event"] == "scope_decision" for r in recs)


def test_seed_mode_refused_for_active_tool(fake_scope, registry_fake, fake_tools, tmp_path):
    _, which = fake_tools
    runner, audit = _runner(fake_scope, registry_fake, which, tmp_path)  # echotool active
    with pytest.raises(RunnerError):
        runner.run("echotool", ["acme-api.com"], tmp_path / "out", seeds=True)
    assert any(r["event"] == "tool_refused" for r in audit.read_all())


def test_target_mode_still_rejects_wildcard_base(fake_scope, registry_fake, tmp_path):
    runner, _ = _runner(fake_scope, registry_fake, lambda n: None, tmp_path)
    res = runner.run("echotool", ["acme-api.com"], tmp_path / "o", dry_run=True)
    assert res.rejected == ["acme-api.com"] and not res.invocations


# --------------------------------------------------------------------------- #
# per-tool timeout (item B)
# --------------------------------------------------------------------------- #
_HANG_TOOL = """\
import subprocess, sys, time
from pathlib import Path
t = sys.argv[1]
# a grandchild, like a real tool's worker; it must die with the tree
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(__file__).with_name(f"child-{t}.pid").write_text(str(child.pid))
print("partial", t, flush=True)
time.sleep(60)
"""


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return code.value == 259                  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_dead(pid: int, within_s: float = 5.0) -> bool:
    import time
    deadline = time.monotonic() + within_s
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


def test_timeout_kills_tree_keeps_partial_output_and_continues(scope, tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    hang = str(_make_stub(bindir, "hangtool", _HANG_TOOL))
    reg = {"hangtool": _spec("hangtool", "{target}", stage="passive_recon",
                             input="domain", active=False)}
    s = dataclasses.replace(
        scope, allowed_tools=frozenset({"hangtool"}),
        limits=dataclasses.replace(scope.limits, max_tool_seconds=2))
    audit = AuditLog(tmp_path / "audit.jsonl", engagement="t")
    runner = GuardedRunner(s, reg, audit, which=lambda n: hang)

    res = runner.run("hangtool", ["a.acme.com", "b.acme.com"], tmp_path / "out")

    # both targets attempted: the first timeout did not stop the run
    assert [iv.target for iv in res.invocations] == ["a.acme.com", "b.acme.com"]
    for iv in res.invocations:
        assert iv.timed_out and iv.exit_code == -1
        assert iv.error == "timeout after 2s"
        assert iv.duration_s < 2 + 15           # killed, not left to sleep 60s
        assert f"partial {iv.target}" in open(iv.output_path).read()   # partial kept
        # the grandchild died with the tree (not just the wrapper)
        child_pid = int((bindir / f"child-{iv.target}.pid").read_text())
        assert _wait_dead(child_pid), f"grandchild {child_pid} still running"

    recs = audit.read_all()
    timeouts = [r for r in recs if r["event"] == "tool_timeout"]
    assert [t["target"] for t in timeouts] == ["a.acme.com", "b.acme.com"]
    assert all(t["timeout_s"] == 2 and t["partial_stdout_chars"] > 0 for t in timeouts)
    assert sum(r["event"] == "tool_end" for r in recs) == 2


def test_timeout_resolution_per_tool_override(fake_scope, registry_fake, fake_tools,
                                              tmp_path):
    _, which = fake_tools
    s = dataclasses.replace(fake_scope, limits=dataclasses.replace(
        fake_scope.limits, max_tool_seconds=42, tool_timeouts={"echotool": 7}))
    runner, audit = _runner(s, registry_fake, which, tmp_path)
    runner.run("echotool", ["foo.acme.com"], tmp_path / "o1")              # override
    runner.run("filetool", ["a.acme.com"], tmp_path / "o2")                # default
    runner.run("filetool", ["a.acme.com"], tmp_path / "o3", timeout_s=3)   # explicit
    starts = [(r["tool"], r["timeout_s"]) for r in audit.read_all()
              if r["event"] == "tool_start"]
    assert starts == [("echotool", 7), ("filetool", 42), ("filetool", 3)]


def test_ctrl_c_during_tool_kills_tree_logs_tool_end_and_reraises(
        fake_scope, registry_fake, fake_tools, tmp_path, monkeypatch):
    import reconpilot.runner as rmod

    class _Proc:
        pid = 0
        def communicate(self, timeout=None):
            raise KeyboardInterrupt
    killed = []
    monkeypatch.setattr(rmod, "_spawn", lambda cmd: _Proc())
    monkeypatch.setattr(rmod, "_kill_tree", lambda proc: killed.append(proc))
    _, which = fake_tools
    runner, audit = _runner(fake_scope, registry_fake, which, tmp_path)
    with pytest.raises(KeyboardInterrupt):
        runner.run("echotool", ["foo.acme.com"], tmp_path / "out")
    assert len(killed) == 1
    ends = [r for r in audit.read_all() if r["event"] == "tool_end"]
    assert ends and ends[0]["error"] == "interrupted: KeyboardInterrupt"
