"""Desktop launcher: starts the existing app on a local ephemeral port and stops
it cleanly. No pywebview window is opened (headless) — we test AppServer only."""

import json
import urllib.error
import urllib.request

import pytest

from reconpilot.desktop import HOST, AppServer, _free_port


@pytest.fixture
def engdir(tmp_path):
    d = tmp_path / "engagements"
    d.mkdir()
    (d / "demo.yaml").write_text(
        "engagement:\n  name: demo\n  program_url: https://x.test/demo\n"
        "  authorized_by: t\n  authorized_date: 2026-10-01\n"
        "in_scope:\n  domains: [demo.com]\nallowed_tools: [httpx]\n")
    return d


def _get(url, host_header=None):
    req = urllib.request.Request(url, headers={"host": host_header} if host_header else {})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, json.load(r)


def test_free_port_is_usable():
    p = _free_port()
    assert isinstance(p, int) and 1024 < p < 65536


def test_server_starts_on_localhost_and_serves(engdir):
    server = AppServer(base_dir=engdir)
    try:
        url = server.start()
        # target URL is the LOCAL server (the window will point here)
        assert url == server.url
        assert url.startswith(f"http://{HOST}:")
        assert HOST == "127.0.0.1"
        status, body = _get(url + "/api/engagements")
        assert status == 200 and body["engagements"] == ["demo"]
    finally:
        server.stop()


def test_window_target_host_passes_host_allowlist(engdir):
    # the window loads server.url, whose Host header is 127.0.0.1:<port> -> allowed
    server = AppServer(base_dir=engdir)
    try:
        server.start()
        status, _ = _get(server.url + "/api/engagements",
                         host_header=f"{HOST}:{server.port}")
        assert status == 200
    finally:
        server.stop()


def test_stop_shuts_down_server(engdir):
    server = AppServer(base_dir=engdir)
    url = server.start()
    _get(url + "/api/engagements")          # up
    server.stop()
    # after stop, the port no longer serves
    with pytest.raises(urllib.error.URLError):
        _get(url + "/api/engagements")


def test_stop_cancels_running_jobs(engdir):
    import threading
    gate = threading.Event()

    def long_job(plan, canceller):
        gate.set()
        if canceller.wait(5):
            raise KeyboardInterrupt("run cancelled")
        return {"summary": "x"}

    server = AppServer(base_dir=engdir, executor=long_job)
    try:
        server.start()
        job = server.app.state.jobs.submit("demo", "liveness", {})
        assert gate.wait(2)
        server.stop()
        assert job.wait(3) and job.status == "cancelled"
    finally:
        server.stop()


def test_default_base_dir_not_frozen():
    import reconpilot.desktop as d
    assert d._default_base_dir() == "engagements"      # cwd-relative when not frozen


def test_default_base_dir_frozen(monkeypatch, tmp_path):
    import reconpilot.desktop as d
    fake_exe = tmp_path / "ReconPilot.exe"
    monkeypatch.setattr(d.sys, "frozen", True, raising=False)
    monkeypatch.setattr(d.sys, "executable", str(fake_exe))
    assert d._default_base_dir() == str(tmp_path / "engagements")   # next to the exe
