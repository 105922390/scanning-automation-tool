"""Desktop app: the EXISTING web UI in a native window (pywebview).

This wraps — it does not rewrite — the FastAPI app. It starts that app on a
background thread bound to 127.0.0.1 on an ephemeral free port (all existing guards
intact: localhost bind, Host-header allowlist, no-store), waits until it's serving,
then opens a pywebview window pointing at it. Closing the window stops the server AND
cancels any running background job, killing child tool processes.

    python -m reconpilot.desktop
"""

from __future__ import annotations

import socket
import threading
import time

import uvicorn

from .engagement import DEFAULT_DIR
from .web.app import ALLOWED_HOSTS, create_app

HOST = "127.0.0.1"          # local only — never 0.0.0.0
WINDOW_TITLE = "ReconPilot"
DEFAULT_SIZE = (1200, 820)


def _free_port() -> int:
    """Ask the OS for an unused local port, then release it for uvicorn to bind."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST, 0))
        return s.getsockname()[1]
    finally:
        s.close()


class AppServer:
    """Runs the FastAPI app under uvicorn on a background thread, with clean stop."""

    def __init__(self, base_dir: str = DEFAULT_DIR, port: int | None = None,
                 executor=None):
        self.host = HOST
        self.port = port or _free_port()
        self.app = create_app(base_dir=base_dir, allowed_hosts=ALLOWED_HOSTS,
                              executor=executor)
        self._server = uvicorn.Server(uvicorn.Config(
            self.app, host=self.host, port=self.port, log_level="warning"))
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self, timeout: float = 15.0) -> str:
        """Start serving on a background thread; block until it's up. Returns url."""
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._server.started:
                return self.url
            time.sleep(0.05)
        raise RuntimeError(f"server did not start within {timeout}s")

    def stop(self, timeout: float = 10.0) -> None:
        """Cancel any running job (kills child tool trees), then stop the server."""
        try:
            self.app.state.jobs.stop_all()
        except Exception:         # noqa: BLE001 - never let shutdown cleanup raise
            pass
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=timeout)


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="reconpilot.desktop",
                                description="ReconPilot desktop app (local only).")
    p.add_argument("--engagements-dir", default=DEFAULT_DIR)
    args = p.parse_args(argv)

    server = AppServer(base_dir=args.engagements_dir)
    server.start()
    print(f"ReconPilot desktop: {server.url}  (local only)")

    import webview        # imported here so tests / headless use don't require it
    icon = _icon_path()
    window_kwargs = {"width": DEFAULT_SIZE[0], "height": DEFAULT_SIZE[1]}
    webview.create_window(WINDOW_TITLE, server.url, **window_kwargs)
    try:
        # when webview.start() returns, the window has been closed
        webview.start(icon=icon) if icon else webview.start()
    finally:
        server.stop()
    return 0


def _icon_path():
    from pathlib import Path
    p = Path(__file__).parent / "web" / "static" / "icon.png"
    return str(p) if p.exists() else None


if __name__ == "__main__":
    raise SystemExit(main())
