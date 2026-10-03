"""Launch the read-only dashboard, bound to localhost ONLY.

    python -m reconpilot.web [--port 8000] [--engagements-dir engagements]

The host is hard-pinned to 127.0.0.1 and is NOT configurable — the dashboard must
never be exposed on 0.0.0.0 / a LAN interface.
"""

from __future__ import annotations

import argparse

import uvicorn

from ..engagement import DEFAULT_DIR
from .app import create_app

HOST = "127.0.0.1"   # local only — never 0.0.0.0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="reconpilot.web",
                                description="ReconPilot read-only dashboard (localhost only).")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--engagements-dir", default=DEFAULT_DIR)
    args = p.parse_args(argv)

    app = create_app(base_dir=args.engagements_dir)
    print(f"ReconPilot dashboard: http://{HOST}:{args.port}  (local only)")
    uvicorn.run(app, host=HOST, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
