"""Shared ingest helpers for stages that run a tool and parse its output file."""

from __future__ import annotations

from typing import Callable, Optional


def choose_output(inv, parse_fn: Callable[[str], list]) -> Optional[str]:
    """Pick which output path of an invocation to ingest.

    Normally the tool's own output file (``-o {output}``). But a tool that writes
    its own file (dnsx, httpx) may be KILLED on timeout before it flushes that
    file, leaving it empty while the partial results actually captured live in the
    stdout sidecar ``<output>.log`` (the runner always writes captured stdout
    there for self-writing tools). So on a timeout, if the primary file has no
    parseable records, fall back to the sidecar. This ensures a tool_timeout never
    silently discards work that was captured.
    """
    path = inv.output_path
    if not path:
        return None
    if getattr(inv, "timed_out", False) and not parse_fn(path):
        alt = str(path) + ".log"
        if parse_fn(alt):
            return alt
    return path
