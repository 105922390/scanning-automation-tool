"""Tool allowlist + presence detection. Never auto-installs, never substitutes.

A tool may run only if it is (a) defined in tools.yaml, (b) listed in the
engagement's allowed_tools, and (c) found on PATH. Any failure yields a status
that tells the operator exactly why and, if missing, the install command.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Callable, Optional

from .config import Scope, ToolSpec
from .errors import ToolNotAvailable


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    reason: str                     # "ok" | "not_in_registry" | "not_allowlisted" | "not_installed"
    path: Optional[str] = None      # resolved binary path when available
    install: str = ""               # install command, shown verbatim when missing


Which = Callable[[str], Optional[str]]


def detect_tool(name: str, registry: dict[str, ToolSpec], scope: Scope,
                which: Which = shutil.which) -> ToolStatus:
    """Resolve one tool's runnability. ``which`` is injectable for tests."""
    spec = registry.get(name)
    if spec is None:
        return ToolStatus(name, False, "not_in_registry")
    if name not in scope.allowed_tools:
        return ToolStatus(name, False, "not_allowlisted", install=spec.install)
    path = which(spec.binary)
    if not path:
        return ToolStatus(name, False, "not_installed", install=spec.install)
    return ToolStatus(name, True, "ok", path=path, install=spec.install)


def detect_all(registry: dict[str, ToolSpec], scope: Scope,
               which: Which = shutil.which) -> dict[str, ToolStatus]:
    """Status for every allowlisted tool — the GUI's readiness panel."""
    return {name: detect_tool(name, registry, scope, which=which)
            for name in sorted(scope.allowed_tools)}


def require_tool(name: str, registry: dict[str, ToolSpec], scope: Scope,
                 which: Which = shutil.which) -> ToolStatus:
    """Like :func:`detect_tool` but raises with an actionable message. The
    runner calls this immediately before building a command line."""
    status = detect_tool(name, registry, scope, which=which)
    if status.available:
        return status
    if status.reason == "not_in_registry":
        raise ToolNotAvailable(f"'{name}' is not defined in tools.yaml")
    if status.reason == "not_allowlisted":
        raise ToolNotAvailable(
            f"'{name}' is not in this engagement's allowed_tools (scope.yaml)")
    raise ToolNotAvailable(
        f"'{name}' is not installed. Install it with:\n    {status.install}")
