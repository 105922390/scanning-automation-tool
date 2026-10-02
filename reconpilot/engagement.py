"""Engagement selection: map a program *name* to its scope file.

One scope file per program lives under ``engagements/``. The active engagement
is chosen by name (``--engagement <name>`` on the CLI, a dropdown in the GUI
later). No program-specific knowledge lives in code — this module only resolves
and loads ``engagements/<name>.yaml``.

Fail-closed by design (see build item 5): an unknown or unsafe name is an error,
never a silent fallback to some default scope. A missing/typo'd engagement must
make the app do *less*, not quietly scan something it shouldn't.
"""

from __future__ import annotations

import re
from pathlib import Path

from .config import Scope, load_scope
from .errors import ConfigError

DEFAULT_DIR = "engagements"
_EXTS = (".yaml", ".yml")

# A safe engagement name: starts alphanumeric, then alnum / dot / dash / underscore.
# This rejects path traversal ("..", "/", "\\") and absolute paths outright.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _dir(base: str | Path = DEFAULT_DIR) -> Path:
    return Path(base)


def list_engagements(base: str | Path = DEFAULT_DIR) -> list[str]:
    """Sorted, de-duplicated engagement names available under ``base``."""
    d = _dir(base)
    if not d.is_dir():
        return []
    names = {p.stem for p in d.iterdir()
             if p.is_file() and p.suffix.lower() in _EXTS}
    return sorted(names)


def resolve_path(name: str, base: str | Path = DEFAULT_DIR) -> Path:
    """Resolve an engagement name to its scope file. Raises ConfigError if the
    name is unsafe or no matching file exists (fail-closed, no default)."""
    if not name or not _SAFE_NAME.match(name):
        raise ConfigError(
            f"invalid engagement name {name!r}: use letters, digits, '.', '-', '_' "
            "(no paths or '..')")
    d = _dir(base)
    for ext in _EXTS:
        p = d / f"{name}{ext}"
        if p.is_file():
            return p
    available = list_engagements(base)
    hint = f" available: {', '.join(available)}" if available else " (none found)"
    raise ConfigError(f"engagement {name!r} not found in {d}/.{hint}")


def load_engagement(name: str, base: str | Path = DEFAULT_DIR) -> Scope:
    """Resolve + load + validate the named engagement into a :class:`Scope`."""
    return load_scope(resolve_path(name, base))
