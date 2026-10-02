"""Load and validate scope.yaml and tools.yaml into typed objects.

Everything downstream consumes these dataclasses, never the raw dicts, so a
malformed engagement file fails loudly here instead of deep inside a tool run.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError


# --------------------------------------------------------------------------- #
# Limits
# --------------------------------------------------------------------------- #
DEFAULT_MAX_TOOL_SECONDS = 300


@dataclass(frozen=True)
class Limits:
    max_rps_per_host: float
    max_global_concurrency: int
    max_requests_per_run: int
    safe_mode: bool
    # Wall-clock cap on ONE tool invocation; on expiry the runner kills the
    # process tree and moves on. tool_timeouts overrides it per tool (e.g. amass).
    max_tool_seconds: int = DEFAULT_MAX_TOOL_SECONDS
    tool_timeouts: dict[str, int] = field(default_factory=dict)

    def tool_timeout(self, tool: str) -> int:
        return self.tool_timeouts.get(tool, self.max_tool_seconds)

    def effective(self, force_safe_mode: bool = False) -> "Limits":
        """Return the limits actually enforced at runtime.

        safe_mode (from scope.yaml or the global --safe-mode flag) halves the
        per-host rate and global concurrency, flooring each at a sane minimum.
        """
        safe = self.safe_mode or force_safe_mode
        if not safe:
            return self
        return replace(
            self,
            max_rps_per_host=max(0.5, self.max_rps_per_host / 2),
            max_global_concurrency=max(1, self.max_global_concurrency // 2),
            safe_mode=True,
        )


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Engagement:
    name: str
    program_url: str
    platform: str
    authorized_by: str
    authorized_date: str
    notes: str = ""


@dataclass(frozen=True)
class Posture:
    allow_active_exploitation: bool = False
    allow_bruteforce: bool = False
    allow_form_submission: bool = False
    require_plan_confirmation: bool = True


# Placeholder markers that mean "the user hasn't filled in the user_agent yet".
_UA_PLACEHOLDERS = ("your_h1_username",)


@dataclass(frozen=True)
class Http:
    """HTTP behavior policy for active tools (optional ``http:`` block)."""
    user_agent: str = ""
    require_user_agent: bool = False
    no_third_party_oob: bool = False
    drop_on_redirect_to: tuple[str, ...] = ()

    def user_agent_is_valid(self) -> bool:
        """True only if a real UA is set — not blank and not a template placeholder."""
        ua = self.user_agent.strip()
        if not ua:
            return False
        low = ua.lower()
        return not any(ph in low for ph in _UA_PLACEHOLDERS)


@dataclass(frozen=True)
class Scope:
    engagement: Engagement
    in_scope_domains: tuple[str, ...]
    in_scope_cidrs: tuple[str, ...]
    out_of_scope_domains: tuple[str, ...]
    out_of_scope_cidrs: tuple[str, ...]
    limits: Limits
    allowed_tools: frozenset[str]
    posture: Posture
    # Label-based out-of-scope rules (optional). Needles are stored lowercased.
    out_of_scope_host_label_contains: tuple[str, ...] = ()
    out_of_scope_host_label_equals: tuple[str, ...] = ()
    http: Http = Http()


def _require(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d or d[key] is None:
        raise ConfigError(f"{where}: missing required key '{key}'")
    return d[key]


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise ConfigError(f"expected a list, got {type(v).__name__}: {v!r}")
    return [str(x).strip() for x in v if str(x).strip()]


def _positive_int(v: Any, where: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
        raise ConfigError(f"{where}: expected a positive integer (seconds), got {v!r}")
    return v


def _tool_timeouts(v: Any) -> dict[str, int]:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ConfigError(f"limits.tool_timeouts: expected a mapping tool -> seconds, got {v!r}")
    return {str(k): _positive_int(n, f"limits.tool_timeouts.{k}") for k, n in v.items()}


def load_scope(path: str | Path) -> Scope:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"scope file not found: {path}")
    raw = yaml.safe_load(path.read_text()) or {}

    eng = _require(raw, "engagement", "scope.yaml")
    engagement = Engagement(
        name=str(_require(eng, "name", "engagement")),
        program_url=str(_require(eng, "program_url", "engagement")),
        platform=str(eng.get("platform", "unknown")),
        authorized_by=str(_require(eng, "authorized_by", "engagement")),
        authorized_date=str(_require(eng, "authorized_date", "engagement")),
        notes=str(eng.get("notes", "") or ""),
    )

    in_scope = raw.get("in_scope") or {}
    out_scope = raw.get("out_of_scope") or {}
    lim = raw.get("limits") or {}
    pos = raw.get("posture") or {}
    http_raw = raw.get("http") or {}
    http = Http(
        user_agent=str(http_raw.get("user_agent", "") or ""),
        require_user_agent=bool(http_raw.get("require_user_agent", False)),
        no_third_party_oob=bool(http_raw.get("no_third_party_oob", False)),
        drop_on_redirect_to=tuple(_as_list(http_raw.get("drop_on_redirect_to"))),
    )

    limits = Limits(
        max_rps_per_host=float(lim.get("max_rps_per_host", 2)),
        max_global_concurrency=int(lim.get("max_global_concurrency", 10)),
        max_requests_per_run=int(lim.get("max_requests_per_run", 50000)),
        safe_mode=bool(lim.get("safe_mode", True)),
        max_tool_seconds=_positive_int(
            lim.get("max_tool_seconds", DEFAULT_MAX_TOOL_SECONDS), "limits.max_tool_seconds"),
        tool_timeouts=_tool_timeouts(lim.get("tool_timeouts")),
    )

    allowed = frozenset(_as_list(raw.get("allowed_tools")))
    if not allowed:
        raise ConfigError("scope.yaml: allowed_tools must list at least one tool")

    scope = Scope(
        engagement=engagement,
        in_scope_domains=tuple(_as_list(in_scope.get("domains"))),
        in_scope_cidrs=tuple(_as_list(in_scope.get("cidrs"))),
        out_of_scope_domains=tuple(_as_list(out_scope.get("domains"))),
        out_of_scope_cidrs=tuple(_as_list(out_scope.get("cidrs"))),
        out_of_scope_host_label_contains=tuple(
            s.lower() for s in _as_list(out_scope.get("host_label_contains"))),
        out_of_scope_host_label_equals=tuple(
            s.lower() for s in _as_list(out_scope.get("host_label_equals"))),
        http=http,
        limits=limits,
        allowed_tools=allowed,
        posture=Posture(
            allow_active_exploitation=bool(pos.get("allow_active_exploitation", False)),
            allow_bruteforce=bool(pos.get("allow_bruteforce", False)),
            allow_form_submission=bool(pos.get("allow_form_submission", False)),
            require_plan_confirmation=bool(pos.get("require_plan_confirmation", True)),
        ),
    )
    if not scope.in_scope_domains and not scope.in_scope_cidrs:
        raise ConfigError("scope.yaml: in_scope has no domains or cidrs — nothing is authorized")
    return scope


# --------------------------------------------------------------------------- #
# Tool registry
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ToolSpec:
    name: str
    stage: str
    binary: str
    input: str
    output: str
    active: bool
    args: str
    install: str
    templates_default: str = ""
    # HTTP policy hooks (item 3). Appended by the runner for active tools:
    ua_arg: str = ""          # how this tool takes a custom User-Agent, e.g. "-H 'User-Agent: {user_agent}'"
    no_oob_arg: str = ""      # flag(s) disabling third-party callbacks, e.g. "-no-interactsh"
    requires_oob: bool = False  # tool can ONLY work via a third-party callback -> skip when OOB disabled
    resolver: bool = False    # active, but queries public DNS resolvers (dnsx), NOT the target
                              # -> exempt from the per-host limiter + request breaker


def load_tools(path: str | Path) -> dict[str, ToolSpec]:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"tools file not found: {path}")
    raw = yaml.safe_load(path.read_text()) or {}
    tools = raw.get("tools") or {}
    if not tools:
        raise ConfigError("tools.yaml: no tools defined under 'tools:'")
    out: dict[str, ToolSpec] = {}
    for name, spec in tools.items():
        if not isinstance(spec, dict):
            raise ConfigError(f"tools.yaml: tool '{name}' must be a mapping")
        out[name] = ToolSpec(
            name=name,
            stage=str(_require(spec, "stage", f"tool {name}")),
            binary=str(_require(spec, "binary", f"tool {name}")),
            input=str(_require(spec, "input", f"tool {name}")),
            output=str(_require(spec, "output", f"tool {name}")),
            active=bool(spec.get("active", True)),
            args=str(_require(spec, "args", f"tool {name}")),
            install=str(spec.get("install", "")),
            templates_default=str(spec.get("templates_default", "")),
            ua_arg=str(spec.get("ua_arg", "") or ""),
            no_oob_arg=str(spec.get("no_oob_arg", "") or ""),
            requires_oob=bool(spec.get("requires_oob", False)),
            resolver=bool(spec.get("resolver", False)),
        )
    return out
