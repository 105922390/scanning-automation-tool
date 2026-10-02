"""Typed errors so callers can distinguish safety-stops from ordinary failures."""


class ReconPilotError(Exception):
    """Base class for all ReconPilot errors."""


class ConfigError(ReconPilotError):
    """scope.yaml / tools.yaml is missing a required field or is malformed."""


class ScopeViolation(ReconPilotError):
    """A target was rejected by the scope guard. Raised only when a caller
    uses the ``require`` helpers; the plain ``check`` path returns a decision
    object instead so batches can be filtered without exceptions."""


class ToolNotAvailable(ReconPilotError):
    """A requested tool is not in the registry, not allowlisted, or not
    installed. Never auto-resolved — the caller is told the install command."""


class CircuitBreakerTripped(ReconPilotError):
    """A run exceeded ``max_requests_per_run``. Abort rather than hammer."""


class RunnerError(ReconPilotError):
    """A tool invocation could not be built or run (bad template, missing
    required placeholder value, etc.). Distinct from a tool exiting non-zero,
    which is a normal result the caller inspects."""
