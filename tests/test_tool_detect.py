"""Tool allowlist + detection: no silent skips, no substitutions."""

import pytest

from reconpilot.errors import ToolNotAvailable
from reconpilot.tool_detect import detect_all, detect_tool, require_tool


def _which_only(*present):
    present = set(present)
    return lambda binary: f"/usr/local/bin/{binary}" if binary in present else None


def test_available_when_registered_allowlisted_and_installed(scope, registry):
    which = _which_only("subfinder")
    s = detect_tool("subfinder", registry, scope, which=which)
    assert s.available and s.reason == "ok"
    assert s.path == "/usr/local/bin/subfinder"


def test_missing_binary_reports_install_command(scope, registry):
    which = _which_only()   # nothing installed
    s = detect_tool("httpx", registry, scope, which=which)
    assert not s.available and s.reason == "not_installed"
    assert "go install" in s.install


def test_not_in_registry(scope, registry):
    # 'nuclei' is allowlisted in the fixture scope but absent from the registry
    s = detect_tool("nuclei", registry, scope, which=_which_only("nuclei"))
    assert not s.available and s.reason == "not_in_registry"


def test_in_registry_but_not_allowlisted(scope, registry):
    # 'ffuf' is in the registry but not in scope.allowed_tools
    s = detect_tool("ffuf", registry, scope, which=_which_only("ffuf"))
    assert not s.available and s.reason == "not_allowlisted"


def test_detect_all_covers_every_allowlisted_tool(scope, registry):
    statuses = detect_all(registry, scope, which=_which_only("subfinder", "httpx-binary-xyz"))
    assert set(statuses) == set(scope.allowed_tools)
    assert statuses["subfinder"].available
    assert statuses["httpx"].available          # resolved via its binary name
    assert not statuses["nuclei"].available     # not in registry


@pytest.mark.parametrize("name,needle", [
    ("nuclei", "not defined in tools.yaml"),
    ("ffuf", "not in this engagement's allowed_tools"),
    ("httpx", "not installed"),
])
def test_require_tool_raises_actionable(scope, registry, name, needle):
    with pytest.raises(ToolNotAvailable) as exc:
        require_tool(name, registry, scope, which=_which_only())
    assert needle in str(exc.value)


def test_require_tool_returns_status_when_ok(scope, registry):
    s = require_tool("subfinder", registry, scope, which=_which_only("subfinder"))
    assert s.available
