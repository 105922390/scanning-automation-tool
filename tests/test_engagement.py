"""Engagement selector: listing, safe name resolution, fail-closed loading, CLI."""

from pathlib import Path

import pytest

from reconpilot import cli
from reconpilot.engagement import list_engagements, load_engagement, resolve_path
from reconpilot.errors import ConfigError

# The real engagements/ dir shipped with the repo.
REPO_ENGAGEMENTS = Path(__file__).resolve().parent.parent / "engagements"

_MIN_YAML = """
engagement:
  name: "{name}"
  program_url: "https://example.test/{name}"
  authorized_by: "tester"
  authorized_date: "2026-10-01"
in_scope:
  domains: ["{name}.com"]
allowed_tools: ["httpx"]
"""


@pytest.fixture
def eng_dir(tmp_path):
    d = tmp_path / "engagements"
    d.mkdir()
    (d / "alpha.yaml").write_text(_MIN_YAML.format(name="alpha"))
    (d / "beta.yml").write_text(_MIN_YAML.format(name="beta"))
    (d / "notes.txt").write_text("ignore me")   # non-yaml ignored
    return d


# --------------------------------------------------------------------------- #
# listing
# --------------------------------------------------------------------------- #
def test_list_engagements(eng_dir):
    assert list_engagements(eng_dir) == ["alpha", "beta"]


def test_list_missing_dir_is_empty(tmp_path):
    assert list_engagements(tmp_path / "nope") == []


def test_real_repo_has_amazon_vrp():
    assert "amazon-vrp" in list_engagements(REPO_ENGAGEMENTS)


# --------------------------------------------------------------------------- #
# resolution + loading
# --------------------------------------------------------------------------- #
def test_resolve_prefers_yaml_then_yml(eng_dir):
    assert resolve_path("alpha", eng_dir).name == "alpha.yaml"
    assert resolve_path("beta", eng_dir).name == "beta.yml"


def test_load_engagement(eng_dir):
    scope = load_engagement("alpha", eng_dir)
    assert scope.engagement.name == "alpha"
    assert "alpha.com" in scope.in_scope_domains


def test_load_real_amazon_vrp():
    scope = load_engagement("amazon-vrp", REPO_ENGAGEMENTS)
    assert scope.engagement.name == "amazon-vrp"
    assert "*.amazon.com" in scope.in_scope_domains


# --------------------------------------------------------------------------- #
# fail-closed: unknown / unsafe names never fall back to a default
# --------------------------------------------------------------------------- #
def test_missing_engagement_raises(eng_dir):
    with pytest.raises(ConfigError) as e:
        load_engagement("ghost", eng_dir)
    assert "not found" in str(e.value)


@pytest.mark.parametrize("bad", ["../secrets", "a/b", "..", "/etc/passwd", ".hidden", ""])
def test_unsafe_names_rejected(eng_dir, bad):
    with pytest.raises(ConfigError):
        resolve_path(bad, eng_dir)


def test_traversal_cannot_escape_dir(tmp_path):
    # a real file exists one level up; traversal name must still be refused
    (tmp_path / "secret.yaml").write_text(_MIN_YAML.format(name="secret"))
    d = tmp_path / "engagements"
    d.mkdir()
    with pytest.raises(ConfigError):
        resolve_path("../secret", d)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_list(eng_dir, capsys):
    rc = cli.main(["--list", "--engagements-dir", str(eng_dir)])
    out = capsys.readouterr().out
    assert rc == 0 and "alpha" in out and "beta" in out


def test_cli_selects_and_summarizes(eng_dir, capsys):
    rc = cli.main(["-e", "alpha", "--engagements-dir", str(eng_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Active engagement : alpha" in out
    assert "in-scope" in out and "allowed tools" in out


def test_cli_safe_mode_halves(eng_dir, capsys):
    # alpha has default limits (rps 2 from config defaults, safe_mode default True)
    rc = cli.main(["-e", "alpha", "--engagements-dir", str(eng_dir), "--safe-mode"])
    assert rc == 0
    assert "(safe_mode)" in capsys.readouterr().out


def test_cli_missing_engagement_is_error(eng_dir, capsys):
    rc = cli.main(["-e", "ghost", "--engagements-dir", str(eng_dir)])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_cli_requires_engagement_or_list(capsys):
    rc = cli.main([])
    assert rc == 2
    assert "required" in capsys.readouterr().err
