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


# --------------------------------------------------------------------------- #
# limits.max_tool_seconds / limits.tool_timeouts
# --------------------------------------------------------------------------- #
def test_tool_timeout_defaults(eng_dir):
    lim = load_engagement("alpha", eng_dir).limits
    assert lim.max_tool_seconds == 300 and lim.tool_timeouts == {}
    assert lim.tool_timeout("amass") == 300


def test_real_amazon_vrp_gives_amass_its_own_timeout():
    lim = load_engagement("amazon-vrp", REPO_ENGAGEMENTS).limits
    assert lim.tool_timeout("subfinder") == lim.max_tool_seconds == 300
    assert lim.tool_timeout("amass") == 120


def test_tool_timeouts_parsed_and_survive_safe_mode(tmp_path):
    (tmp_path / "t.yaml").write_text(_MIN_YAML.format(name="t") + (
        "limits:\n  max_tool_seconds: 60\n  tool_timeouts:\n    amass: 600\n"))
    lim = load_engagement("t", tmp_path).limits
    assert lim.tool_timeout("amass") == 600 and lim.tool_timeout("x") == 60
    assert lim.effective(force_safe_mode=True).tool_timeout("amass") == 600


@pytest.mark.parametrize("block", [
    "  max_tool_seconds: 0\n",
    "  max_tool_seconds: -5\n",
    "  max_tool_seconds: soon\n",
    "  tool_timeouts:\n    amass: 0\n",
    "  tool_timeouts: [amass]\n",
])
def test_bad_tool_timeouts_fail_loudly(tmp_path, block):
    (tmp_path / "t.yaml").write_text(_MIN_YAML.format(name="t") + "limits:\n" + block)
    with pytest.raises(ConfigError):
        load_engagement("t", tmp_path)


@pytest.fixture
def amazon_copy(tmp_path):
    """The real amazon-vrp.yaml in a temp dir, so CLI tests never touch the
    live engagement's audit log / database."""
    d = tmp_path / "engagements"
    d.mkdir()
    src = REPO_ENGAGEMENTS / "amazon-vrp.yaml"
    (d / "amazon-vrp.yaml").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return d


def test_cli_only_dry_run_plans_subfinder_alone(capsys, tmp_path, amazon_copy):
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-passive", "--dry-run", "--only", "subfinder",
                   "--out", str(tmp_path / "runs")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Running passive_recon (subfinder)" in out
    assert "subfinder" in out and "amass" not in out.split("Running passive_recon", 1)[1]


def test_cli_only_rejects_ineligible_tool(capsys, tmp_path, amazon_copy):
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-passive", "--dry-run", "--only", "httpx",
                   "--out", str(tmp_path / "runs")])
    assert rc == 2
    assert "not eligible" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# dns_resolve / liveness CLI plumbing (offline: dry-run + seam message)
# --------------------------------------------------------------------------- #
def test_cli_run_dns_dry_run_reports_input(capsys, tmp_path, amazon_copy):
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-dns", "--dry-run", "--out", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert rc == 0 and "Running dns_resolve (dnsx)" in out and "DRY RUN" in out


def test_cli_run_liveness_dry_run_reports_input(capsys, tmp_path, amazon_copy):
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-liveness", "--dry-run", "--limit-hosts", "1",
                   "--out", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert rc == 0 and "Running liveness (httpx)" in out and "limit 1" in out


def test_cli_run_liveness_errors_cleanly_when_httpx_absent(capsys, tmp_path, amazon_copy):
    # invoke_tool is wired now. With a registry that has NO httpx, the run fails
    # fast via the tool-availability guard (ToolNotAvailable -> rc 1) and never
    # executes a real tool. Deterministic on any machine (httpx installed or not).
    reg = tmp_path / "tools-no-httpx.yaml"
    reg.write_text(
        "tools:\n"
        "  dnsx:\n"
        "    stage: dns_resolve\n"
        "    binary: dnsx\n"
        "    input: targets_file\n"
        "    output: hosts\n"
        "    active: true\n"
        "    args: \"-l {targets_file} -o {output}\"\n")
    # --host forces one in-scope host so a chunk actually runs (an empty resolved
    # set would yield no chunks and never reach the tool-availability check)
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-liveness", "--host", "www.amazon.com",
                   "--tools", str(reg), "--out", str(tmp_path / "r")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "httpx" in err and "tools.yaml" in err


def test_cli_run_liveness_host_rejects_out_of_scope(capsys, tmp_path, amazon_copy):
    # --host out of scope: rejected up front (rc 2), never runs the tool
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-liveness", "--host", "www.google.com", "--out", str(tmp_path / "r")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "out of scope" in err and "google.com" in err


def test_cli_run_liveness_host_in_scope_dry_run(capsys, tmp_path, amazon_copy):
    # in-scope --host on a dry run: planned, reported as 1 host, no execution
    rc = cli.main(["-e", "amazon-vrp", "--engagements-dir", str(amazon_copy),
                   "--run-liveness", "--host", "www.amazon.com", "--dry-run",
                   "--out", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert rc == 0 and "on 1 host(s)" in out and "--host www.amazon.com" in out


def test_chunk_sizes_parsed_and_validated(tmp_path):
    (tmp_path / "t.yaml").write_text(_MIN_YAML.format(name="t") + (
        "limits:\n  chunk_sizes:\n    liveness: 500\n    dns_resolve: 5000\n"))
    lim = load_engagement("t", tmp_path).limits
    assert lim.chunk_size("liveness", 999) == 500
    assert lim.chunk_size("dns_resolve", 999) == 5000
    assert lim.chunk_size("other", 123) == 123          # falls back to default


@pytest.mark.parametrize("bad", ["    liveness: 0\n", "    liveness: -1\n",
                                 "    liveness: big\n"])
def test_bad_chunk_sizes_fail_loudly(tmp_path, bad):
    (tmp_path / "t.yaml").write_text(_MIN_YAML.format(name="t")
                                     + "limits:\n  chunk_sizes:\n" + bad)
    with pytest.raises(ConfigError):
        load_engagement("t", tmp_path)
