"""Shared fixtures. Builds Scope objects in-memory so tests never need YAML."""

import pytest

from reconpilot.config import Engagement, Limits, Posture, Scope, ToolSpec


@pytest.fixture
def scope():
    return Scope(
        engagement=Engagement(
            name="test-eng",
            program_url="https://example.test/program",
            platform="self-hosted",
            authorized_by="tester",
            authorized_date="2026-10-01",
        ),
        in_scope_domains=("acme.com", "*.acme.com", "*.acme-api.com"),
        in_scope_cidrs=("203.0.113.0/24",),
        out_of_scope_domains=("*.internal.acme.com", "legacy.acme.com", "blog.acme.com"),
        out_of_scope_cidrs=("203.0.113.128/25",),
        limits=Limits(max_rps_per_host=4, max_global_concurrency=8,
                      max_requests_per_run=100, safe_mode=False),
        allowed_tools=frozenset({"subfinder", "httpx", "nuclei"}),
        posture=Posture(),
    )


@pytest.fixture
def registry():
    return {
        "subfinder": ToolSpec("subfinder", "passive_recon", "subfinder",
                              "domain", "subdomains", False,
                              "-d {target} -o {output}", "go install .../subfinder"),
        "httpx": ToolSpec("httpx", "liveness", "httpx-binary-xyz",
                          "targets_file", "hosts", True,
                          "-l {targets_file} -o {output}", "go install .../httpx"),
        # 'nuclei' is allowlisted but intentionally absent from the registry
        # in some tests; 'ffuf' is in the registry but not allowlisted.
        "ffuf": ToolSpec("ffuf", "content_discovery", "ffuf",
                         "urls_file", "urls", True,
                         "-u {target}/FUZZ -o {output}", "go install .../ffuf"),
    }
