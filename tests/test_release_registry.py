"""1.6.0: the release publishes the MCP Registry's entry, so the owner doesn't.

The official MCP Registry lists a server from its `server.json`, published by
`mcp-publisher`. In 1.5.4's design the owner ran it after each release, a fourth owner
action. The registry also takes a GitHub Actions OIDC login for a repository's own
`io.github.<owner>/*` names: no secret, no account step (its `github-actions.mdx`,
read 2026-10-25). `registry` runs after `promote`, so PyPI already serves the version
the registry starts with `uvx valvur==<version> mcp`. It runs as its own job, so a
failure there leaves the release whole and the job alone can be re-run.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RELEASE = REPO / ".github" / "workflows" / "release.yml"
RELEASING = REPO / "docs" / "RELEASING.md"
#: v1.8.1, 2026-08-06: the newest release past the 7-day cooldown on 2026-10-25, and
#: the one the registry's own guide names. Its signature verified on this Mac that day.
PUBLISHER = "v1.8.1"
PUBLISHER_SHA256 = "a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc"


def _job(name: str) -> str:
    text = RELEASE.read_text()
    start = re.search(rf"^  {re.escape(name)}:\n", text, re.M)
    assert start, f"no job {name}"
    end = re.search(r"^  [a-z][a-z-]*:\n", text[start.end():], re.M)
    return text[start.start(): start.end() + (end.start() if end else len(text))]


def _runs(job: str) -> list[str]:
    return re.findall(r"run: \|\n((?:\s{10,}.*\n|\n)+)", job) + re.findall(r"run: (\S.*)\n", job)


def test_registry_follows_promote_and_never_runs_in_a_rehearsal():
    """A rehearsal's `.devN` goes to TestPyPI, which the registry never reads, and a
    rehearsal must publish nothing anyone can install."""
    registry = _job("registry")

    assert re.search(r"needs: \[verify, promote\]\n", registry)
    assert "if: github.event_name != 'workflow_dispatch'\n" in registry
    assert "environment:" not in registry, "the brake is promote's, before it"


def test_registry_holds_only_what_the_oidc_login_needs():
    registry = _job("registry")
    grant = re.search(r"    permissions:\n((?:      .*\n)+)", registry)

    assert grant, "no job-level permissions"
    lines = sorted(line.split("#")[0].strip() for line in grant[1].splitlines())
    assert lines == ["contents: read", "id-token: write"], lines
    assert "secrets." not in registry, "the OIDC login needs no secret"


def test_registry_runs_mcp_publisher_only_once_its_digest_and_signature_check():
    registry = _job("registry")

    assert f"MCP_PUBLISHER_VERSION: {PUBLISHER}\n" in registry
    assert f"MCP_PUBLISHER_SHA256: {PUBLISHER_SHA256}\n" in registry
    code = "\n".join(line for line in registry.splitlines() if not line.lstrip().startswith("#"))
    assert "releases/latest" not in code, "a mutable URL"
    assert 'sha256sum -c -' in registry
    assert ("--certificate-identity \"https://github.com/modelcontextprotocol/registry/"
            ".github/workflows/release.yml@refs/tags/$MCP_PUBLISHER_VERSION\"") in registry
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in registry
    first_use = registry.index("./mcp-publisher")
    assert registry.index("sha256sum -c -") < first_use
    assert registry.index("cosign verify-blob") < first_use


def test_registry_publishes_the_entry_that_names_this_release_once_pypi_serves_it():
    registry = _job("registry")

    check = registry.index('jq -e --arg v "$VERSION"')
    wait = registry.index('https://pypi.org/pypi/valvur/$VERSION/json')
    login = registry.index("./mcp-publisher login github-oidc")
    publish = registry.index("./mcp-publisher publish docs/mcp-registry/server.json")
    assert check < wait < login < publish


def test_no_expression_is_expanded_inside_a_registry_run_block():
    """Values reach the shell through `env:`, as zizmor's template-injection audit asks."""
    for block in _runs(_job("registry")):
        assert "${{" not in block, block


def test_releasing_says_the_release_publishes_the_entry():
    text = RELEASING.read_text()
    section = text[text.index("### After a release: the MCP Registry"):]
    section = section[:section.index("\n### ", 1)]

    assert "`registry`" in section
    assert "mcp-publisher login github\n" not in section, "the owner's device-flow login"
