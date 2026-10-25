"""The official MCP Registry's entry for valvur: `docs/mcp-registry/server.json`.

The registry proves the PyPI package is ours by finding the server's name in PyPI's copy
of the README (`test_pypi_readme.py` holds that line), and a client starts what the
entry's package names. Published by the release's `registry` job, after `promote`
(`test_release_registry.py`); outside the source distribution, since `docs/` is
(`test_build_hash.py`).
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "docs" / "mcp-registry" / "server.json"
#: The format the entry is written to, read on 2026-10-25; a newer one is a decision.
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"


def _entry() -> dict:
    return json.loads(SERVER.read_text())


def _declared() -> str:
    return tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]


def test_the_entry_names_the_server_pypi_s_readme_proves_is_ours():
    [proved] = re.findall(r"<!-- mcp-name: (\S+) -->", (REPO / "README.md").read_text())

    assert _entry()["name"] == proved


def test_a_client_starts_this_release_s_package_as_valvur_mcp_over_stdio():
    """`uvx valvur==<version> mcp`: the CLI's `mcp` command (`test_cli_mcp.py`). The
    package has no entry-point field, so `valvur-mcp` cannot be named here."""
    entry = _entry()

    assert entry["$schema"] == SCHEMA
    assert entry["version"] == _declared()
    assert entry["packages"] == [{
        "registryType": "pypi",
        "identifier": "valvur",
        "version": _declared(),
        "runtimeHint": "uvx",
        "transport": {"type": "stdio"},
        "packageArguments": [{"type": "positional", "value": "mcp"}],
    }]


def test_the_entry_keeps_within_the_registry_s_limits():
    entry = _entry()

    assert 1 <= len(entry["description"]) <= 100
    assert 1 <= len(entry["title"]) <= 100
    assert entry["repository"]["url"] == "https://github.com/MaverickHQ/valvur"
