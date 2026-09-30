"""R15.3: the Kiro power (D40, ADR-0031).

Kiro's powers are Agent Plugins (kiro.dev/docs/powers/create/, read 2026-09-30):
`plugin.json` at the power's root, `mcp.json` beside it, and `skills/<name>/SKILL.md`.
The manifest's schema is closed; `keywords` are what activate the power. A stdio
server in `mcp.json` takes `type`, `command`, `args`, `env` and `cwd` and nothing
else: a field such as Kiro's own `disabled` or `autoApprove` makes the entry invalid.
A symlink that leaves the power's root is rejected, so the skill is a copy.
Installed from `https://github.com/MaverickHQ/valvur/tree/main/powers/valvur`.
"""

from __future__ import annotations

import json
from pathlib import Path

from test_plugin import _held_to_the_package

REPO = Path(__file__).resolve().parent.parent
POWER = REPO / "powers" / "valvur"
SCHEMA = "https://agent-plugins.org/schemas/1.0.0/"

#: The Agent Plugins 1.0.0 manifest's fields: its schema allows no other.
MANIFEST_FIELDS = {"$schema", "name", "version", "description", "author", "homepage",
                   "repository", "license", "keywords", "extensions"}
#: A stdio server's fields in the spec's `mcp.json`.
STDIO_FIELDS = {"type", "command", "args", "env", "cwd"}


def test_the_manifest_has_the_fields_kiro_requires_and_no_other():
    manifest = json.loads((POWER / "plugin.json").read_text())

    assert set(manifest) <= MANIFEST_FIELDS, set(manifest) - MANIFEST_FIELDS
    assert manifest["$schema"] == SCHEMA + "plugin.schema.json"
    assert manifest["name"] == "valvur" == POWER.name    # Kiro names a power by folder
    assert manifest["description"] and manifest["author"]["name"]
    assert {"security", "scan", "vulnerabilities"} <= set(manifest["keywords"])
    assert manifest["license"] == "Apache-2.0"


def test_its_server_is_kiros_block_as_the_spec_allows_it():
    """Kiro's client block, `uvx --from valvur valvur-mcp`, pinned to the release, with
    `type` and without the fields Kiro's own settings file takes."""
    from valvur.mcp import clients
    from valvur.version import __version__

    config = json.loads((POWER / "mcp.json").read_text())
    server = config["mcpServers"]["valvur"]
    kiro = json.loads(clients.snippet(clients.client("kiro"), version=__version__))

    assert config["$schema"] == SCHEMA + "mcp.schema.json"
    assert set(config) == {"$schema", "mcpServers"} and set(server) <= STDIO_FIELDS
    assert server["type"] == "stdio"
    assert {k: server[k] for k in ("command", "args")} == \
        {k: kiro["mcpServers"]["valvur"][k] for k in ("command", "args")}


def test_the_powers_skill_is_the_packages_byte_for_byte():
    _held_to_the_package(POWER / "skills" / "valvur")
