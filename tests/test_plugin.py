"""R15.2: the Claude Code plugin (D40, F9.13, ADR-0031).

The repository is its own marketplace: `.claude-plugin/marketplace.json` lists one
plugin, `plugins/valvur/`, which carries the skill and valvur's MCP server pinned to
the release. `/plugin marketplace add MaverickHQ/valvur`, then
`/plugin install valvur@valvur`, gives both. The plugin is copied into Claude Code's
cache when it is installed, and a symlink under its `skills/` is skipped, so the
skill is a copy that a test holds byte for byte to the package's.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MARKETPLACE = REPO / ".claude-plugin" / "marketplace.json"
PLUGIN = REPO / "plugins" / "valvur"


def test_the_repository_is_a_marketplace_listing_the_plugin():
    marketplace = json.loads(MARKETPLACE.read_text())

    assert marketplace["name"] == "valvur"          # `/plugin install valvur@valvur`
    assert marketplace["owner"]["name"]
    [entry] = marketplace["plugins"]
    assert entry["name"] == "valvur" and entry["source"] == "./plugins/valvur"
    assert (REPO / entry["source"]).resolve() == PLUGIN


def test_the_plugins_manifest_names_it_and_says_what_it_is():
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())

    assert manifest["name"] == "valvur"
    assert manifest["license"] == "Apache-2.0"
    assert manifest["description"] and manifest["repository"].endswith("/valvur")


@pytest.mark.skipif(shutil.which("claude") is None, reason="no Claude Code CLI here")
@pytest.mark.parametrize("path", [PLUGIN, REPO], ids=["plugin", "marketplace"])
def test_claude_code_validates_it_strictly(path):
    """`claude plugin validate --strict`: what the runtime tolerates, such as an
    unrecognised field or missing metadata, fails here."""
    checked = subprocess.run(["claude", "plugin", "validate", "--strict", str(path)],
                             capture_output=True, text=True, timeout=120, check=False)

    assert checked.returncode == 0, checked.stdout + checked.stderr
