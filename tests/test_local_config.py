"""R5.3: local agent configuration that would leak (F3.6).

The owner's audit of 2026-09-27 found an untracked `.mcp.json` holding a private
path, not gitignored, and `.claude/settings.local.json` not ignored; valvur reported
neither. A local configuration file that git would publish, holding an absolute
local path or a credential-shaped value, is a medium Finding. The Check reads the
Snapshot, which holds ignored agent configuration on purpose (ADR-0021), so the
host, which has git, drops the Finding when git ignores the file.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.checks.ai_artifact import AiArtifactCheck

RULE = "valvur.ai-artifact.local-config-exposed"


def _ws(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


def _server(command: str, **env: str) -> str:
    spec: dict = {"command": command, "args": ["--stdio"]}
    if env:
        spec["env"] = env
    return json.dumps({"mcpServers": {"tool": spec}}, indent=2)


def _exposed(workspace: Path) -> dict[str, dict]:
    return {f["path"]: f for f in AiArtifactCheck().run(workspace) if f["rule"] == RULE}


def test_an_absolute_local_path_in_local_agent_configuration_is_a_medium_finding(tmp_path):
    ws = _ws(tmp_path, {
        ".mcp.json": _server("/Users/example/tools/run-tool"),
        ".claude/settings.local.json": json.dumps(
            {"permissions": {"allow": ["Read(/home/alice/notes/**)"]}}),
        ".kiro/settings/mcp.json": _server("C:\\Users\\bob\\bin\\tool.exe"),
        # Portable: nothing of this machine in it.
        ".roo/mcp.json": _server("npx", HOME_DIR="${HOME}"),
    })

    found = _exposed(ws)

    assert sorted(found) == [".claude/settings.local.json", ".kiro/settings/mcp.json",
                             ".mcp.json"]
    assert {f["severity"] for f in found.values()} == {"medium"}
    assert "absolute local path" in found[".mcp.json"]["title"]
