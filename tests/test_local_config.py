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


def test_a_credential_shaped_value_is_named_by_its_key_and_never_quoted(tmp_path):
    value = "Zq" + "9f" * 10          # built here, so no scanner sees a literal
    ws = _ws(tmp_path, {
        ".claude/settings.local.json": json.dumps({"env": {"GITHUB_TOKEN": value}}),
        ".cursor/mcp.json": json.dumps({"mcpServers": {"api": {
            "url": "https://example.invalid/mcp",
            "headers": {"Authorization": f"Bearer {value}"}}}}),
        # References are portable: the value lives in the environment.
        ".mcp.json": _server("npx", API_KEY="${API_KEY}", DB_PASSWORD="$DB_PASSWORD"),
    })

    found = _exposed(ws)

    assert sorted(found) == [".claude/settings.local.json", ".cursor/mcp.json"]
    assert "GITHUB_TOKEN" in found[".claude/settings.local.json"]["title"]
    assert "Authorization" in found[".cursor/mcp.json"]["title"]
    assert not any(value in json.dumps(f) for f in found.values()), "the value was quoted"


def test_a_file_holding_both_is_one_finding(tmp_path):
    value = "Zq" + "9f" * 10
    ws = _ws(tmp_path, {".mcp.json": _server("/home/alice/bin/tool", SERVICE_TOKEN=value)})

    [finding] = _exposed(ws).values()

    assert "absolute local path" in finding["title"] and "SERVICE_TOKEN" in finding["title"]


# ---------------------------------------- the host decides what git ignores

def test_a_file_git_ignores_is_not_reported_and_one_it_would_publish_is(tmp_path, monkeypatch):
    """Through a real scan: the Check reads both, because the File Set keeps ignored
    agent configuration for its hooks (ADR-0021); the host drops the one git
    ignores. `.claude/settings.local.json` is untracked and not ignored: one
    `git add -A` publishes it, which is what the owner's audit found."""
    import subprocess

    from valvur import api, cache
    from valvur.adapters.check import CheckAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    # This machine's own ignores are not the test's: Claude Code's global one lists
    # `**/.claude/settings.local.json`, which is exactly a file git then ignores.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "gitconfig"))
    ws = _ws(tmp_path / "ws", {
        ".gitignore": ".mcp.json\n",
        ".mcp.json": _server("/Users/me/tools/run-tool"),
        ".claude/settings.local.json": json.dumps(
            {"permissions": {"allow": ["Read(/home/me/notes/**)"]}}),
    })
    subprocess.run(["git", "init", "-q", str(ws)], check=True)
    subprocess.run(["git", "-C", str(ws), "add", ".gitignore"], check=True)

    run = api.scan(ws, runner=LocalRuntime(), adapters=[CheckAdapter("ai-artifact")])

    assert [f.path for f in run.findings if f.rule == RULE] == [".claude/settings.local.json"]
