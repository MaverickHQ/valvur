"""R18.4: the hook, shipped in the plugin (D40, D44).

The plugin declares one `PreToolUse` hook on `Bash` in `hooks/hooks.json`
(code.claude.com/docs/en/plugins/manifest-reference.md, read 2026-10-02). Its command is
`hooks/pre-tool-use.sh`, which starts valvur only when the command names an installer:
the pinned `uvx --from valvur==<version> valvur-hook` costs about 0.45 s warm (R18.1),
too much before every shell command an agent runs. `VALVUR_HOOK` points the script at
another `valvur-hook`, such as this checkout's, which the tests and the smoke run use.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PLUGIN = REPO / "plugins" / "valvur"
SCRIPT = PLUGIN / "hooks" / "pre-tool-use.sh"
LOCAL_HOOK = REPO / ".venv" / "bin" / "valvur-hook"


def test_the_plugin_declares_one_pre_tool_use_hook_on_bash_running_its_script():
    declared = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())

    [entry] = declared["hooks"]["PreToolUse"]
    assert entry["matcher"] == "Bash"
    [command] = entry["hooks"]
    assert command["type"] == "command"
    assert command["command"] == 'sh "${CLAUDE_PLUGIN_ROOT}/hooks/pre-tool-use.sh"'
    assert 0 < command["timeout"] <= 60
    assert set(declared) == {"hooks"}


def _replay(command: str, *, hook: str, tool: str = "Bash", cwd: Path = REPO,
            cache: Path | None = None) -> tuple[int, str]:
    event = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool,
             "tool_input": {"command": command}, "cwd": str(cwd)}
    done = subprocess.run(["sh", str(SCRIPT)], input=json.dumps(event), text=True,
                          capture_output=True, timeout=60, check=False,
                          env={**os.environ, "VALVUR_HOOK": hook,
                               **({"VALVUR_CACHE": str(cache)} if cache else {})})
    return done.returncode, done.stdout


def test_a_command_that_names_no_installer_never_starts_valvur():
    """`false` as the hook would fail if it ran: these commands never reach it."""
    for command in ("ls -la", "pytest -q", "git status", "echo done"):
        assert _replay(command, hook="false") == (0, ""), command


@pytest.mark.skipif(not LOCAL_HOOK.exists(), reason="no installed valvur-hook in .venv")
def test_recorded_inputs_replayed_through_the_plugins_command_answer_as_the_hook_does(
        name_index):
    # The hook runs as its own process: it finds this test's index under `VALVUR_CACHE`,
    # at `<cache>/valvur/names`, as `cache.root()` lays the cache out.
    import shutil

    index = name_index(npm=["react"], pip=["requests"], built_at="2026-09-29T09:57:48Z")
    cache = index.parent / "cache-root"
    shutil.copytree(index, cache / "valvur" / "names")

    code, out = _replay("npm install reakt", hook=str(LOCAL_HOOK), cache=cache)
    assert code == 0
    decision = json.loads(out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "ask" and "reakt" in decision[
        "permissionDecisionReason"]
    assert _replay("npm install react", hook=str(LOCAL_HOOK), cache=cache) == (0, "")
    assert _replay("npm install reakt", hook=str(LOCAL_HOOK), tool="Edit", cache=cache) == (0, "")


def test_when_valvur_cannot_start_the_install_still_asks_naming_why(tmp_path):
    """Found by 1.3.0's smoke run: `uvx` could not yet resolve the release, the hook's
    command failed, Claude Code treats a failing hook as non-blocking, and the install
    went ahead unasked. The check is never silently off (D44): the script asks."""
    broken = tmp_path / "broken-hook"
    broken.write_text('#!/bin/sh\necho \'error: no version of "valvur==9.9.9"\' >&2\nexit 1\n')
    broken.chmod(0o755)

    code, out = _replay("npm install left-pad", hook=str(broken))

    assert code == 0
    decision = json.loads(out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "ask"
    reason = decision["permissionDecisionReason"]
    assert "could not check this install" in reason and "valvur==9.9.9" in reason
