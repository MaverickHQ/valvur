"""R18.3: the hook answers (D44).

Claude Code runs `valvur-hook` before every `Bash` call the agent makes, with the call
as JSON on stdin (code.claude.com/docs/en/hooks.md, read 2026-10-02). When the command
installs a package `valvur check` would flag, the hook answers `ask`, with each
package's verdict, and the human decides. Otherwise it says nothing, and the usual
permission flow applies. It never answers `deny`, never runs the command, and opens no
socket: the answers come from this machine's index, as `check_package`'s do.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from valvur import hook
from valvur.name_index import malicious

FIXTURE = Path(__file__).parent / "fixtures" / "malicious-packages"


@pytest.fixture
def index(name_index):
    directory = name_index(npm=["react", "left-pad", "atez"], pip=["requests"],
                           built_at="2026-09-29T09:57:48Z")
    assert malicious._main(["build-malicious", str(directory), str(FIXTURE)]) == 0
    return directory


def _run(command: str, *, tool: str = "Bash", cwd: Path = Path(".")) -> tuple[int, str]:
    event = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool,
             "tool_input": {"command": command}, "cwd": str(cwd),
             "permission_mode": "default"}
    out = io.StringIO()
    code = hook.main(stdin=io.StringIO(json.dumps(event)), stdout=out)
    return code, out.getvalue()


def _decision(out: str) -> dict:
    return json.loads(out)["hookSpecificOutput"]


def test_a_flagged_package_makes_it_ask_with_each_verdict(index):
    code, out = _run("npm install reakt react && pip install requestz")

    decision = _decision(out)
    assert code == 0
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "ask"
    reason = decision["permissionDecisionReason"]
    assert "npm `reakt`: nonexistent" in reason
    assert "pip `requestz`: near-miss" in reason and "'requests'" in reason
    assert "npm `react`:" not in reason                      # a real package is not listed
