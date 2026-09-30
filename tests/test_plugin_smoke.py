"""R15.2, behaviour 4: the plugin's smoke run (D36), judged from Claude Code's stream.

`claude -p --plugin-dir plugins/valvur`, with no shell, loads the plugin; the stream's
first event lists what loaded. The run is judged on that: the plugin, its skill,
its server connected, and each tool the server should list. The judging is tested
here on a stream shaped as Claude Code 2.1.284 writes it; the run itself costs money
and is recorded, not repeated in the suite.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "acceptance" / "plugin_smoke.py"


def _smoke():
    spec = importlib.util.spec_from_file_location("plugin_smoke", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["plugin_smoke"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _stream(*, tools=("scan", "findings", "doctor"), status="connected",
            skills=("tdd", "valvur:valvur"), cost=0.12) -> str:
    init = {"type": "system", "subtype": "init",
            "plugins": [{"name": "valvur", "path": "/x/plugins/valvur",
                         "source": "valvur@inline", "version": "1.1.0"}],
            "skills": list(skills),
            "mcp_servers": [{"name": "plugin:valvur:valvur", "status": status,
                             "source": "plugin"}],
            "tools": ["Read", *(f"mcp__plugin_valvur_valvur__{t}" for t in tools)]}
    result = {"type": "result", "total_cost_usd": cost}
    return "\n".join(json.dumps(e) for e in (init, {"type": "assistant"}, result)) + "\n"


def test_a_run_that_loaded_everything_passes():
    judged = _smoke().judge(_stream(), expected={"scan", "findings", "doctor"})

    assert judged.ok and judged.version == "1.1.0" and judged.cost_usd == 0.12
    assert judged.tools == ["doctor", "findings", "scan"]


def test_a_missing_tool_is_named():
    judged = _smoke().judge(_stream(tools=("scan",)), expected={"scan", "check_package"})

    assert not judged.ok and judged.missing == ["check_package"]


def test_a_server_that_did_not_connect_or_a_skill_not_listed_fails():
    smoke = _smoke()

    assert not smoke.judge(_stream(status="failed"), expected={"scan"}).ok
    assert not smoke.judge(_stream(skills=("tdd",)), expected={"scan"}).ok


def test_the_command_has_no_shell_and_a_budget():
    command = _smoke().command(Path("/x/plugins/valvur"), budget=0.5)

    assert command[:2] == ["claude", "-p"]
    assert command[command.index("--plugin-dir") + 1] == "/x/plugins/valvur"
    assert command[command.index("--disallowedTools") + 1] == "Bash"
    assert command[command.index("--max-budget-usd") + 1] == "0.5"


def test_from_the_tree_the_server_is_this_checkout(tmp_path):
    """The shipped plugin pins the published release; a smoke of this build points a
    copy of it at this checkout's server, and changes nothing else."""
    smoke = _smoke()

    copy = smoke.from_tree(smoke.PLUGIN, tmp_path / "plugin")

    config = json.loads((copy / ".mcp.json").read_text())["mcpServers"]["valvur"]
    assert config["command"] == "uv" and str(smoke.REPO) in config["args"]
    assert (copy / "skills" / "valvur" / "SKILL.md").read_bytes() == \
        (smoke.PLUGIN / "skills" / "valvur" / "SKILL.md").read_bytes()
