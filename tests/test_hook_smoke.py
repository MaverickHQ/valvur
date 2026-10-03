"""R18.4, behaviour 4: the hook's smoke run (D46), judged from Claude Code's stream.

`claude -p`, with the plugin and the `Bash` tool allowed, is asked to install a made-up
npm package. Every installer, `curl` and `wget` is a stub first on `PATH` that records
its arguments, so nothing can be installed. The run passes when the stream shows the
hook stopping the call (in `-p`, Claude Code turns the hook's `ask` into a
`permission_denied` with `decision_reason_type: "hook"`, measured 2026-10-02) and the
stubs recorded no install of the name.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "acceptance" / "hook_smoke.py"
NAME = "valvur-smoke-unpublished-7f3e9a"


def _smoke():
    spec = importlib.util.spec_from_file_location("hook_smoke", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["hook_smoke"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _stream(*, denied_by: str = "hook", reason: str | None = None, cost: float = 0.68) -> str:
    reason = reason if reason is not None else (
        f"valvur checked this install before it runs (offline, from this machine's index):\n"
        f"- npm `{NAME}`: nonexistent. not on the npm registry")
    events = [
        {"type": "system", "subtype": "init", "plugins": [{"name": "valvur"}]},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": f"npm install {NAME}"}}]}},
        {"type": "system", "subtype": "permission_denied", "tool_name": "Bash",
         "decision_reason_type": denied_by, "decision_reason": reason},
        {"type": "result", "subtype": "success", "total_cost_usd": cost},
    ]
    return "\n".join(json.dumps(e) for e in events) + "\n"


def test_the_hook_stopping_the_install_with_nothing_installed_passes():
    judged = _smoke().judge(_stream(), installs="", name=NAME)

    assert judged.ok and judged.stopped_by_hook and not judged.installed
    assert judged.cost_usd == 0.68


def test_an_install_that_reached_a_stub_fails_whatever_the_stream_says():
    judged = _smoke().judge(_stream(), installs=f"npm install {NAME}\n", name=NAME)

    assert not judged.ok and judged.installed


def test_a_denial_that_was_not_the_hooks_or_not_about_the_name_fails():
    smoke = _smoke()

    assert not smoke.judge(_stream(denied_by="rule"), installs="", name=NAME).ok
    assert not smoke.judge(_stream(reason="something else"), installs="", name=NAME).ok


def test_the_stubs_cover_every_installer_and_the_fetchers():
    assert set(_smoke().STUBBED) >= {"npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv",
                                     "poetry", "cargo", "gem", "composer", "curl", "wget"}


def test_as_shipped_the_hook_is_the_released_one_and_installers_stay_stubbed(tmp_path):
    """After a release, the smoke run uses the plugin exactly as published: no
    `VALVUR_HOOK`, the pinned `uvx --from valvur==<version>` reachable, and every
    installer still a stub ahead of it on `PATH`."""
    smoke = _smoke()
    stubs = tmp_path / "bin"

    shipped = smoke.environment(stubs, as_shipped=True, uvx="/opt/tools/uvx")
    from_tree = smoke.environment(stubs, as_shipped=False, uvx="/opt/tools/uvx")

    assert "VALVUR_HOOK" not in shipped and from_tree["VALVUR_HOOK"].endswith("valvur-hook")
    path = shipped["PATH"].split(":")
    assert path[0] == str(stubs) and "/opt/tools" in path
    assert path.index(str(stubs)) < path.index("/opt/tools")


def test_an_agent_that_never_ran_the_install_is_inconclusive_not_a_failure():
    """As shipped, the skill tells the agent to call `check_package` first; one that does
    may never run the install, so the hook is never asked. That run proves nothing about
    the hook, and says so, rather than failing it."""
    events = [{"type": "system", "subtype": "init", "plugins": [{"name": "valvur"}]},
              {"type": "assistant", "message": {"content": [
                  {"type": "tool_use", "name": "mcp__plugin_valvur_valvur__check_package",
                   "input": {"packages": [{"ecosystem": "npm", "name": NAME}]}}]}},
              {"type": "result", "subtype": "success", "total_cost_usd": 0.4}]
    stream = "\n".join(json.dumps(e) for e in events) + "\n"

    judged = _smoke().judge(stream, installs="", name=NAME)

    assert not judged.attempted and not judged.ok and not judged.installed
    assert _smoke().judge(_stream(), installs="", name=NAME).attempted
