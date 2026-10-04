"""R21.3, behaviour 4 (D58d): the hook's smoke run under Claude Code's *don't ask* mode.

Under `claude -p`, the hook's `ask` became a refusal (R18.4). The owner's own sessions
run in *don't ask*, which refuses every tool not allowed beforehand, so what that mode
does with the hook's `ask` is measured the same way: `--permission-mode dontAsk`, the
same stubs, the same judge. The run is paid from D58's own $2, not D46's ledger.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "acceptance" / "hook_smoke.py"


def _smoke():
    spec = importlib.util.spec_from_file_location("hook_smoke_modes", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["hook_smoke_modes"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_dont_ask_is_paid_from_d58s_two_dollars_and_the_default_from_d46s():
    smoke = _smoke()

    dont_ask, default = smoke.budget("dontAsk"), smoke.budget(None)

    assert dont_ask.ledger.name == "agent-cost-r21.json" and dont_ask.cap_usd == 2.0
    assert default.ledger.name == "agent-cost-r18.json" and default.cap_usd == 5.0


def test_the_mode_is_passed_to_claude_and_nothing_else_changes(tmp_path):
    smoke = _smoke()
    plugin = tmp_path / "plugin"

    plain = smoke.arguments("claude", plugin, mode=None, budget_usd=1.0)
    dont_ask = smoke.arguments("claude", plugin, mode="dontAsk", budget_usd=1.0)

    assert dont_ask == [*plain, "--permission-mode", "dontAsk"]
    assert "--permission-mode" not in plain


def test_the_command_line_names_the_mode():
    smoke = _smoke()

    assert smoke.options(["--permission-mode", "dontAsk"]) == (False, "dontAsk")
    assert smoke.options(["--as-shipped"]) == (True, None)
    assert smoke.options([]) == (False, None)
