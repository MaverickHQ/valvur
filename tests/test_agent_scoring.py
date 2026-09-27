"""R2.4: an agent's answer is scored against the repository's expectations.

The scorer reads `claude -p --output-format json`'s result; the run itself costs money
and is opt-in, so it is tested against a recorded result, not a live one.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TASKS = "- [ ] **R3.2** **The File Set**\n"


def _agent():
    path = REPO / "scripts" / "acceptance" / "agent.py"
    spec = importlib.util.spec_from_file_location("acceptance_agent", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_agent"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


RESULT = {"type": "result", "subtype": "success", "num_turns": 7,
          "total_cost_usd": 0.42, "duration_ms": 61_500,
          "result": "valvur found a shell injection in src/app/app.py and another in "
                    "src/archive/app.py (subprocess with shell=True)."}
EXPECTED = {"must": [
    {"rule": "subprocess-shell-true", "path": "src/app/app.py"},
    {"rule": "subprocess-shell-true", "path": "src/archive/app.py"},
    {"rule": "subprocess-shell-true", "path": "mypkg/build/steps.py", "until": "R3.2"},
]}


def test_the_score_counts_turns_cost_and_whether_every_live_finding_is_named():
    score = _agent().score(RESULT, EXPECTED, TASKS)
    assert (score.turns, score.cost_usd, score.seconds) == (7, 0.42, 61.5)
    assert score.named_all is True and score.unnamed == []


def test_a_finding_the_answer_leaves_out_is_unnamed():
    silent = {**RESULT, "result": "valvur found a shell injection in src/app/app.py."}
    score = _agent().score(silent, EXPECTED, TASKS)
    assert score.named_all is False
    assert score.unnamed == ["src/archive/app.py"]
