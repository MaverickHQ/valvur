"""R26.5: local pre-checks only where CI cannot reach (D62d).

Before `1.4.0`'s tag, `RELEASING.md` asked for `verify.sh` and the e2e suite on the
owner's machine, the same suites the pull request's required checks run and, before
R26.3, `verify` ran a third time. What no check on GitHub reaches is the self-scan on
the day's data, which the release gates on, and the Mac, whose lane GitHub's macOS
runners cannot host (they run no containers). So those are the pre-checks, and the
Mac lane only when detection changed since its last measurement.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _cutting() -> str:
    text = (REPO / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    return text.split("\n## Cutting a release\n", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]


def test_the_pre_checks_are_the_self_scan_gate_and_the_mac_lane_when_detection_changed():
    block = _cutting()
    [step] = [s for s in re.split(r"\n(?=# \d+\. )", block) if "Local pre-checks" in s]

    commands = [line.strip() for line in step.splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    assert commands == [
        "uv run valvur scan . --profile full",
        "uv run valvur gate . --fail-on any --no-inconclusive",
    ], commands
    assert "the Mac lane" in step and "when detection changed since" in step
    assert "scripts/acceptance.py --generate" in step and "scripts/eval.py --compare" in step
    assert "./scripts/verify.sh" not in block and "-m e2e" not in block
