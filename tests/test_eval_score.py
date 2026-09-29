"""R9.3: the Score's formula (ADR-0026, N4.1).

Each track is scored by the OWASP Benchmark's method: per category, the true-positive
rate minus the false-positive rate, averaged over the categories, 0 to 100. A case
is flagged only by an active finding of its kind on its path.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parent.parent / "scripts" / "eval"


def _score():
    spec = importlib.util.spec_from_file_location("score", EVAL / "score.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["score"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _finding(path: str, rule: str, **extra) -> dict:
    return {"path": path, "rule": rule, "suppressed": None, "status": "new", **extra}


def test_a_track_is_the_mean_over_categories_of_tpr_minus_fpr():
    s = _score()
    cases = [
        s.Case("a1", "t", "A", "a/one.py", True, rules=("r",)),
        s.Case("a2", "t", "A", "a/two.py", True, rules=("r",)),
        s.Case("a3", "t", "A", "a/three.py", False, rules=("r",)),
        s.Case("a4", "t", "A", "a/four.py", False, rules=("r",)),
        s.Case("b1", "t", "B", "b/one.py", True, rules=("r",)),
        s.Case("b2", "t", "B", "b/two.py", False, rules=("r",)),
    ]
    findings = [_finding("a/one.py", "r"), _finding("b/one.py", "r"),
                _finding("b/two.py", "r")]

    result = s.score_track(cases, findings)

    assert result.categories["A"].tpr == 0.5 and result.categories["A"].fpr == 0.0
    assert result.categories["B"].tpr == 1.0 and result.categories["B"].fpr == 1.0
    assert result.score == 25.0
