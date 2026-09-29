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


def test_only_an_active_finding_of_the_case_s_kind_on_its_path_flags_it():
    s = _score()
    by_rule = s.Case("r", "t", "c", "src/app.py", True, rules=("r",))
    by_prefix = s.Case("p", "t", "c", "pkg/requirements.txt", True,
                       prefixes=("valvur.dependency.",))
    by_advisory = s.Case("v", "t", "c", "lock/package-lock.json", True,
                         advisories=("CVE-2021-23337",))
    by_cwe = s.Case("w", "t", "c", "testcode/T1.py", True, cwes=(89,))
    in_a_directory = s.Case("d", "t", "c", "cases/hooks", True, rules=("r",))
    cwe_of = {"sql-rule": {89}}.get

    def hit(case, finding):
        return s.flagged(case, [finding], cwe_of=lambda f: cwe_of(f["rule"], set()))

    assert hit(by_rule, _finding("src/app.py", "r"))
    assert not hit(by_rule, _finding("src/app.py", "r", suppressed={"reason": "x"}))
    assert not hit(by_rule, _finding("src/app.py", "r", status="fixed"))
    assert not hit(by_rule, _finding("src/app.py", "other"))
    assert not hit(by_rule, _finding("src/app.pyc", "r"))
    assert hit(by_prefix, _finding("pkg/requirements.txt", "valvur.dependency.nonexistent"))
    assert hit(by_advisory, _finding("lock/package-lock.json", "GHSA-35jh-r3h4-6jhm",
                                     exploit={"cve": "CVE-2021-23337"}))
    assert hit(by_cwe, _finding("testcode/T1.py", "sql-rule"))
    assert not hit(by_cwe, _finding("testcode/T1.py", "other-rule"))
    assert hit(in_a_directory, _finding("cases/hooks/.claude/settings.json", "r"))
    assert not hit(in_a_directory, _finding("cases/hooks-safe/.claude/settings.json", "r"))


def test_a_case_keyed_by_scanner_is_flagged_by_any_of_its_findings():
    s = _score()
    case = s.Case("k", "secrets", "aws", "config/aws.env", True, sources=("gitleaks",))

    assert s.flagged(case, [_finding("config/aws.env", "generic-api-key",
                                     sources=["gitleaks"])])
    assert not s.flagged(case, [_finding("config/aws.env", "CKV_SECRET_2",
                                         sources=["checkov"])])
