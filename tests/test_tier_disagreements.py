"""R49.2: the tier table is held to the measurement, not to a copy of itself (D82d).

A rule is *measured on the corpus* with five or more judged Findings there, and *under the
bar* when fewer than half of them are true. `rule_precision.tier_disagreements` reads the
table's rows and `rules-measured.json` and names each rule that is under the bar with no
row, and each row whose counts are not the measurement's.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "eval"))

import rule_precision


def _measured(opengrep: dict[str, tuple[int, int]], others: dict[tuple[str, str], tuple[int, int]]
              ) -> dict:
    return {
        "rules": {rule: {"places": {"corpus": {"tp": tp, "fp": fp, "unjudged": 0}}}
                  for rule, (tp, fp) in opengrep.items()},
        "others": [{"scanner": scanner, "rule": rule,
                    "corpus": {"findings": tp + fp, "judged": tp + fp, "tp": tp, "fp": fp,
                               "sampled": False}, "planted": {"tp": 0, "fp": 0}}
                   for (scanner, rule), (tp, fp) in others.items()]}


def _row(scanner: str, rule: str, tp: int, fp: int) -> SimpleNamespace:
    return SimpleNamespace(scanner=scanner, id=rule, tp=tp, fp=fp)


def test_a_rule_under_the_bar_with_no_row_is_named():
    measured = _measured({"valvur.python.weak-hash": (0, 21), "valvur.python.fine": (9, 3)},
                         {("gitleaks", "jwt"): (2, 27), ("zizmor", "artipacked"): (25, 0)})

    assert rule_precision.tier_disagreements([], measured) == [
        "gitleaks jwt: 2 true of 29 on the corpus, under the bar, and has no row",
        "opengrep valvur.python.weak-hash: 0 true of 21 on the corpus, under the bar, and has "
        "no row"]


def test_a_row_whose_counts_are_not_the_measurements_is_named():
    measured = _measured({"valvur.python.weak-hash": (0, 21)}, {})

    assert rule_precision.tier_disagreements(
        [_row("opengrep", "valvur.python.weak-hash", 0, 21)], measured) == []
    assert rule_precision.tier_disagreements(
        [_row("opengrep", "valvur.python.weak-hash", 0, 19)], measured) == [
        "opengrep valvur.python.weak-hash: its row says 0 true and 19 false, and the "
        "measurement 0 and 21"]


def test_a_row_for_a_rule_the_measurement_does_not_have_is_named():
    assert rule_precision.tier_disagreements(
        [_row("gitleaks", "gone", 0, 9)], _measured({}, {})) == [
        "gitleaks gone: its row says 0 true and 9 false, and the measurement has no such rule"]


def test_nothing_is_named_for_a_rule_with_fewer_than_five_judged_findings():
    measured = _measured({"valvur.javascript.ssrf": (0, 2)}, {("checkov", "CKV_TF_1"): (0, 4)})

    assert rule_precision.tier_disagreements([], measured) == []


def test_half_true_is_at_the_bar_and_not_under_it():
    measured = _measured({}, {("checkov", "CKV_DOCKER_2"): (7, 7)})

    assert rule_precision.tier_disagreements([], measured) == []
