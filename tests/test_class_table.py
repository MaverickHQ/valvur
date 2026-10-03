"""R20.4: one table decides what a path class changes (D56; D47b, c).

Of the corpus's 26 false alarms, 11 were secrets in tests and docs, ranked first in
their repositories, and the vendored `random` rule and `weak-hash` fired in docs
(R20.1). A secret there ranks `low` and stays active, because a real key in a test
is still a key. `weak-hash` and `random` are not reported there, and `run.json`
counts what the table removed, by class and rule, so nothing goes without a number.
A class with no row changes nothing.
"""

from __future__ import annotations

import json

import pytest

from valvur import classtable, verdict
from valvur.findings import Finding, Severity
from valvur.scanrun import ScanRun


def _finding(rule: str, path: str, context: str, *, source: str = "opengrep",
             severity: str = "critical") -> Finding:
    return Finding(rule=rule, path=path, line=1, title=rule, fingerprint=f"{rule}{path}",
                   sources=(source,), severity=severity, context=context)


@pytest.mark.parametrize("context", ["test", "fixture", "docs", "example"])
def test_a_secret_where_tests_and_docs_live_ranks_low_and_stays_active(context):
    secret = _finding("generic-api-key", "x/config.py", context, source="gitleaks")

    [kept], removed = classtable.apply([secret])

    assert kept.severity is Severity.LOW and verdict.active(kept)
    assert removed == {}
    run = ScanRun(findings=[kept], profile="offline", db_age_days=1.0,
                  name_index_age_days=1.0)
    assert run.status == "findings"


@pytest.mark.parametrize("rule", ["valvur.python.weak-hash", "python_random_rule-random"])
@pytest.mark.parametrize("context", ["test", "fixture", "docs", "example"])
def test_weak_hash_and_random_are_not_reported_there_and_are_counted(rule, context):
    kept, removed = classtable.apply([_finding(rule, "x/a.py", context, severity="low")])

    assert kept == []
    assert removed == {context: {rule: 1}}


@pytest.mark.parametrize("context", ["source", "vendored", "generated"])
def test_a_class_with_no_row_changes_nothing(context):
    findings = [_finding("generic-api-key", "a.py", context, source="gitleaks"),
                _finding("valvur.python.weak-hash", "a.py", context, severity="low")]

    assert classtable.apply(findings) == (findings, {})


def test_run_json_counts_what_the_table_removed(tmp_path):
    from valvur.provenance import render

    run = ScanRun(findings=[], profile="offline",
                  removed_by_class={"docs": {"python_random_rule-random": 2}})

    assert json.loads(render(run))["removed_by_class"] == {
        "docs": {"python_random_rule-random": 2}}
