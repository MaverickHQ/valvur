"""R13.3: the rules that met D29's bar, vendored and shipped.

Exactly the four R13.2 measured over the bar, as R13.6 amended it: their files as
GitLab wrote them, its licence, the commit they came from, and a manifest of each
rule's origin and measurement. The image carries them beside valvur's own rules,
`run.json` names the rule set's commit, and a finding keeps the rule's own id wherever
the directory sits.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VENDORED = REPO / "rules" / "vendor" / "gitlab"
MEASURED = REPO / "tests" / "eval" / "sast-rules-measured.json"


def _ids() -> set[str]:
    found = set()
    for path in VENDORED.rglob("*.yaml"):
        found |= set(re.findall(r"""^\s*- id:\s*["']?([^"'\s]+)""", path.read_text(), re.M))
    return found


def test_exactly_the_rules_that_met_the_bar_are_vendored():
    measured = json.loads(MEASURED.read_text())

    assert _ids() == set(measured["ships"])
    assert len(measured["ships"]) == 4
    assert all(measured["rules"][rule]["ships"] for rule in measured["ships"])


def test_the_licence_the_commit_and_the_manifest_travel_with_them():
    pinned = tomllib.loads((REPO / "tests" / "eval" / "sources.toml").read_text())
    manifest = json.loads((VENDORED / "manifest.json").read_text())

    assert "Copyright (c) 2011-present GitLab Inc." in (VENDORED / "LICENSE").read_text()
    assert manifest["commit"] == pinned["gitlab-sast-rules"]["commit"]
    assert {rule["id"] for rule in manifest["rules"]} == _ids()
    for rule in manifest["rules"]:
        assert rule["origin_licence"] in {"MIT", "Apache-2.0"} and rule["cwe"], rule
        assert rule["precision"] >= 0.5 and rule["true_positives"] >= 1, rule
    assert "gitlab-org/security-products/sast-rules" in (REPO / "NOTICE").read_text()


def test_a_vendored_rules_finding_keeps_its_own_id():
    from valvur.adapters.opengrep import _short_rule

    assert _short_rule("opt.valvur-rules.vendor.gitlab.python.sql."
                       "python_sql_rule-hardcoded-sql-expression") == \
        "python_sql_rule-hardcoded-sql-expression"
    assert _short_rule("opt.valvur-rules.python-security.valvur.python.dangerous-eval") == \
        "valvur.python.dangerous-eval"


def test_run_json_names_the_rule_sets_commit():
    from valvur import provenance
    from valvur.adapters.opengrep import RULE_SETS
    from valvur.api import ScanRun

    manifest = json.loads((VENDORED / "manifest.json").read_text())
    written = json.loads(provenance.render(ScanRun()))

    assert RULE_SETS["gitlab-sast-rules"] == manifest["commit"]
    assert written["rule_sets"]["gitlab-sast-rules"] == manifest["commit"]


def test_the_score_reads_the_vendored_rules_cwes():
    spec = importlib.util.spec_from_file_location("cwe_mod", REPO / "scripts" / "eval" / "cwe.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["cwe_mod"] = module
    spec.loader.exec_module(module)

    cwes = module.rule_cwes(REPO / "rules")

    assert cwes["python_sql_rule-hardcoded-sql-expression"] == {89}
    assert cwes["python_random_rule-random"] == {338}
