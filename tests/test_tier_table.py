"""R49.2: one tier table for every Scanner's rules (D82c, D82d, ADR-0033).

Only Opengrep's adapter could mark a Finding `inventory`, from the rule's own YAML. A
vendored rule may not be edited and Gitleaks' rules are not valvur's files, so the tier
moves to one table, `src/valvur/data/tiers.toml`, that names a rule by its Scanner and its
ID. A rule measured on maintained code and under the bar there is inventory: reported for
review, never active, never counted by the verdict or the gate. The Scanner is faked by an
adapter that returns canned Findings, as `tests/test_not_rechecked.py` fakes one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api, gate
from valvur import fingerprint as _fp
from valvur.engine_host import LocalRuntime
from valvur.findings import Finding
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"


class _Canned:
    """A Scanner that reports the Findings it was given."""

    artifact = None
    kind = "scanner"
    version = "1"

    def __init__(self, name: str, found: list[tuple[str, str]]):
        self.name = name
        self.found = found

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool=self.name, version="1", report=f"{self.name}.json", timeout=60,
                          argv=("fake-report", "0", "[1]", f"/results/{self.name}.json"))

    def parse(self, output):
        return [Finding(rule=rule, path=path, line=1, title=f"{rule} found something",
                        fingerprint=_fp.derive(rule, path), sources=(self.name,),
                        severity="medium")
                for rule, path in self.found]


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _scan(workspace: Path, scanner: str, *found: tuple[str, str]):
    for _rule, path in found:
        (workspace / path).parent.mkdir(parents=True, exist_ok=True)
        (workspace / path).write_text("x = 1\n")
    run = api.scan(workspace, runner=LocalRuntime(FAKE_TOOLS),
                   adapters=[_Canned(scanner, list(found))])
    written = json.loads((workspace / RESULTS / "findings.json").read_text())["findings"]
    return run, written


def test_a_rule_under_the_bar_is_inventory_and_the_project_reads_clean(workspace):
    run, [record] = _scan(workspace, "opengrep", ("valvur.python.weak-hash", "app/hashing.py"))

    assert record["rule"] == "valvur.python.weak-hash" and record["inventory"] is True
    assert run.status == "clean"
    assert gate.evaluate(workspace).exit_code == 0


def test_a_rule_with_no_row_is_active_as_before(workspace):
    run, [record] = _scan(workspace, "opengrep", ("valvur.python.sql-injection", "app/db.py"))

    assert "inventory" not in record and run.status == "findings"
    assert gate.evaluate(workspace, fail_on="medium").exit_code == 1


def test_its_title_says_why_it_is_listed_for_review(workspace):
    _run, [record] = _scan(workspace, "opengrep", ("valvur.python.weak-hash", "app/hashing.py"))

    assert record["title"] == ("valvur.python.weak-hash found something, a rule under the bar "
                               "on maintained code: listed for review")


def test_the_summary_counts_it_as_listed_for_review_and_not_as_a_sink(workspace):
    _scan(workspace, "opengrep", ("valvur.python.weak-hash", "app/hashing.py"),
          ("valvur.python.weak-hash", "app/etag.py"))

    summary = (workspace / RESULTS / "SUMMARY.md").read_text()
    assert "**Listed for review:** 2" in summary and "Sinks to review" not in summary
    assert ("_2 finding(s) listed for review: reported by a rule that is under the bar on "
            "maintained code (`docs/RULES.md`), so more often wrong than right there. Not "
            "active; `findings` with `inventory: true` lists them._") in " ".join(summary.split())


def test_a_project_cannot_name_a_tier(workspace):
    """A guard: the project file's schema, which `doctor` reads, refuses the key, and a
    scan ignores it. An agent cannot make Findings go away, or come back, by editing a
    tier: the table is package data."""
    from valvur import project_schema, toml_input

    text = '[[tier]]\nscanner = "opengrep"\nid = "valvur.python.weak-hash"\ntier = "active"\n'
    (workspace / ".security-scan.toml").write_text(text)

    run, [record] = _scan(workspace, "opengrep", ("valvur.python.weak-hash", "app/hashing.py"))

    assert "`tier` is not a key it takes" in project_schema.problem(toml_input.loads(text))
    assert record["inventory"] is True and run.status != "findings"


def test_no_rule_is_named_both_in_the_table_and_by_its_own_file():
    """The four sink rules keep `metadata.inventory` in their YAML (D47a). One home each."""
    import re

    from valvur import tiers

    declared = set()
    for path in (Path(__file__).resolve().parents[1] / "rules").rglob("*.yaml"):
        for block in path.read_text().split("\n  - id: ")[1:]:
            if re.search(r"^\s+inventory: true$", block, re.M):
                declared.add(block.split("\n", 1)[0].strip())

    assert len(declared) == 4
    assert declared.intersection(row.id for row in tiers.rows()) == set()
    assert len({(row.scanner, row.id) for row in tiers.rows()}) == len(tiers.rows())


@pytest.mark.parametrize("scanner, rule, path", [
    ("checkov", "CKV2_AWS_12", "infra/main.tf"),
    ("zizmor", "cache-poisoning", ".github/workflows/publish.yml"),
])
def test_another_scanners_rule_under_the_bar_is_inventory_too(workspace, scanner, rule, path):
    run, [record] = _scan(workspace, scanner, (rule, path))

    assert record["inventory"] is True and run.status == "clean"
    assert record["title"].endswith("a rule under the bar on maintained code: listed for review")


def test_a_row_names_its_scanner_so_another_scanners_rule_of_that_name_is_active(workspace):
    run, [record] = _scan(workspace, "trivy", ("cache-poisoning", "app/x.py"))

    assert "inventory" not in record and run.status == "findings"


def test_the_vendored_random_rule_is_inventory_in_a_source_path(workspace):
    """R49.3: a vendored rule's file may not be edited, so its tier is a row."""
    run, [record] = _scan(workspace, "opengrep", ("python_random_rule-random", "app/ids.py"))

    assert record["inventory"] is True and run.status == "clean"


def test_in_test_material_both_rules_are_listed_where_the_class_table_removed_them(workspace):
    """One home for both rules: they were removed under tests and docs, with a count in
    `run.json`, and active everywhere else. Now they are in `findings.json`, listed."""
    run, records = _scan(workspace, "opengrep",
                         ("valvur.python.weak-hash", "tests/test_cache.py"),
                         ("python_random_rule-random", "docs/tutorial/sample.py"))

    assert sorted((r["rule"], r["context"], r["inventory"]) for r in records) == [
        ("python_random_rule-random", "docs", True),
        ("valvur.python.weak-hash", "test", True)]
    assert run.status == "clean"
    assert json.loads((workspace / RESULTS / "run.json").read_text())["removed_by_class"] == {}
