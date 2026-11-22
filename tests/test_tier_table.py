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
