"""R50.6: ranking reads a declaration (D82n, ADR-0036).

valvur cannot know which part of a codebase faces the internet or holds sensitive data,
and does not pretend to. A project can say so, in `.security-scan.toml`. A Finding under a
declared path then ranks ahead of the others in its own tier, and never across one: a
known-exploited advisory elsewhere still outranks a medium Finding in a declared path. The
raise is the project's statement, called a *declaration* wherever it shows, and never
analysis.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from valvur import api
from valvur import fingerprint as _fp
from valvur.engine_host import LocalRuntime
from valvur.findings import Finding
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"
API, LIB = "services/api/handlers.py", "lib/util.py"
SENTENCE = ("raised by this project's declaration: `services/api/` is internet-facing "
            "(`.security-scan.toml`)")


def _finding(rule: str, path: str, severity: str = "medium") -> Finding:
    return Finding(rule=rule, path=path, line=3, title=f"{rule} in {path}", severity=severity,
                   fingerprint=_fp.derive(rule, path), sources=("opengrep",))


class _Opengrep:
    artifact = None
    kind = "scanner"
    version = "1"
    name = "opengrep"

    def __init__(self, found: list[Finding]):
        self.found = found

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool=self.name, version="1", report="opengrep.json", timeout=60,
                          argv=("fake-report", "0", "{}", "/results/opengrep.json"))

    def parse(self, output):
        return list(self.found)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    for name in (API, LIB):
        (ws / name).parent.mkdir(parents=True, exist_ok=True)
        (ws / name).write_text("x = 1\n")
    return ws


def _scan(ws: Path, *found: Finding, declared: str = "") -> tuple[list[dict], str]:
    if declared:
        (ws / ".security-scan.toml").write_text(declared)
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Opengrep(list(found))])
    records = json.loads((ws / RESULTS / "findings.json").read_text())["findings"]
    return records, (ws / RESULTS / "REMEDIATION.md").read_text()


DECLARED = '[[context]]\npath = "services/api/"\nexposure = "internet"\n'
PAIR = (_finding("valvur.python.sql-injection", API), _finding("valvur.python.sql-injection", LIB))


def test_with_no_declaration_the_order_is_what_it_was(workspace):
    records, plan = _scan(workspace, *PAIR)

    assert [r["path"] for r in records] == [LIB, API]
    assert "declaration" not in json.dumps(records) and "declaration" not in plan


def test_of_two_findings_in_one_tier_the_declared_path_ranks_first(workspace):
    records, _plan = _scan(workspace, *PAIR, declared=DECLARED)

    assert [(r["path"], r["rank"]) for r in records] == [(API, 1), (LIB, 2)]


def test_a_higher_tier_still_outranks_a_declared_path(workspace):
    urgent = _finding("valvur.dependency.nonexistent", LIB, severity="low")

    records, _plan = _scan(workspace, PAIR[0], urgent, declared=DECLARED)

    assert [r["rule"] for r in records] == ["valvur.dependency.nonexistent",
                                            "valvur.python.sql-injection"]


def test_a_declaration_that_names_every_path_gives_the_order_of_none(workspace):
    everywhere = DECLARED + '\n[[context]]\npath = "lib/"\ndata = "sensitive"\n'

    records, _plan = _scan(workspace, *PAIR, declared=everywhere)

    assert [r["path"] for r in records] == [LIB, API]


def test_the_raised_item_says_which_declaration_raised_it(workspace):
    records, plan = _scan(workspace, *PAIR, declared=DECLARED)

    by_path = {r["path"]: r for r in records}
    assert by_path[API]["declaration"] == "`services/api/` is internet-facing"
    assert "declaration" not in by_path[LIB]
    assert " ".join(plan.split()).count(SENTENCE) == 1


def test_sensitive_data_is_said_in_its_own_words(workspace):
    records, plan = _scan(workspace, *PAIR,
                          declared='[[context]]\npath = "lib"\ndata = "sensitive"\n')

    assert [r["path"] for r in records] == [LIB, API]
    assert ("raised by this project's declaration: `lib/` holds sensitive data "
            "(`.security-scan.toml`)") in " ".join(plan.split())


def test_a_path_is_matched_by_whole_segments(workspace):
    records, _plan = _scan(workspace, *PAIR,
                           declared='[[context]]\npath = "services/ap"\nexposure = "internet"\n')

    assert "declaration" not in json.dumps(records)


@pytest.mark.parametrize("text, named", [
    (DECLARED, None),
    ('[[context]]\npath = "lib/"\ndata = "sensitive"\n', None),
    ('[[context]]\npath = "lib/"\nexposure = "intranet"\n', "context[0].exposure"),
    ('[[context]]\npath = "lib/"\ndata = "secret"\n', "context[0].data"),
    ('[[context]]\nexposure = "internet"\n', "context[0].path"),
    ('[[context]]\npath = "lib/"\nreachable = true\n', "context[0].reachable"),
])
def test_doctor_and_the_schema_refuse_a_value_outside_the_two(text, named):
    import tomllib

    from valvur import project_schema

    said = project_schema.problem(tomllib.loads(text))

    assert (said is None) if named is None else (said is not None and said.startswith(
        f"`{named}`")), said


_ANALYSIS = re.compile(r"reachab|analy[sz]|exploitab|data.?flow|proved|proven", re.I)


def test_no_output_calls_the_raise_analysis_or_reachability(workspace):
    records, plan = _scan(workspace, *PAIR, declared=DECLARED)

    raised = [line for line in plan.splitlines() if "declaration" in line]
    raised += [r["declaration"] for r in records if "declaration" in r]
    assert raised and not [line for line in raised if _ANALYSIS.search(line)]
    # Seen red against a planted word: the finder does find one.
    assert _ANALYSIS.search("raised by reachability analysis of `services/api/`")
