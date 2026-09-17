"""Task 23.5.5 — a licence valvur could not read is a statement about valvur.

Measured on the corpus (`tests/corpus/report.json`, `full`): a licence statement is an
active Finding on eight of twelve real repositories, and awesome-cursorrules reads
`findings` on a `licence.unidentified` note and nothing else. *"Licences could not be
determined for 600 of 618 dependencies"* is a fact about the lockfile's metadata; *"no
known licence signature matched"* is a fact about our signatures. Neither is a defect
in the code, and §7's rule is that the verdict is about the code.

So the three join the coverage notes — never active, counted as `not_covered`, listed
in `SUMMARY.md` — with one difference the note machinery did not have: they cast no
doubt. A licence we could not read is not a vulnerability we did not look for, and a
security verdict of `clean` stays `clean` over it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import coverage
from valvur.api import ScanRun
from valvur.findings import Dependency, Finding


def _statement(rule):
    return Finding(rule=rule, path="sbom.cdx.json", line=0, severity="low",
                   title={
                       "valvur.licence.dependencies-unreadable":
                           "Licences could not be determined for 600 of 618 dependencies",
                       "valvur.licence.dependency-unknown":
                           "15 dependencies have no licence recorded",
                       "valvur.licence.unidentified":
                           "Licence file present but its licence could not be identified",
                   }[rule])


def _gap():
    return Finding(rule=coverage.RULE, path="Pipfile", line=0, severity="low",
                   title="Python dependencies were not checked for existence")


def _live():
    return Finding(rule="aws-access-token", path="config.py", line=1, severity="critical",
                   title="a live problem")


STATEMENTS = sorted(coverage.LICENCE_STATEMENT_RULES)


# ------------------------------------------------------------------ the class

@pytest.mark.parametrize("rule", STATEMENTS)
def test_a_licence_valvur_could_not_read_is_never_active(rule):
    run = ScanRun(findings=[_statement(rule)])

    assert run.active == []
    assert [n.rule for n in run.coverage_notes] == [rule]


@pytest.mark.parametrize("rule", STATEMENTS)
def test_a_licence_statement_casts_no_doubt_on_a_security_verdict(rule):
    """The flag the note machinery needed. The existence and vulnerability gaps make
    a nil result `inconclusive` — we did not look, so `clean` is not ours to claim.
    A licence we could not read is a different claim, and the verdict is `clean`."""
    run = ScanRun(findings=[_statement(rule)])

    assert run.status == "clean"
    assert run.doubts == []
    assert "licence" not in run.status_reason.lower()


def test_a_real_gap_beside_a_licence_statement_still_casts_its_doubt():
    run = ScanRun(findings=[_statement(STATEMENTS[0]), _gap()])

    assert run.status == "inconclusive"
    assert run.doubts == ["not inspected — Python dependencies: existence"]


def test_a_live_finding_beside_a_licence_statement_is_still_findings():
    run = ScanRun(findings=[_statement(STATEMENTS[0]), _live()])

    assert run.status == "findings"
    assert run.status_reason == "1 active finding(s)"


@pytest.mark.parametrize("rule,severity", [
    ("valvur.licence.missing", "low"),
    ("valvur.licence.mismatch", "medium"),
    ("valvur.licence.copyleft-in-permissive", "unknown"),
])
def test_a_missing_or_contradictory_licence_is_still_a_finding(rule, severity):
    """The line: these are facts about the project, not about what valvur could
    read. No licence file blocks a release (F4.2); two files disagreeing is a
    statement someone will rely on (F4.3); copyleft in a permissive tree is the
    policy F4.5 asks for."""
    run = ScanRun(findings=[Finding(rule=rule, path=".", line=0, severity=severity,
                                    title="a licence problem")])

    assert run.status == "findings"
    assert run.coverage_notes == []


def test_the_three_are_notes_and_only_the_two_gaps_cast_doubt():
    """Pinned as sets so adding a rule to one without deciding the other fails."""
    assert coverage.LICENCE_STATEMENT_RULES <= coverage.NOTE_RULES
    assert coverage.DOUBT_RULES == {coverage.RULE, coverage.VULNERABILITY_RULE}
    assert coverage.DOUBT_RULES.isdisjoint(coverage.LICENCE_STATEMENT_RULES)
    assert coverage.NOTE_RULES == coverage.DOUBT_RULES | coverage.LICENCE_STATEMENT_RULES


# ------------------------------------------------------------------ the surfaces

def test_the_summary_keeps_what_it_could_not_read_apart_from_what_it_did_not_inspect():
    """Two blocks, two claims. "Part of this repository was not inspected at all" is
    the gap's sentence and stays the gap's; a licence statement gets its own, and it
    says the verdict does not turn on it."""
    from valvur import results

    summary = results._summary(ScanRun(findings=[_statement(STATEMENTS[0]), _gap()]))

    inspected = summary.index("not inspected at all")
    unread = summary.index("could not read")
    assert inspected < unread
    gap_block = summary[inspected:unread]
    assert "Python dependencies were not checked" in gap_block
    assert "Licences could not be determined" not in gap_block
    assert "Licences could not be determined for 600 of 618" in summary[unread:]
    assert "not counted in the verdict" in summary[unread:].lower()


def test_the_summary_without_a_gap_has_no_not_inspected_block_for_a_statement():
    from valvur import results

    summary = results._summary(ScanRun(findings=[_statement(STATEMENTS[2])]))

    assert "Part of this repository was not inspected at all" not in summary
    assert "could not read" in summary
    assert "**Status:** clean" in summary


def test_run_json_counts_a_statement_as_not_covered(tmp_path):
    from valvur import results

    results.write(tmp_path, ScanRun(findings=[_live(), _statement(STATEMENTS[1])]))
    data = json.loads((tmp_path / ".security-scan" / "run.json").read_text())

    assert data["findings"] == {"active": 1, "suppressed": 0, "not_covered": 1, "total": 2}
    assert data["status"] == "findings"


def test_the_gate_never_sees_a_licence_statement_at_any_threshold(tmp_path):
    """The consequence that decides it: `--fail-on any` — our own release gate's
    setting — over a project whose only Finding is a licence valvur could not read."""
    from valvur import gate, results

    results.write(tmp_path, ScanRun(findings=[_statement(r) for r in STATEMENTS]))

    verdict = gate.evaluate(tmp_path, fail_on="any", no_inconclusive=True)

    assert verdict.exit_code == 0, verdict.failures


def test_scan_status_reports_a_statement_as_not_covered_not_active(tmp_path):
    from valvur import results
    from valvur.operations import scan_status

    results.write(tmp_path, ScanRun(findings=[_statement(STATEMENTS[0])]))

    text = scan_status({"workspace": str(tmp_path)})

    assert "status:   clean" in text
    assert "0 active, 1 not covered" in text


# -------------------------------------------------- REMEDIATION.md: actions only

def test_remediation_never_proposes_an_action_for_a_coverage_note():
    """Found while deciding the class: every coverage note went through the action
    grouper, and `valvur.dependency.vulnerabilities-unchecked` — "npm dependencies
    were not checked for known vulnerabilities" — came out as **"Remove the
    hallucinated dependencies"**, on every corpus repository without a lockfile,
    and from there into `scan_status`'s "REMEDIATION.md, action 1 of N". A note is
    a statement about valvur; nothing in the user's code resolves it."""
    from valvur.remediation import render

    note = Finding(rule=coverage.VULNERABILITY_RULE, path="package.json", line=0,
                   title="npm dependencies were not checked for known vulnerabilities")

    text = render([note, _statement(STATEMENTS[0]), _live()])

    assert "hallucinated" not in text
    assert "Resolve licensing" not in text
    assert text.count("\n## ") == 1
    assert "**1 action(s)** resolve **1 finding(s)**" in text
    assert "2 coverage note(s)" in text and "SUMMARY.md" in text


def test_remediation_with_only_notes_says_there_is_nothing_to_do_and_why():
    from valvur.remediation import render

    text = render([_statement(r) for r in STATEMENTS])

    assert "Nothing to remediate" in text
    assert "3 coverage note(s)" in text
    assert "\n## " not in text


# ----------------------------------------------- one target per action (Trivy)

def _trivy_finding(package, installed, fixed):
    from valvur.adapters.trivy import _minimal_fix

    return _minimal_fix(fixed, installed)


@pytest.mark.parametrize("installed,fixed,expected", [
    ("1.0.1", "2.2.2, 1.0.2", "1.0.2"),          # json5 in the golden fixture
    ("2.1.0", "2.2.2, 1.0.2", "2.2.2"),
    ("1.26.5", "2.0.7, 1.26.18", "1.26.18"),     # urllib3, two lines
    ("3.0.0", "1.4.2, 2.0.4, 3.2.1", "3.2.1"),
    ("1.0.1", "1.0.2", "1.0.2"),                  # one fix: unchanged
    ("1.0.1", "", ""),                            # no fix: unchanged
])
def test_trivy_names_the_minimal_fix_above_the_installed_version(installed, fixed, expected):
    """Trivy reports one `FixedVersion` per release line, comma-joined — `"2.2.2,
    1.0.2"` for json5 1.0.1 — and the adapter copied the string, so the proposal
    read *"so `json5` reaches 2.2.2, 1.0.2"*: two targets in one action, the
    major jump first. OSV's adapter already picks the smallest fix above the
    installed version; Trivy's now answers the same way, from the same ordering."""
    assert _trivy_finding("pkg", installed, fixed) == expected


def test_a_fix_list_with_nothing_above_the_installed_version_is_kept_as_trivy_said_it():
    """Not ours to drop: Trivy reported it, and `raw/` and the evidence must agree.
    The one case OSV answers with "" is the one where we keep Trivy's own words."""
    from valvur.adapters.trivy import _minimal_fix

    assert _minimal_fix("1.0.2, 2.2.2", "3.0.0") == "1.0.2, 2.2.2"


def _via_root(package, installed, fix, root="webpack@4.46.0"):
    return Finding(
        rule=f"CVE-{package}-{fix}", path="package-lock.json", line=0, title="t",
        dependency=Dependency(ecosystem="npm", package=package, version=installed,
                              fixed_version=fix, path=(root, f"{package}@{installed}")),
    )


def test_a_root_upgrade_names_what_each_transitive_package_must_reach():
    """The other half of the same sentence. A root group holds findings on several
    packages, and the highest fix across all of them was written after whichever
    package the first finding named — *"so `json5` reaches 1.4.2"*, loader-utils'
    version on json5's name. One target per package, the highest fix each needs."""
    from valvur.remediation import group

    [item] = group([
        _via_root("json5", "1.0.1", "1.0.2"),
        _via_root("loader-utils", "1.4.0", "1.4.1"),
        _via_root("loader-utils", "1.4.0", "1.4.2"),
    ])

    assert item.action == (
        "Upgrade `webpack` so `json5` reaches 1.0.2 and `loader-utils` reaches 1.4.2"
    )


def test_a_root_group_whose_first_finding_has_no_fix_still_names_the_others():
    """The first finding decided the action's shape: with no fix it read "Upgrade
    `webpack`" and the fixes the later findings carried were never written."""
    from valvur.remediation import group

    [item] = group([
        _via_root("json5", "1.0.1", ""),
        _via_root("loader-utils", "1.4.0", "1.4.2"),
    ])

    assert item.action == "Upgrade `webpack` so `loader-utils` reaches 1.4.2"


def test_the_golden_fixture_proposes_one_target_for_json5():
    """End to end through the real adapter and the grouper: the sentence the task
    quotes, from the fixture that produced it."""
    from valvur.adapters.trivy import TrivyAdapter
    from valvur.remediation import render
    from valvur.runner import ScannerOutput

    raw = Path(__file__).parent.joinpath("fixtures/golden/trivy-0.74.0.json").read_text()
    findings = TrivyAdapter().parse(ScannerOutput("trivy", "0.74.0", raw, "", 0))
    json5 = [f for f in findings if f.dependency and f.dependency.package == "json5"]
    assert json5, "the fixture lost its json5 finding"

    assert {f.dependency.fixed_version for f in json5} == {"1.0.2"}
    assert all("to 1.0.2" in f.evidence for f in json5)
    text = render(findings)
    assert "Upgrade `webpack` so `json5` reaches 1.0.2 and `loader-utils` reaches 1.4.2" in text
    assert "2.2.2, 1.0.2" not in text
    # No action anywhere names two versions.
    import re
    assert not re.search(r"(reaches|to) \d[\w.+-]*, \d", text), text


def test_the_terminal_says_could_not_read_rather_than_not_checked(
    tmp_path, capsys, monkeypatch
):
    """The one line a CLI user sees for a note. "not checked" is the gap's word and
    would be false of a licence file valvur opened and could not identify."""
    from conftest import FakeRunner

    from valvur import cli

    def fake_scan(workspace, *, runner, profile, on_progress, jobs=None, budget_s=None):
        return ScanRun(findings=[_statement(STATEMENTS[2]), _gap()], profile=profile)

    monkeypatch.setattr(cli, "scan", fake_scan)
    (tmp_path / "ws").mkdir()

    assert cli.main(["scan", str(tmp_path / "ws")], runner=FakeRunner()) == 0
    out = capsys.readouterr().out

    assert "· could not read: Licence file present but its licence could not be identified" in out
    assert "· not checked: Python dependencies" in out
