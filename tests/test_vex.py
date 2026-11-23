"""R50.5: a project's own VEX, honoured only where the project says so (D82m, ADR-0035).

`.security-scan.toml` may name an OpenVEX document and a date it is accepted until. A
statement in it that a dependency is not affected by a vulnerability, or has it fixed,
suppresses that Finding, and the Finding says so with the document's author and time. Every
way a document could lower a Finding it should not, or fail in silence, is refused or
reported. valvur writes no VEX. Trivy is faked by an adapter that returns canned Findings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api, gate, verdict
from valvur import fingerprint as _fp
from valvur.engine_host import LocalRuntime
from valvur.findings import Dependency, Finding
from valvur.invocation import Invocation
from valvur.refusal import Refusal

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"
CVE, PURL = "CVE-2026-0001", "pkg:pypi/requests@2.19.1"
VULNERABLE = Finding(
    rule=CVE, path="requirements.txt", line=0, title="requests: a flaw", severity="high",
    fingerprint=_fp.derive("pip", "requests", "2.19.1", CVE), sources=("trivy",),
    aliases=("GHSA-aaaa-bbbb-cccc",),
    dependency=Dependency(ecosystem="pip", package="requests", version="2.19.1", purl=PURL))
CODE = Finding(rule=CVE, path="app/x.py", line=3, title="a rule that shares the name",
               severity="high", fingerprint=_fp.derive(CVE, "app/x.py"), sources=("opengrep",))


class _Scanner:
    artifact = None
    kind = "scanner"
    version = "1"

    def __init__(self, name: str, found: list[Finding]):
        self.name, self.found = name, found

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool=self.name, version="1", report=f"{self.name}.json", timeout=60,
                          argv=("fake-report", "0", "{}", f"/results/{self.name}.json"))

    def parse(self, output):
        return list(self.found)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    (ws / "app" / "x.py").write_text("x = 1\n")
    return ws


def _statement(status: str = "not_affected", *, name: str = CVE, product: str = PURL,
               **more) -> dict:
    if status == "not_affected" and "justification" not in more and "impact_statement" not in more:
        more["justification"] = "vulnerable_code_not_in_execute_path"
    return {"vulnerability": {"name": name}, "products": [{"@id": product}], "status": status,
            **{k: v for k, v in more.items() if v is not None}}


def _vex(ws: Path, *statements: dict, expires: str = "2099-01-01", declared: bool = True,
         path: str = "security/valvur.openvex.json") -> None:
    (ws / path).parent.mkdir(parents=True, exist_ok=True)
    (ws / path).write_text(json.dumps({
        "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.invalid/vex/1",
        "author": "the platform team", "timestamp": "2026-11-01T09:00:00Z", "version": 1,
        "statements": list(statements)}))
    if declared:
        (ws / ".security-scan.toml").write_text(
            f'[[vex]]\npath = "{path}"\nexpires = {expires}\n')


def _scan(ws: Path, *found: Finding):
    found = found or (VULNERABLE,)
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS),
                   adapters=[_Scanner("trivy", [f for f in found if "trivy" in f.sources]),
                             _Scanner("opengrep", [f for f in found if "opengrep" in f.sources])])
    records = json.loads((ws / RESULTS / "findings.json").read_text())["findings"]
    return run, {r["rule"] + " " + r["path"]: r for r in records}


def test_a_not_affected_statement_suppresses_the_finding_and_says_who_said_so(workspace):
    _vex(workspace, _statement())

    run, records = _scan(workspace)

    record = records[f"{CVE} requirements.txt"]
    assert record["suppressed"] == (
        "VEX not_affected: vulnerable_code_not_in_execute_path (the platform team, "
        "2026-11-01T09:00:00Z), accepted until 2099-01-01")
    assert not verdict.active(record) and run.status == "clean"
    summary = " ".join((workspace / RESULTS / "SUMMARY.md").read_text().split())
    assert "suppressed:** 1" in summary
    assert gate.evaluate(workspace, fail_on="any").exit_code == 0


def test_a_fixed_statement_does_the_same(workspace):
    _vex(workspace, _statement("fixed"))

    _run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"].startswith(
        "VEX fixed (the platform team, ")


def test_an_alias_of_the_finding_is_its_vulnerability_too(workspace):
    _vex(workspace, _statement(name="GHSA-aaaa-bbbb-cccc"))

    _run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"]


@pytest.mark.parametrize("status", ["affected", "under_investigation"])
def test_a_statement_that_does_not_clear_the_package_changes_nothing(workspace, status):
    _vex(workspace, _statement(status))

    run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"] is None and run.status == "findings"


@pytest.mark.parametrize("statement, why", [
    (_statement(product="pkg:pypi/requests"), "names no version of the package"),
    (_statement(justification=None, impact_statement=None) | {"status": "not_affected"},
     "gives neither a justification nor an impact statement"),
])
def test_a_statement_that_would_apply_and_is_not_honoured_is_reported(workspace, statement, why):
    statement = {k: v for k, v in statement.items() if k != "justification"} \
        if "neither" in why else statement
    _vex(workspace, statement)

    _run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"] is None
    [said] = [r for r in records.values() if r["rule"] == "valvur.vex.not-honoured"]
    assert said["title"] == (f"A VEX statement for {CVE} in `security/valvur.openvex.json` "
                             f"{why}, and was not honoured")
    assert said["severity"] == "low"


def test_another_version_of_the_package_is_another_product(workspace):
    _vex(workspace, _statement(product="pkg:pypi/requests@2.31.0"))

    _run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"] is None
    assert "valvur.vex.not-honoured security/valvur.openvex.json" not in records


def test_a_statement_cannot_suppress_what_is_not_a_dependency_vulnerability(workspace):
    _vex(workspace, _statement())

    _run, records = _scan(workspace, VULNERABLE, CODE)

    assert records[f"{CVE} requirements.txt"]["suppressed"]
    assert records[f"{CVE} app/x.py"]["suppressed"] is None


def test_an_entry_past_its_date_is_a_lapsed_suppression_and_fails_every_gate(workspace):
    _vex(workspace, _statement(), expires="2020-01-01")

    _run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"] is None
    [lapsed] = [r for r in records.values() if r["rule"] == "valvur.suppression.expired"]
    assert "`security/valvur.openvex.json` was accepted until 2020-01-01" in lapsed["title"]
    assert gate.evaluate(workspace, fail_on="critical").exit_code == 1


def test_statements_that_match_nothing_are_counted_at_low_and_pass_a_gate_at_high(workspace):
    _vex(workspace, _statement(), _statement(name="CVE-2019-9999"),
         _statement(product="pkg:npm/left-pad@1.0.0"))

    _run, records = _scan(workspace)

    [unused] = [r for r in records.values() if r["rule"] == "valvur.vex.unused"]
    assert unused["title"] == "2 statement(s) in `security/valvur.openvex.json` match nothing here"
    assert unused["severity"] == "low"
    assert gate.evaluate(workspace, fail_on="high").exit_code == 0


def test_a_document_no_entry_names_is_never_read(workspace):
    _vex(workspace, _statement(), declared=False)

    run, records = _scan(workspace)

    assert records[f"{CVE} requirements.txt"]["suppressed"] is None and run.status == "findings"


@pytest.mark.parametrize("how", ["dots", "absolute", "a link"])
def test_a_path_that_leaves_the_workspace_is_refused_at_the_call(workspace, tmp_path, how):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    if how == "a link":
        (workspace / "security").mkdir()
        (workspace / "security" / "vex.json").symlink_to(outside)
    named = {"dots": "../outside.json", "absolute": str(outside), "a link": "security/vex.json"}
    (workspace / ".security-scan.toml").write_text(
        f'[[vex]]\npath = "{named[how]}"\nexpires = 2099-01-01\n')

    with pytest.raises(Refusal, match="outside the project"):
        _scan(workspace)

    assert not (workspace / RESULTS / "findings.json").exists()


@pytest.mark.parametrize("text", ["not json", "{}", '{"@context": "https://example.invalid"}',
                                  '{"@context": "https://openvex.dev/ns/v0.2.0"}'])
def test_a_document_that_is_not_openvex_is_an_error_that_names_it(workspace, text):
    _vex(workspace, _statement())
    (workspace / "security" / "valvur.openvex.json").write_text(text)

    with pytest.raises(Refusal, match=r"valvur\.openvex\.json") as refused:
        _scan(workspace)

    assert "did not go on without it" in str(refused.value)
    assert not (workspace / RESULTS / "findings.json").exists()


def test_an_entry_with_no_expiry_is_refused(workspace):
    _vex(workspace, _statement())
    (workspace / ".security-scan.toml").write_text(
        '[[vex]]\npath = "security/valvur.openvex.json"\n')

    with pytest.raises(Refusal, match="needs a `path` and a date"):
        _scan(workspace)


# ---- the project file's schema, the tools, and the skill


@pytest.mark.parametrize("text, named", [
    ('[[vex]]\npath = "security/x.openvex.json"\nexpires = 2027-05-21\n', None),
    ('[[vex]]\npath = "security/x.openvex.json"\n', "vex[0].expires"),
    ('[[vex]]\nexpires = 2027-05-21\n', "vex[0].path"),
    ('[[vex]]\npath = "x.json"\nexpires = 2027-05-21\nstatus = "not_affected"\n',
     "vex[0].status"),
])
def test_doctor_and_the_schema_know_the_entry(text, named):
    import tomllib

    from valvur import project_schema

    said = project_schema.problem(tomllib.loads(text))

    assert (said is None) if named is None else (said is not None and said.startswith(
        f"`{named}`")), said


def test_no_tool_and_no_command_writes_or_prints_a_vex_statement(capsys):
    """Widened from the test that holds `scan_and_fix`'s absence (ADR-0009): a VEX
    statement is a risk acceptance, and valvur writes none of those."""
    from valvur import cli
    from valvur.mcp.tools import FORBIDDEN, registry

    assert "vex" in FORBIDDEN
    assert not [tool.name for tool in registry() if "vex" in tool.name.lower()]
    commands = cli.build_parser()._subparsers._group_actions[0].choices
    assert not [name for name in commands if "vex" in name.lower()]
    cli.main(["suppress", "0" * 32, "--reason", "r"])
    assert "openvex" not in capsys.readouterr().out.lower()


def test_the_skills_rule_on_suppressions_names_vex_in_every_copy():
    repo = Path(__file__).resolve().parents[1]
    copies = [repo / "src/valvur/data/skills/valvur/SKILL.md",
              repo / "plugins/valvur/skills/valvur/SKILL.md",
              repo / "powers/valvur/skills/valvur/SKILL.md"]

    for copy in copies:
        text = " ".join(copy.read_text().split())
        assert "or a `[[vex]]` entry" in text, copy
        assert text.count("`[[vex]]`") >= 2, copy


def test_a_statement_that_matches_and_changes_nothing_is_not_counted_as_unused(workspace):
    """`affected` says the Finding is right. It matches something here, so the count of
    statements that match nothing is not for it."""
    _vex(workspace, _statement("affected"), _statement("under_investigation"))

    _run, records = _scan(workspace)

    assert not [r for r in records.values() if r["rule"] == "valvur.vex.unused"]


def test_a_finding_a_suppression_already_accepts_keeps_its_reason(workspace):
    _vex(workspace, _statement())
    (workspace / ".security-scan.toml").write_text(
        (workspace / ".security-scan.toml").read_text()
        + f'\n[[suppress]]\nfingerprint = "{VULNERABLE.fingerprint}"\nrule = "{CVE}"\n'
        'path = "requirements.txt"\nexpires = 2099-01-01\nreason = "accepted by hand"\n')

    _run, records = _scan(workspace)

    assert "VEX" not in records[f"{CVE} requirements.txt"]["suppressed"]
    assert not [r for r in records.values() if r["rule"] == "valvur.vex.unused"]
