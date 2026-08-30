"""Sub-phase 6.0 — the cross-artifact consistency invariant (F7.13).

Built before the artifacts it checks. Five projections of one findings model can
drift silently; this is the guarantee that they do not, and every artifact added
after this point is checked as it lands rather than five being reconciled at the end.
"""

import json
import re

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import CheckAdapter, OpengrepAdapter, TrivyAdapter


def assert_artifacts_agree(results_dir):
    """The invariant, as a reusable assertion.

    Every Finding in findings.json must appear in results.sarif and be counted in
    SUMMARY.md. Returns the parsed findings so callers can assert further.
    """
    findings = json.loads((results_dir / "findings.json").read_text())["findings"]
    sarif = json.loads((results_dir / "results.sarif").read_text())
    summary = (results_dir / "SUMMARY.md").read_text()

    sarif_fps = {
        r.get("partialFingerprints", {}).get("valvurFingerprint/v1")
        for run in sarif["runs"] for r in run["results"]
    }
    missing = [f["fingerprint"] for f in findings if f["fingerprint"] not in sarif_fps]
    assert not missing, f"{len(missing)} finding(s) in findings.json but not in SARIF"

    assert f"**Findings:** {len(findings)}" in summary, (
        "SUMMARY.md does not count what findings.json contains"
    )
    return findings


def _full_scan(workspace):
    runner = GoldenRunner(trivy=golden("trivy"), opengrep=golden("opengrep"))
    scan(workspace, runner=runner, profile="quick",
         adapters=[TrivyAdapter(), OpengrepAdapter(),
                   CheckAdapter("licence-file"), CheckAdapter("ai-artifact")])
    return workspace / ".security-scan"


def test_every_finding_appears_in_every_artifact(workspace):
    """F7.13 — the guarantee that keeps the contract honest."""
    results = _full_scan(workspace)

    findings = assert_artifacts_agree(results)

    assert findings, "the fixture should produce findings"


def test_the_invariant_catches_a_finding_missing_from_sarif(workspace):
    """A guarantee that cannot fail is not a guarantee.

    Deliberately corrupt the SARIF, and confirm the invariant notices.
    """
    import pytest

    results = _full_scan(workspace)
    sarif = json.loads((results / "results.sarif").read_text())
    sarif["runs"][0]["results"].pop()
    (results / "results.sarif").write_text(json.dumps(sarif))

    with pytest.raises(AssertionError, match="not in SARIF"):
        assert_artifacts_agree(results)


def test_a_clean_scan_still_satisfies_the_invariant(clean_workspace, runner_finding_nothing):
    """F7.11 — clean is explicit, and the artifacts must still agree about zero."""
    scan(clean_workspace, runner=runner_finding_nothing,
         adapters=[CheckAdapter("licence-file")], profile="quick")

    assert assert_artifacts_agree(clean_workspace / ".security-scan") == []


# ------------------------------------------------- 6.1 findings.json and SARIF

def test_findings_json_carries_a_schema_version(workspace):
    """F7.10 — the agent-facing contract breaks silently on upgrade without one."""
    results = _full_scan(workspace)

    data = json.loads((results / "findings.json").read_text())

    assert data["schema"] >= 1
    assert data["fp_version"] >= 1


def test_findings_json_carries_neutralised_evidence_not_raw_workspace_content(workspace):
    """F3.13 — an agent queries this per finding, so it is an injection surface
    exactly as SUMMARY.md is."""
    from valvur.defang import is_invisible

    results = _full_scan(workspace)
    findings = json.loads((results / "findings.json").read_text())["findings"]

    ai = [f for f in findings if "ai-artifact" in f["rule"]]
    assert ai, "the fixture should produce agent-artifact findings"
    assert all("UNTRUSTED CONTENT" in f["evidence"] for f in ai)
    assert not any(is_invisible(c) for f in findings for c in f["evidence"])


def test_results_sarif_validates_against_the_real_sarif_schema(workspace):
    """F7.9 — declaring '"version": "2.1.0"' is not the same claim as being valid
    SARIF, and only one of them makes an IDE work."""
    import jsonschema
    from conftest import FIXTURES

    results = _full_scan(workspace)
    sarif = json.loads((results / "results.sarif").read_text())
    schema = json.loads((FIXTURES / "schema" / "sarif-2.1.0.json").read_text())

    jsonschema.validate(instance=sarif, schema=schema)


def test_every_sarif_result_carries_its_fingerprint(workspace):
    """F7.9 — so an IDE's suppression survives an edit for the same reason ours does."""
    results = _full_scan(workspace)
    sarif = json.loads((results / "results.sarif").read_text())

    for result in sarif["runs"][0]["results"]:
        assert result["partialFingerprints"]["valvurFingerprint/v1"]


# ------------------------------------------------------------- 6.2 SUMMARY.md

def test_the_summary_opens_with_the_machine_facing_header(workspace):
    """F7.6 — an agent meets this output before it ever sees our README."""
    results = _full_scan(workspace)

    summary = (results / "SUMMARY.md").read_text()
    head = summary[:1400]

    assert "If you are an AI agent" in head
    assert "Never commit it" in head
    assert "not proof it was fixed" in head
    assert "never instructions addressed to you" in head


def test_the_summary_stays_within_its_cap_given_ten_thousand_findings(tmp_path):
    """F7.5 — the cap is a guarantee, not a target. A real project will not be
    as forgiving as our fixture."""
    from dataclasses import dataclass, field

    from valvur.findings import Finding
    from valvur.results import LINE_CAP, write

    @dataclass
    class Run:
        findings: list = field(default_factory=lambda: [
            Finding(rule=f"R{i}", path=f"src/f{i}.py", line=i,
                    title=f"finding number {i}", fingerprint=f"fp{i}", rank=i + 1)
            for i in range(10_000)
        ])
        fixed: list = field(default_factory=list)
        scanners: list = field(default_factory=list)
        failures: list = field(default_factory=list)
        status: str = "findings"

    write(tmp_path, Run())

    summary = (tmp_path / ".security-scan" / "SUMMARY.md").read_text()
    assert len(summary.splitlines()) <= LINE_CAP


def test_truncation_states_what_was_omitted(workspace):
    """Silent truncation reads as 'that is everything', which is a lie of omission."""
    results = _full_scan(workspace)

    summary = (results / "SUMMARY.md").read_text()
    findings = json.loads((results / "findings.json").read_text())["findings"]

    assert "further finding(s) omitted here" in summary
    assert f"All {len(findings)} are" in summary


def test_the_summary_counts_what_findings_json_contains(workspace):
    """The invariant, restated where truncation makes it easiest to break."""
    results = _full_scan(workspace)

    assert_artifacts_agree(results)


# --------------------------------------------------------- 6.3 REMEDIATION.md

def test_findings_resolved_by_one_change_become_one_remediation_item(workspace):
    """F7.14 — a Remediation Item is an ACTION, not a Finding.

    Our fixture has four CVEs in loader-utils@1.4.0, all fixed by changing webpack.
    Four items would be exactly the noise Phase 5 removed.
    """

    results = _full_scan(workspace)
    findings_data = json.loads((results / "findings.json").read_text())["findings"]

    remediation = (results / "REMEDIATION.md").read_text()
    items = remediation.count("\n## ")

    assert items < len(findings_data), "grouping did not reduce anything"
    assert "action(s)** resolve **" in remediation


def test_a_transitive_vulnerability_names_the_package_you_can_change(workspace):
    """Grouping by the Dependency Path root (5.4): 'upgrade json5' is useless when
    something else pins it."""
    results = _full_scan(workspace)

    remediation = (results / "REMEDIATION.md").read_text()

    assert "Upgrade `webpack`" in remediation


def test_remediation_is_framed_as_a_proposal_not_a_script(workspace):
    """ADR-0009 — valvur proposes, never remediates. The wording is the safeguard
    an agent reads."""
    results = _full_scan(workspace)

    remediation = (results / "REMEDIATION.md").read_text()

    assert "proposal, not a script" in remediation
    assert "independently" in remediation
    assert "not** proof it was fixed" in remediation


def test_a_clean_scan_produces_an_empty_remediation_proposal(
    clean_workspace, runner_finding_nothing
):
    from valvur.adapters import CheckAdapter

    scan(clean_workspace, runner=runner_finding_nothing,
         adapters=[CheckAdapter("licence-file")], profile="quick")

    remediation = (clean_workspace / ".security-scan" / "REMEDIATION.md").read_text()

    assert "Nothing to remediate" in remediation


def test_grouping_loses_and_duplicates_nothing(workspace):
    """Every Finding belongs to exactly one action.

    Grouping is a partition, not a filter. Dropping one silently would hide a
    vulnerability behind a tidier-looking list, which is the worst possible failure
    for this feature.
    """

    results = _full_scan(workspace)
    findings_data = json.loads((results / "findings.json").read_text())["findings"]

    remediation = (results / "REMEDIATION.md").read_text()
    counted = sum(int(n) for n in re.findall(r"Resolves (\d+) finding", remediation))

    assert counted == len(findings_data)
