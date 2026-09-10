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
from valvur.coverage import RULE as COVERAGE_RULE


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

    # Since 7.2 the summary counts active and suppressed separately (F8.9), so the
    # invariant checks the SPLIT sums to the whole rather than assuming one number.
    # A suppressed finding vanishing from both counts is exactly what this catches.
    #
    # Three parts since 19.C.1, not two. A coverage note is a Finding — fingerprinted,
    # in SARIF, suppressible — but it is a statement about valvur's reach, not about
    # the scanned code, so it is counted on its own line. The invariant is still that
    # the parts account for every Finding: nothing may vanish from all three.
    active = [f for f in findings
              if not f.get("suppressed") and f["rule"] != COVERAGE_RULE]
    suppressed = [f for f in findings if f.get("suppressed")]
    notes = [f for f in findings
             if not f.get("suppressed") and f["rule"] == COVERAGE_RULE]

    assert len(active) + len(suppressed) + len(notes) == len(findings), (
        "the split does not account for every finding in findings.json"
    )
    assert f"**Active findings:** {len(active)}" in summary, (
        "SUMMARY.md does not count the active findings in findings.json"
    )
    if suppressed:
        assert f"**suppressed:** {len(suppressed)}" in summary, (
            "SUMMARY.md does not count the suppressed findings in findings.json"
        )
    if notes:
        assert f"**not covered:** {len(notes)}" in summary, (
            "SUMMARY.md does not count the coverage notes in findings.json"
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

    # Content from an agent instruction file is fenced unconditionally: the file
    # exists to instruct an agent, so everything in one is a directive whether or not
    # it reads like prose.
    ai = [f for f in findings if "ai-artifact" in f["rule"]]
    assert ai, "the fixture should produce agent-artifact findings"
    assert all("UNTRUSTED CONTENT" in f["evidence"] for f in ai)

    # Everywhere else, fencing is selective — our own advice should not be buried in
    # warnings — but invisible characters are escaped universally.
    ours = [f for f in findings if f["rule"].startswith("CVE-")]
    assert ours and not any("UNTRUSTED CONTENT" in f["evidence"] for f in ours)

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

    # The "All N are in findings.json" pointer counts the ACTIVE findings, which is
    # what the truncated list above it contains. Counting every Finding would send the
    # reader looking for entries that were never in that list — a coverage note is in
    # findings.json but is reported in its own block, not among the most urgent.
    active = [f for f in findings
              if not f.get("suppressed") and f["rule"] != COVERAGE_RULE]

    assert "further finding(s) omitted here" in summary
    assert f"All {len(active)} are" in summary


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


# ------------------------------------------------------------------ 6.4 raw/

def test_raw_preserves_each_scanners_own_output(workspace):
    """F2.8, P2 — the credibility artifact. When we say Trivy found CVE-X, a
    reviewer must be able to check we did not mangle it."""
    results = _full_scan(workspace)

    raw = results / "raw"
    assert raw.is_dir()
    trivy = json.loads((raw / "trivy.json").read_text())

    # Trivy's own shape, not ours.
    assert "Results" in trivy


def test_no_secret_value_appears_anywhere_in_the_results_folder(workspace):
    """F5.7, re-asserted at the riskiest surface.

    raw/ is PRE-MODEL scanner output and bypasses the Finding-boundary redaction
    entirely. Gitleaks emits live credential values in its JSON, so without a pass of
    its own our security tool would copy your credentials to a second cleartext
    location on disk.
    """
    from conftest import GoldenRunner

    runner = GoldenRunner(gitleaks=json.dumps([{
        "RuleID": "aws-access-token", "Description": "AWS Access Token",
        "File": "/workspace/config.py", "StartLine": 9,
        "Secret": "AKIAV7Q2XR4TVBN6WLKJ",
        "Match": 'AWS_ACCESS_KEY_ID = "AKIAV7Q2XR4TVBN6WLKJ"',
    }]))
    from valvur.adapters import GitleaksAdapter

    scan(workspace, runner=runner, adapters=[GitleaksAdapter()], profile="quick")

    for path in (workspace / ".security-scan").rglob("*"):
        if path.is_file():
            assert "AKIAV7Q2XR4TVBN6WLKJ" not in path.read_text(encoding="utf-8"), (
                f"secret leaked into {path.name}"
            )


def test_the_raw_scrubber_is_actually_doing_the_work():
    """A redaction that never had anything to remove proves nothing."""
    from valvur.rawoutput import scrub, secrets_in

    gitleaks = json.dumps([{"Secret": "AKIAV7Q2XR4TVBN6WLKJ",
                            "Match": 'KEY = "AKIAV7Q2XR4TVBN6WLKJ"'}])

    secrets = secrets_in(gitleaks)
    assert "AKIAV7Q2XR4TVBN6WLKJ" in secrets

    scrubbed = scrub(gitleaks, secrets)
    assert "AKIAV7Q2XR4TVBN6WLKJ" not in scrubbed
    assert "REDACTED:" in scrubbed


def test_raw_prunes_older_runs(workspace, tmp_path):
    """N3.3 — raw/ is the bulk of the folder and grows without this."""
    from valvur.rawoutput import KEEP_RUNS, write

    results = tmp_path / ".security-scan"
    results.mkdir()
    for i in range(KEEP_RUNS + 3):
        (results / f"raw-{i:03d}").mkdir()

    write(results, [("trivy", "{}")])

    archives = sorted(p for p in results.glob("raw-*") if p.is_dir())
    assert len(archives) == KEEP_RUNS
