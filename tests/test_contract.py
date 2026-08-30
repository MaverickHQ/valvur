"""Sub-phase 6.0 — the cross-artifact consistency invariant (F7.13).

Built before the artifacts it checks. Five projections of one findings model can
drift silently; this is the guarantee that they do not, and every artifact added
after this point is checked as it lands rather than five being reconciled at the end.
"""

import json

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
