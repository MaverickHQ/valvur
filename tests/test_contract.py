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
