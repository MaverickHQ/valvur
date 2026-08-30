"""Sub-phase 3.3 cycle 9 — Trivy."""

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import TrivyAdapter


def test_trivy_dependency_vulnerabilities_become_findings(workspace):
    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()])

    assert "CVE-2019-20477" in [f.rule for f in run.findings]


def test_a_trivy_finding_carries_the_package_and_the_version_that_fixes_it(workspace):
    """Unactionable without both: you cannot fix 'PyYAML is vulnerable'."""
    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()])

    finding = next(f for f in run.findings if f.rule == "CVE-2019-20477")

    assert "PyYAML" in finding.title
    assert "5.2" in finding.evidence


def test_upgrading_the_package_would_retire_the_finding(workspace):
    """Identity includes the installed version (Phase 2), so a bump marks it fixed."""
    from valvur.fingerprint import for_dependency_vuln

    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()])
    finding = next(f for f in run.findings if f.rule == "CVE-2019-20477")

    assert finding.fingerprint == for_dependency_vuln("pip", "PyYAML", "5.1", "CVE-2019-20477")
