"""Sub-phase 3.3 cycles 10, 12, 13 — OSV-Scanner, Checkov, Syft."""

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import CheckovAdapter, OsvAdapter, SyftAdapter, TrivyAdapter


def test_osv_vulnerabilities_become_findings(workspace):
    run = scan(workspace, runner=GoldenRunner(**{"osv-scanner": golden("osv-scanner")}),
               adapters=[OsvAdapter()])

    assert len(run.findings) > 0


def test_osv_and_trivy_agree_on_identity_so_their_findings_merge(workspace):
    """F5.8 — the two overlap heavily. Reporting everything twice would be noise,
    and the ecosystem naming differs ('PyPI' vs 'pip'), so identity must normalise."""
    runner = GoldenRunner(trivy=golden("trivy"), **{"osv-scanner": golden("osv-scanner")})

    run = scan(workspace, runner=runner, adapters=[TrivyAdapter(), OsvAdapter()])

    both = [f for f in run.findings if len(f.sources) > 1]
    assert both, "no findings merged — the two scanners disagree on identity"
    assert {"trivy", "osv-scanner"} == set(both[0].sources)


def test_checkov_findings_carry_the_resource_address(workspace):
    """The resource address is the identity (ADR-0003) and what a developer greps for."""
    run = scan(workspace, runner=GoldenRunner(checkov=golden("checkov")),
               adapters=[CheckovAdapter()])

    addresses = {f.evidence for f in run.findings}
    assert "aws_security_group.wide_open" in addresses


def test_syft_writes_a_cyclonedx_sbom(workspace):
    import json

    scan(workspace, runner=GoldenRunner(syft=golden("syft")), adapters=[SyftAdapter()])

    sbom = json.loads((workspace / ".security-scan" / "sbom.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"


def test_opengrep_results_become_findings(workspace):
    from valvur.adapters import OpengrepAdapter

    run = scan(workspace, runner=GoldenRunner(opengrep=golden("opengrep")),
               adapters=[OpengrepAdapter()])

    assert "valvur.python.dangerous-eval" in [f.rule for f in run.findings]


def test_byte_identical_matches_in_one_file_get_distinct_fingerprints(workspace):
    """Cycle 11 — the SAST class is the only one that can collide, so ordinal
    disambiguation must actually be applied, not merely available."""
    from valvur.adapters import OpengrepAdapter

    run = scan(workspace, runner=GoldenRunner(opengrep=golden("opengrep")),
               adapters=[OpengrepAdapter()])

    duplicates = [f for f in run.findings if f.evidence == "return eval(user_input)"]

    assert len(duplicates) == 2, "the identical pair collapsed into one finding"
    assert duplicates[0].fingerprint != duplicates[1].fingerprint


def test_rule_identity_survives_the_rules_directory_moving(workspace):
    """Opengrep prefixes ids with the config path; identity must not depend on it."""
    from valvur.adapters import OpengrepAdapter

    run = scan(workspace, runner=GoldenRunner(opengrep=golden("opengrep")),
               adapters=[OpengrepAdapter()])

    assert all(f.rule.startswith("valvur.") for f in run.findings)
