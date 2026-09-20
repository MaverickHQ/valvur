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


# ------------------------------------------------ OSV-Scanner 2.6.0 (2026-09-20)

def test_a_file_osv_scanner_reads_twice_is_reported_once():
    """OSV-Scanner 2.6.0 (from 2.2.4, by Dependabot) reports `requirements.txt` in
    two result blocks: the lockfile extractor's, and a second of `type: unknown`
    whose versions are PEP 440-normalised — `pyyaml 5.1` and `pyyaml 5.1.0`, six
    advisories each, two identities. The golden holds both; the adapter keeps the
    lockfile block and drops the other for the same path."""
    from valvur.runner import ScannerOutput

    output = ScannerOutput("osv-scanner", "2.6.0", golden("osv-scanner"), "", 0)
    findings = OsvAdapter().parse(output)

    pyyaml = {(f.dependency.package, f.dependency.version) for f in findings
              if f.dependency.package == "pyyaml"}
    assert pyyaml == {("pyyaml", "5.1")}, pyyaml
    # 35 advisory entries in one block (18 identities once aliases merge, as
    # before); the second block would have made it 70.
    pillow = [f for f in findings if f.dependency.package == "pillow"]
    assert len(pillow) == 35, len(pillow)


def test_a_path_that_only_the_unknown_extractor_read_is_still_reported():
    """The other half: `unknown` is dropped only where a lockfile block covers the
    same path. A file only the generic extractor understood keeps its findings."""
    import json

    from valvur.runner import ScannerOutput

    report = {"results": [{
        "source": {"path": "/workspace/setup.py", "type": "unknown"},
        "packages": [{"package": {"name": "pillow", "version": "10.0.0", "ecosystem": "PyPI"},
                      "vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-2023-4863"]}]}],
    }]}

    findings = OsvAdapter().parse(ScannerOutput("osv-scanner", "2.6.0", json.dumps(report), "", 0))

    assert [f.rule for f in findings] == ["CVE-2023-4863"]


def test_osv_scanner_2_6_reads_the_npm_lockfile_and_merges_with_trivy(workspace):
    """2.2.4 reported nothing for the fixture's `package-lock.json`; 2.6.0 does, so
    what it reports has to land on Trivy's identities rather than beside them."""
    runner = GoldenRunner(trivy=golden("trivy"), **{"osv-scanner": golden("osv-scanner")})

    run = scan(workspace, runner=runner, adapters=[TrivyAdapter(), OsvAdapter()])

    npm = [f for f in run.findings if f.dependency and f.dependency.ecosystem == "npm"]
    assert npm, "no npm findings at all"
    assert any(len(f.sources) > 1 for f in npm), "OSV's npm findings did not merge with Trivy's"
