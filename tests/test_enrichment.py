"""Sub-phase 5.0 — enrichment metadata on Findings."""

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import CheckovAdapter, OpengrepAdapter, OsvAdapter, TrivyAdapter


def _enriched(workspace):
    runner = GoldenRunner(trivy=golden("trivy"), opengrep=golden("opengrep"),
                          checkov=golden("checkov"), **{"osv-scanner": golden("osv-scanner")})
    return scan(workspace, runner=runner,
                adapters=[TrivyAdapter(), OsvAdapter(), OpengrepAdapter(), CheckovAdapter()])


def test_a_dependency_finding_carries_its_severity(workspace):
    run = _enriched(workspace)

    severities = {f.severity for f in run.findings if f.dependency}
    assert severities and severities <= {"critical", "high", "medium", "low", "unknown"}


def test_a_dependency_finding_carries_the_version_that_fixes_it(workspace):
    run = _enriched(workspace)

    fixable = [f for f in run.findings if f.dependency and f.dependency.fixed_version]
    assert fixable, "no finding knows what to upgrade to"


def test_a_cve_finding_carries_its_identifier_for_enrichment(workspace):
    """5.1 and 5.2 look up KEV and EPSS by CVE; without this they have no key."""
    run = _enriched(workspace)

    assert [f for f in run.findings if f.exploit and f.exploit.cve.startswith("CVE-")]


def test_enrichment_does_not_change_fingerprints(workspace):
    """5.0.3, as a permanent guard rather than a one-off check.

    Enrichment is additive metadata. If any of it ever leaks into the Fingerprint,
    every Suppression in every project using valvur silently stops matching — the
    single most expensive mistake available in this codebase (ADR-0003).
    """
    from valvur.fingerprint import for_dependency_vuln, for_secret

    # Pinned literals. These are a published contract the moment anyone writes a
    # suppression against them, so they are asserted against fixed values rather
    # than against themselves — a self-comparison would pass no matter what changed.
    assert for_secret("aws-access-token", "config.py", "AKIAV7Q2XR4TVBN6WLKJ") == (
        "4e4dff3986a7b9acfb97e1a31fe7aac3"
    )
    assert for_dependency_vuln("pip", "PyYAML", "5.1", "CVE-2019-20477") == (
        "98858e7f381a6275a65e52ff83b37dda"
    )

    run = _enriched(workspace)
    again = _enriched(workspace)
    assert [f.fingerprint for f in run.findings] == [f.fingerprint for f in again.findings]


def test_development_scope_is_distinguished_from_production():
    """F6.6 — a CVE in requirements-dev.txt is real but never ships."""
    from valvur.adapters.trivy import _scope

    assert _scope("requirements-dev.txt") == "development"
    assert _scope("tests/requirements.txt") == "development"
    assert _scope("requirements.txt") == "production"
