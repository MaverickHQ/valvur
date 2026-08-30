"""Sub-phase 5.1-5.3 — enrichment and exploit-aware ranking.

Every scanner in this space sorts by severity, and that is why developers mute them.
Severity says how bad a vulnerability *would* be; KEV and EPSS say whether anyone is
*using* it. When they disagree, the observation wins.
"""

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import TrivyAdapter
from valvur.findings import Dependency, Exploit, Finding
from valvur.ranking import apply


def _f(rule, severity, *, kev=False, ransomware=False, epss=None, scope="production"):
    return Finding(
        rule=rule, path="requirements.txt", line=0, title=rule, severity=severity,
        exploit=Exploit(cve=rule, kev=kev, ransomware=ransomware, epss=epss),
        dependency=Dependency(ecosystem="pip", package="p", version="1", scope=scope),
    )


# ------------------------------------------------------------------- 5.1 KEV

def test_a_cve_in_kev_is_marked_as_exploited():
    from valvur.enrichment import LocalProvider

    enriched = LocalProvider().enrich([_f("CVE-2021-44228", "critical")], network=False)

    assert enriched[0].exploit.kev is True


def test_a_kev_entry_used_in_ransomware_is_flagged():
    """The strongest call to action we can print. 352 of 1,685 entries carry it."""
    from valvur.enrichment import LocalProvider

    enriched = LocalProvider().enrich([_f("CVE-2021-44228", "critical")], network=False)

    assert enriched[0].exploit.ransomware is True


def test_a_cve_absent_from_kev_is_marked_absent_not_unknown():
    """False and None are different claims: 'checked and absent' is reportable,
    'never looked' is not."""
    from valvur.enrichment import LocalProvider

    enriched = LocalProvider().enrich([_f("CVE-2019-20477", "critical")], network=False)

    assert enriched[0].exploit.kev is False


# --------------------------------------------------------------- 5.3 ranking

def test_the_inversion_a_kev_medium_outranks_a_non_kev_critical():
    """F6.5 — the behaviour the whole feature exists for."""
    ranked = apply([
        _f("CVE-not-exploited", "critical", epss=0.0004),
        _f("CVE-in-kev", "medium", kev=True, epss=0.92),
    ])

    assert ranked[0].rule == "CVE-in-kev"
    assert ranked[0].rank == 1


def test_ransomware_outranks_plain_kev():
    ranked = apply([
        _f("CVE-kev-only", "critical", kev=True),
        _f("CVE-ransomware", "low", kev=True, ransomware=True),
    ])

    assert ranked[0].rule == "CVE-ransomware"


def test_a_development_only_dependency_ranks_below_the_same_finding_in_production():
    """F6.6 — the vulnerability is real, but it never ships."""
    ranked = apply([
        _f("CVE-x", "critical", scope="development"),
        _f("CVE-y", "low", scope="production"),
    ])

    assert ranked[0].rule == "CVE-y"


def test_the_noisiest_class_cannot_crowd_out_an_exploited_vulnerability():
    """5.3.11 — 6 of our fixture's 56 findings were unknown-licence noise."""
    ranked = apply([
        Finding(rule="valvur.licence.dependency-unknown", path="sbom", line=0,
                title="unknown", severity="medium"),
        _f("CVE-real", "medium", kev=True),
    ])

    assert ranked[0].rule == "CVE-real"


def test_the_inversion_holds_against_real_scanner_output(workspace):
    """5.3.10 — synthetic tests prove the function; this proves the wiring.

    Pillow 10.0.0 carries CVE-2023-4863, one of very few PyPI-reachable CVEs in KEV.
    It is rated `high` and must still outrank the `critical` CVEs beside it.
    """
    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()], profile="quick")

    top = min(run.findings, key=lambda f: f.rank)

    assert top.exploit.kev is True
    assert top.severity == "high"
    assert any(f.severity == "critical" and not f.exploit.kev for f in run.findings)


def test_ranking_reorders_the_written_summary(workspace):
    """A correct rank field that nothing sorts by would be a silent no-op."""
    scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
         adapters=[TrivyAdapter()], profile="quick")

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()
    ranked = [ln for ln in summary.splitlines() if ln.startswith("1. ")]

    assert ranked and "KEV" in ranked[0], (
        "the exploited finding is not at the top of the output"
    )


# --------------------------------------------- 5.4 dependency path and scope

def test_a_transitive_vulnerability_reports_the_package_you_can_actually_change(workspace):
    """F6.9 — 'upgrade json5' is useless when json5 is three levels down and pinned
    by something else. The direct dependency is the actionable one."""
    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()], profile="quick")

    transitive = [f for f in run.findings if f.dependency and len(f.dependency.path) > 1]

    assert transitive, "no dependency path was resolved"
    example = transitive[0]
    assert "webpack" in example.dependency.path[0]
    assert "change webpack" in example.evidence


def test_a_flat_manifest_yields_no_path_because_none_exists(workspace):
    """Verified in task 5.4.12: requirements.txt is flat and carries no transitive
    information. Reporting a path there would be an invention, not a limitation."""
    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()], profile="quick")

    flat = [f for f in run.findings
            if f.dependency and f.path.endswith("requirements.txt")]

    assert flat
    assert all(len(f.dependency.path) <= 1 for f in flat)
