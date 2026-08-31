"""Sub-phase 10.3b — false positives found by scanning a real project.

A synthetic fixture is generous: it has no vendored dependencies, no `.env`, and
nothing a developer cannot fix. A real 260k-line codebase produced 20 findings, of
which six were numpy's own test files inside a build directory and two were secrets
in a gitignored `.env`. None of that was visible until then.
"""

from valvur.exclusions import filter_findings, is_vendored
from valvur.findings import Exploit, Finding
from valvur.ranking import apply


def _f(rule, path="src/app.py", severity="medium", **kw):
    return Finding(rule=rule, path=path, line=1, title=rule, severity=severity, **kw)


# ------------------------------------------------------- vendored code

def test_findings_in_build_directories_are_excluded():
    """30% of a real scan's findings were numpy's test fixtures inside .aws-sam/build."""
    kept, dropped = filter_findings([
        _f("generic-api-key", ".aws-sam/build/CampaignFunction/numpy/random/tests/t.py"),
        _f("generic-api-key", "node_modules/pkg/index.js"),
        _f("generic-api-key", "src/app.py"),
    ])

    assert [f.path for f in kept] == ["src/app.py"]
    assert dropped == 2


def test_exclusion_matches_path_segments_not_substrings():
    """`src/distribution/` must survive containing the letters 'dist'."""
    assert is_vendored("app/dist/bundle.js")
    assert not is_vendored("src/distribution/report.py")
    assert not is_vendored("src/building/plan.py")


def test_the_number_excluded_is_reported_not_hidden():
    """Silently dropping findings is how a scanner conceals something. A user who
    vendored a genuinely vulnerable copy deserves to know we skipped it."""
    _, dropped = filter_findings([_f("x", "vendor/lib/a.py"), _f("y", "vendor/lib/b.py")])

    assert dropped == 2


# ------------------------------------------------------- gitignored secrets

def test_a_secret_in_a_gitignored_file_is_not_critical(tmp_path):
    """Every developer has a .env. Keeping credentials out of git is the CORRECT
    practice, and flagging it critical penalises the right behaviour."""
    import subprocess

    from valvur import gitcontext

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("TOKEN=abc\n")

    findings = gitcontext.apply(tmp_path, [_f("telegram-bot-api-token", ".env", "critical")])

    assert findings[0].severity == "medium"
    assert "git is ignoring" in findings[0].title


def test_a_secret_in_a_tracked_file_stays_critical(tmp_path):
    """In the history, on every clone, and on the remote. That is an emergency."""
    import subprocess

    from valvur import gitcontext

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "config.py").write_text("KEY = 'x'\n")
    subprocess.run(["git", "add", "config.py"], cwd=tmp_path, check=True)

    findings = gitcontext.apply(tmp_path, [_f("aws-access-token", "config.py", "critical")])

    assert findings[0].severity == "critical"


def test_a_project_without_git_is_left_alone(tmp_path):
    from valvur import gitcontext

    findings = gitcontext.apply(tmp_path, [_f("aws-access-token", ".env", "critical")])

    assert findings[0].severity == "critical"


# ------------------------------------------------------- the ranking floor

def test_a_noisy_class_cannot_outrank_a_real_finding():
    """The floor was silently discarded: min(exploit_tier, class_weight) preferred the
    no-exploit default of 2 over any class weight above it, so a licence-unknown
    finding weighted 5 still ranked at 2."""
    ranked = apply([
        _f("valvur.licence.dependency-unknown", "sbom.cdx.json"),
        _f("CKV_AWS_18", "template.yaml"),
        _f("valvur.dependency.nonexistent", "requirements.txt"),
    ])

    assert [f.rule for f in ranked] == [
        "valvur.dependency.nonexistent", "CKV_AWS_18",
        "valvur.licence.dependency-unknown",
    ]


def test_exploit_evidence_still_wins_where_it_exists():
    """The fix must not stop KEV outranking a class floor."""
    ranked = apply([
        _f("valvur.licence.missing", "."),
        _f("CVE-2023-4863", "requirements.txt", "high",
           exploit=Exploit(cve="CVE-2023-4863", kev=True)),
    ])

    assert ranked[0].rule == "CVE-2023-4863"


def test_osv_severity_vocabulary_is_normalised_on_every_path():
    """OSV speaks GitHub's vocabulary, which calls medium 'moderate'. Unmapped it
    falls outside our scale and sorts BELOW low, so real npm advisories ranked
    beneath an unknown-licence note. The fallback path skipped the mapping."""
    from valvur.adapters.osv import _severity
    from valvur.findings import SEVERITIES

    from_scores = _severity({"severity": [{"score": "MODERATE"}]})
    from_fallback = _severity({"database_specific": {"severity": "MODERATE"}})

    assert from_scores == "medium"
    assert from_fallback == "medium"
    assert from_fallback in SEVERITIES


def test_unknown_licence_findings_are_aggregated_into_one():
    """A real TypeScript project produced 618 of these — 96% of its findings —
    burying two dozen genuine CVEs. Missing licence metadata is a bulk property of
    the dependency tree, not 618 separate problems."""
    import json

    from valvur.licence_policy import evaluate

    sbom = json.dumps({"components": [
        {"name": f"pkg{i}", "version": "1.0"} for i in range(50)
    ]})

    findings = evaluate("MIT", sbom)

    assert len(findings) == 1
    assert "50 dependencies declare no licence" in findings[0].title


def test_nothing_to_scan_is_not_a_scan_failure():
    """OSV-Scanner reads lockfiles only, so a pyproject-without-lockfile makes it
    exit 128 saying 'No package sources found'. Reporting that as a failure marked
    the whole scan incomplete and made every lockfile-less project look broken."""
    from valvur.runner import _is_nothing_to_scan

    assert _is_nothing_to_scan("No package sources found, --help for usage")
    assert not _is_nothing_to_scan("permission denied reading /workspace")


def test_fixed_version_is_the_minimal_upgrade_not_the_first_listed():
    """OSV publishes a fix per affected release line, so brace-expansion 1.1.15
    carries fixes 1.1.16, 2.1.2 and 5.0.7. Taking the first listed would tell the
    developer to jump three major versions when a patch release clears it."""
    from valvur.adapters.osv import _fixed_version

    vuln = {"affected": [{"package": {"name": "brace-expansion"}, "ranges": [
        {"events": [{"introduced": "5.0.0"}, {"fixed": "5.0.7"}]},
        {"events": [{"introduced": "1.0.0"}, {"fixed": "1.1.16"}]},
        {"events": [{"introduced": "2.0.0"}, {"fixed": "2.1.2"}]},
    ]}]}

    assert _fixed_version(vuln, "brace-expansion", "1.1.15") == "1.1.16"
    assert _fixed_version(vuln, "brace-expansion", "2.1.1") == "2.1.2"


def test_fixed_version_never_suggests_a_downgrade():
    """A fix below the installed version is not a fix for this install."""
    from valvur.adapters.osv import _fixed_version

    vuln = {"affected": [{"ranges": [{"events": [{"fixed": "1.0.0"}]}]}]}

    assert _fixed_version(vuln, "pkg", "9.9.9") == ""


def test_version_key_orders_numerically_not_lexically():
    from valvur.adapters.osv import _version_key

    assert _version_key("1.1.16") > _version_key("1.1.9")


def test_a_narrower_profile_does_not_claim_bare_clean():
    """Measured on a real project: quick reported 0 findings while standard found 24
    CVEs in the same lockfile in the same minute. Quick must stay offline (N2.1), so
    the honest fix is to state the gap rather than widen the profile."""
    from valvur.api import ScanRun
    from valvur.results import _summary

    text = _summary(ScanRun(findings=[], profile="quick"))

    assert "did not run every Scanner" in text
    assert "osv-scanner" in text
    assert "--profile standard" in text


def test_full_coverage_clean_carries_no_caveat():
    """The caveat must mean something. A profile that ran everything earns a plain
    clean, or the warning becomes noise a reader learns to skip."""
    from valvur.api import ScanRun
    from valvur.results import _summary

    assert "did not run every Scanner" not in _summary(ScanRun(findings=[], profile="deep"))


def test_stale_raw_output_does_not_survive_into_a_later_run(tmp_path):
    """A quick scan inheriting a standard scan's osv-scanner.json shows a reader
    vulnerability data attributed to a run that never looked for it. I misread
    exactly this while auditing a real repository."""
    from valvur import rawoutput

    rawoutput.write(tmp_path, [("osv-scanner", "{}"), ("trivy", "{}")])
    rawoutput.write(tmp_path, [("trivy", "{}")])

    present = {p.name for p in (tmp_path / "raw").glob("*.json")}
    assert present == {"trivy.json"}


def test_run_json_records_the_profile_and_its_gaps():
    """Without this, run.json cannot tell you a finding class was out of scope."""
    import json

    from valvur.api import ScanRun
    from valvur.results import _provenance

    doc = json.loads(_provenance(ScanRun(findings=[], profile="quick")))

    assert doc["profile"] == "quick"
    assert "osv-scanner" in doc["scanners_not_run"]


def test_unknown_profile_reports_no_gap_rather_than_raising():
    """Artifact writing must never fail over provenance we do not have."""
    from valvur.profiles import not_run

    assert not_run("") == ()


def _dep_finding(pkg, version, fix, rule):
    from valvur.findings import Dependency, Finding

    return Finding(
        rule=rule, path="pnpm-lock.yaml", line=0, title=f"{pkg} {version}",
        evidence="", fingerprint=f"{rule}-{version}", severity="high",
        sources=("osv-scanner",),
        dependency=Dependency(
            ecosystem="npm", package=pkg, version=version, fixed_version=fix
        ),
    )


def test_distinct_release_lines_are_distinct_upgrades():
    """A real pnpm tree carried brace-expansion 1.x, 2.x and 5.x at once. Merging
    them into one action told the 5.0.7 install to 'upgrade to 1.1.18' — a
    downgrade."""
    from valvur.remediation import group

    items = group([
        _dep_finding("brace-expansion", "1.1.15", "1.1.18", "CVE-1"),
        _dep_finding("brace-expansion", "5.0.7", "5.0.9", "CVE-2"),
    ])

    assert len(items) == 2
    assert {i.action for i in items} == {
        "Upgrade `brace-expansion` to 1.1.18",
        "Upgrade `brace-expansion` to 5.0.9",
    }


def test_the_recommended_upgrade_clears_every_cve_in_its_group():
    """Three CVEs on one release line have three different minimal fixes. Only the
    highest resolves all three; naming the lowest leaves the developer believing
    they are done when two advisories still apply."""
    from valvur.remediation import group

    items = group([
        _dep_finding("brace-expansion", "1.1.15", "1.1.16", "CVE-1"),
        _dep_finding("brace-expansion", "1.1.15", "1.1.18", "CVE-2"),
        _dep_finding("brace-expansion", "1.1.15", "1.1.17", "CVE-3"),
    ])

    assert len(items) == 1
    assert items[0].action == "Upgrade `brace-expansion` to 1.1.18"


def test_an_upgrade_never_claims_to_resolve_an_unfixed_advisory():
    """If one CVE in the group has no published fix, the upgrade does not clear it.
    Counting it as resolved is how a developer stops looking at a live issue."""
    from valvur.remediation import render

    text = render([
        _dep_finding("pkg", "1.0.0", "1.0.1", "CVE-1"),
        _dep_finding("pkg", "1.0.0", "", "CVE-2"),
    ])

    assert "Upgrade `pkg` to 1.0.1" in text
    assert "Resolves 1 finding(s)" in text
    assert "no published fix" in text


def test_dotfile_paths_keep_their_leading_dot():
    """lstrip takes a character set, not a prefix. Checkov reports
    "/.github/workflows/ci.yml"; we reported "github/workflows/ci.yml" — a path that
    does not exist on disk, and a fingerprint no suppression could match."""
    from valvur.adapters.base import container_relative

    assert container_relative("/.github/workflows/ci.yml") == ".github/workflows/ci.yml"
    assert container_relative("/workspace/.env") == ".env"
    assert container_relative("./src/app.py") == "src/app.py"
    assert container_relative("/workspace/src/app.py") == "src/app.py"
