"""Sub-phase 10.3b — false positives found by scanning a real project.

A synthetic fixture is generous: it has no vendored dependencies, no `.env`, and
nothing a developer cannot fix. A real 260k-line codebase produced 20 findings, of
which six were numpy's own test files inside a build directory and two were secrets
in a gitignored `.env`. None of that was visible until then.
"""

import json
from pathlib import Path

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

    # Readable tree, so this exercises aggregation rather than the unreadable case.
    comps = [{"name": f"ok{i}", "version": "1.0",
              "licenses": [{"license": {"id": "MIT"}}]} for i in range(60)]
    comps += [{"name": f"pkg{i}", "version": "1.0"} for i in range(50)]

    findings = evaluate("MIT", json.dumps({"components": comps}))

    assert len(findings) == 1
    assert "50 dependencies have no licence recorded" in findings[0].title


def test_nothing_to_scan_is_not_a_scan_failure():
    """OSV-Scanner reads lockfiles only, so a pyproject-without-lockfile makes it
    exit 128 saying 'No package sources found'. Reporting that as a failure marked
    the whole scan incomplete and made every lockfile-less project look broken."""
    from valvur.invocation import NOTHING_TO_SCAN
    from valvur.runner import _is_empty_result

    assert _is_empty_result("No package sources found, --help for usage", NOTHING_TO_SCAN)
    assert not _is_empty_result("permission denied reading /workspace", NOTHING_TO_SCAN)
    # An adapter that never says such a thing gets no allowance (26.2.1).
    assert not _is_empty_result("No package sources found", ())


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
    from valvur.summary import render as _summary

    text = _summary(ScanRun(findings=[], profile="offline"))

    assert "did not run every Scanner" in text
    # `full`, not `standard`. The Profiles were renamed by ADR-0016 and the sentence
    # recommending one was not — the retired name survived in the output string, which
    # is the one place that actually teaches it to a new user (task 19.D.2).
    assert "--profile full" in text
    assert "--profile standard" not in text
    # Named by what is missing, not by which binary did not run: quick does not run
    # osv-scanner, but Trivy covers dependency CVEs, so listing the tool alone reads
    # as "dependencies unchecked" — which is exactly the false alarm this avoids.
    # Since ADR-0018 hallucinated packages are on the COVERED side of the sentence.
    assert "package age" in text
    assert "It does not cover" in text and "hallucinated" not in text.split("It does not cover")[1]
    assert "does cover dependency CVEs" in text and "hallucinated packages" in text


def test_full_coverage_clean_carries_no_caveat():
    """The caveat must mean something. A profile that ran everything earns a plain
    clean, or the warning becomes noise a reader learns to skip."""
    from valvur.api import ScanRun
    from valvur.summary import render as _summary

    assert "did not run every Scanner" not in _summary(ScanRun(findings=[], profile="full"))


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
    from valvur.provenance import render as _provenance

    doc = json.loads(_provenance(ScanRun(findings=[], profile="offline")))

    assert doc["profile"] == "offline"
    assert "osv-scanner" in doc["scanners_not_run"]


def test_unknown_profile_reports_no_gap_rather_than_raising():
    """Artifact writing must never fail over provenance we do not have."""
    from valvur.profiles import not_run

    assert not_run("") == ()


def _dep_finding(pkg, version, fix, rule):
    from valvur.findings import Dependency, Finding

    return Finding(
        rule=rule, path="pnpm-lock.yaml", line=0, title=f"{pkg} {version}",
        evidence="", fingerprint=f"{rule}-{pkg}-{version}", severity="high",
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


def test_sbom_file_components_are_not_counted_as_dependencies():
    """Syft catalogues workflow YAML and lockfiles as type "file". They are not
    dependencies, and their names are container paths — counting them inflated the
    total and leaked /workspace into evidence bound for a committed file."""
    import json

    from valvur.licence_policy import evaluate

    sbom = json.dumps({"components": [
        {"name": "/workspace/.github/workflows/ci.yml", "type": "file"},
        {"name": "left-pad", "version": "1.0", "type": "library"},
    ]})

    findings = evaluate("MIT", sbom)

    assert len(findings) == 1
    assert "/workspace" not in findings[0].evidence
    assert "1 of 1" in findings[0].title


def test_wholly_absent_licence_data_is_reported_as_unreadable_not_as_absent():
    """npm licence metadata lives in each installed package, not the lockfile. Saying
    "618 dependencies declare no licence" states as fact something we could not read,
    and gives the developer nothing to do about it."""
    import json

    from valvur.licence_policy import evaluate

    sbom = json.dumps({"components": [
        {"name": f"pkg{i}", "version": "1.0", "type": "library"} for i in range(50)
    ]})

    findings = evaluate("MIT", sbom)

    assert findings[0].rule == "valvur.licence.dependencies-unreadable"
    assert "could not be determined" in findings[0].title
    assert "Install dependencies and rescan" in findings[0].evidence


def test_a_minority_of_undeclared_licences_is_still_reported_as_undeclared():
    """The unreadable wording must not swallow the real case: a tree we could read,
    where a few packages genuinely ship no licence."""
    import json

    from valvur.licence_policy import evaluate

    comps = [{"name": f"ok{i}", "version": "1.0", "type": "library",
              "licenses": [{"license": {"id": "MIT"}}]} for i in range(20)]
    comps.append({"name": "mystery", "version": "1.0", "type": "library"})

    findings = evaluate("MIT", json.dumps(comps and {"components": comps}))

    assert findings[0].rule == "valvur.licence.dependency-unknown"
    assert "1 dependencies have no licence recorded" in findings[0].title


def test_an_unreadable_workspace_on_macos_podman_explains_the_vm_share(monkeypatch):
    """Measured on this machine: a path under /var/folders mounts as an empty
    directory under Podman while /private/tmp works, with no error from the runtime.
    Refusing to scan is right; refusing without saying why looks like our bug.

    The platform is pinned rather than assumed: this passed for twelve days on a Mac
    and failed on the first CI run that saw it (22.B.1), because the hint is
    correctly withheld on Linux and the test never said which platform it meant."""
    import platform

    from valvur.runner import _unreadable_hint

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    hint = _unreadable_hint("/opt/podman/bin/podman", "/var/folders/x/ws")

    assert "podman machine set --volume" in hint
    assert "home directory" in hint


def test_the_hint_does_not_blame_podman_on_other_runtimes():
    """Docker Desktop shares more paths by default; the VM advice would misdirect."""
    from valvur.runner import _unreadable_hint

    assert "podman machine" not in _unreadable_hint("/usr/local/bin/docker", "/x")


def test_a_container_that_never_started_is_not_called_an_unreadable_workspace(
    monkeypatch, tmp_path
):
    """The probe discarded stderr, so a failed image pull was reported as "the
    container cannot read the workspace" — sending the reader to check mount
    permissions while the runtime had already said "unauthorized"."""
    import subprocess

    import pytest

    from valvur.runner import ContainerRunner, ContainerStartFailed

    (tmp_path / "a.txt").write_text("x")

    def fail(*a, **k):
        return subprocess.CompletedProcess(
            a[0], 125, "", "Error: unable to retrieve auth token: unauthorized"
        )

    monkeypatch.setattr(subprocess, "run", fail)
    runner = ContainerRunner(runtime="/opt/podman/bin/podman")

    with pytest.raises(ContainerStartFailed) as excinfo:
        runner.verify_workspace_readable(tmp_path)

    message = str(excinfo.value)
    assert "unauthorized" in message
    assert "podman pull" in message
    assert "cannot read the workspace" not in message


def test_a_genuinely_unreadable_workspace_still_reports_as_such(monkeypatch, tmp_path):
    """The new branch must not swallow the failure it was built around: a container
    that runs fine and sees nothing is the silent-clean-scan case."""
    import subprocess

    import pytest

    from valvur.runner import ContainerRunner, WorkspaceUnreadable

    (tmp_path / "a.txt").write_text("x")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "0\n", ""),
    )

    with pytest.raises(WorkspaceUnreadable):
        ContainerRunner(runtime="/usr/local/bin/docker").verify_workspace_readable(tmp_path)


def test_trivy_is_asked_for_dev_dependencies(monkeypatch, tmp_path):
    """Trivy excludes dev dependencies by default; OSV-Scanner includes them.
    Measured on a real Electron app: without this flag the quick profile found 0
    CVEs and standard found 24 — the same 24, same lockfile, one flag apart. Build
    and test tooling runs on the developer's machine and in CI, which is exactly the
    supply-chain surface this product exists to cover."""
    import subprocess

    from valvur import cache
    from valvur.runner import ContainerRunner

    seen = {}

    def capture(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(subprocess, "run", capture)

    from valvur.adapters import TrivyAdapter

    TrivyAdapter().run(ContainerRunner(runtime="/usr/local/bin/docker"), tmp_path)

    assert "--include-dev-deps" in seen["cmd"]


def test_dependency_scope_comes_from_trivys_own_dev_flag():
    """Now that dev dependencies are scanned, saying which findings reach shipped
    code is the difference between 24 findings and 24 a developer can triage."""
    from valvur.adapters.trivy import _scope_for

    assert _scope_for("pnpm-lock.yaml", True) == "development"
    assert _scope_for("pnpm-lock.yaml", False) == "production"


def test_the_same_cve_from_two_scanners_is_one_finding():
    """Finding identity is (ecosystem, package, version, vuln_id). Trivy reports the
    lockfile FORMAT — "pnpm" — where OSV reports the ecosystem "npm", so on a real
    project the same 24 CVEs arrived twice, once from each scanner, and every one
    was reported twice because the fingerprints could not match."""
    from valvur.adapters.osv import OsvAdapter
    from valvur.adapters.trivy import TrivyAdapter
    from valvur.findings import merge
    from valvur.runner import ScannerOutput

    trivy = json.dumps({"Results": [{
        "Target": "pnpm-lock.yaml", "Type": "pnpm", "Class": "lang-pkgs",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-69152", "PkgName": "brace-expansion",
            "InstalledVersion": "1.1.15", "FixedVersion": "1.1.18",
            "Severity": "HIGH", "Title": "DoS",
        }],
    }]})
    osv = json.dumps({"results": [{"source": {"path": "/workspace/pnpm-lock.yaml"},
        "packages": [{
            "package": {"name": "brace-expansion", "version": "1.1.15", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "CVE-2026-69152", "summary": "DoS"}],
        }]}]})

    findings = (
        TrivyAdapter().parse(ScannerOutput("trivy", "1", trivy, "", 0))
        + OsvAdapter().parse(ScannerOutput("osv-scanner", "1", osv, "", 0))
    )

    assert len({f.fingerprint for f in findings}) == 1
    assert len(merge(findings)) == 1


def test_lockfile_formats_normalise_to_their_ecosystem():
    from valvur.ecosystems import normalise

    assert normalise("pnpm") == normalise("yarn") == normalise("npm") == "npm"
    assert normalise("PyPI") == normalise("poetry") == "pip"
    assert normalise("gradle") == "maven"


def test_an_unknown_ecosystem_is_not_silently_blanked():
    """A wrong-but-consistent name still merges with itself; an empty one merges
    unrelated findings."""
    from valvur.ecosystems import normalise

    assert normalise("some-new-thing") == "some-new-thing"
    assert normalise("") == "unknown"


def test_valvur_does_not_scan_its_own_results_folder():
    """Each run would otherwise feed on the last one's output: findings.json quotes
    evidence from the repository, so scanning it produces findings ABOUT findings and
    the noise compounds every run. Caught by dogfooding — valvur reported two
    mutable-git-ref findings against its own findings.json."""
    from valvur.exclusions import is_vendored

    assert is_vendored(".security-scan/findings.json")
    assert is_vendored(".security-scan/raw/ai-artifact.json")
    assert not is_vendored("src/valvur/api.py")


def test_github_actions_are_not_counted_as_unlicensed_dependencies():
    """Syft types GitHub Actions as libraries with a pkg:github purl. They are
    workflow steps pinned by git ref, not licensed packages — the pinning rule
    already covers the risk they carry — so counting them inflates "N dependencies
    declare no licence" with things that have no licence to declare."""
    from valvur.licence_policy import evaluate

    sbom = json.dumps({"components": [
        {"name": "actions/checkout", "version": "v5", "type": "library",
         "purl": "pkg:github/actions/checkout@v5"},
        {"name": "left-pad", "version": "1.0", "type": "library",
         "purl": "pkg:npm/left-pad@1.0"},
        {"name": "ok", "version": "1.0", "type": "library", "purl": "pkg:npm/ok@1.0",
         "licenses": [{"license": {"id": "MIT"}}]},
    ]})

    findings = evaluate("Apache-2.0", sbom)

    assert len(findings) == 1
    assert "1 dependencies have no licence recorded" in findings[0].title
    assert "actions/checkout" not in findings[0].evidence


def test_configured_exclusions_match_on_segment_boundaries():
    """"tests/fixtures" must cover tests/fixtures/broken-repo/app.py and never
    tests/fixtures-helper/app.py — a prefix match on raw strings would swallow an
    unrelated directory whose name merely starts the same way."""
    from valvur.exclusions import is_configured_out

    prefixes = ("tests/fixtures",)

    assert is_configured_out("tests/fixtures/broken-repo/app.py", prefixes)
    assert not is_configured_out("tests/fixtures-helper/app.py", prefixes)
    assert not is_configured_out("tests/test_scan.py", prefixes)


def test_nothing_is_excluded_without_configuration():
    """The exclusion is opt-in per project. A built-in default would silently skip
    every project's tests, hiding real code from the people who most need to see it."""
    from valvur.exclusions import filter_configured, load_configured

    findings = [_f("x", path="tests/fixtures/a.py")]

    assert filter_configured(findings, ()) == (findings, 0)
    assert load_configured(Path("/nonexistent-workspace")) == ()


def test_configured_exclusions_are_read_from_the_committed_file(tmp_path):
    (tmp_path / ".security-scan.toml").write_text(
        '[scan]\nexclude = ["tests/fixtures", "vendor/generated/"]\n'
    )
    from valvur.exclusions import load_configured

    assert load_configured(tmp_path) == ("tests/fixtures", "vendor/generated")


def test_an_exclusion_reports_what_it_cost():
    """An exclusion the reader cannot see is indistinguishable from a scan that
    found nothing. The count and the paths both appear."""
    import json as _json

    from valvur.api import ScanRun
    from valvur.provenance import render as _provenance
    from valvur.summary import render as _summary

    run = ScanRun(findings=[], profile="offline",
                  config_dropped=61, excluded_paths=["tests/fixtures"])

    # Since 29.0.1 every Scanner is told to skip the paths; what it reports
    # there anyway is dropped, and still counted.
    assert "Excluded before the scan" in _summary(run)
    assert "61 finding(s) reported there anyway were dropped" in _summary(run)
    assert "tests/fixtures" in _summary(run)
    doc = _json.loads(_provenance(run))
    assert doc["excluded_by_config"] == {
        "paths": ["tests/fixtures"], "findings_dropped": 61
    }


def test_the_sbom_respects_configured_exclusions(monkeypatch, tmp_path):
    """The SBOM is a release artifact, so an exclusion has to reach it and not only
    the findings derived from it. Without this, valvur's own published SBOM listed
    aws-helper-sdk and locktest — packages its fixtures invent precisely because they
    do not exist."""
    import subprocess

    from valvur.runner import ContainerRunner

    (tmp_path / ".security-scan.toml").write_text('[scan]\nexclude = ["tests/fixtures"]\n')
    seen = {}

    def capture(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", capture)
    from valvur.adapters import SyftAdapter

    SyftAdapter().run(ContainerRunner(runtime="/usr/local/bin/docker"), tmp_path)

    assert "--exclude" in seen["cmd"]
    assert "./tests/fixtures/**" in seen["cmd"]


def test_one_package_under_two_spellings_is_one_upgrade():
    """Scanners disagree on case for the same package: Trivy reports "Pillow", OSV
    reports "pillow" on some advisories. Ungrouped they became two actions for one
    dependency — and the second advised 10.0.1 after the first advised 12.3.0, so
    following the proposal in order downgrades the package it just fixed."""
    from valvur.remediation import group

    items = group([
        _dep_finding("Pillow", "10.0.0", "12.3.0", "CVE-1"),
        _dep_finding("pillow", "10.0.0", "10.0.1", "PYSEC-1"),
    ])

    assert len(items) == 1
    assert items[0].action == "Upgrade `Pillow` to 12.3.0"
