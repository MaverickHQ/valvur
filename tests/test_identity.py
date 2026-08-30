"""Phase 2 — Finding identity.

Findings must survive editing, or the scan -> fix -> rescan loop cannot tell
progress from noise. See docs/adr/0003-per-class-finding-identity.md.
"""

from valvur import scan


def test_a_finding_keeps_its_fingerprint_across_identical_scans(
    workspace, runner_finding_one_secret
):
    first = scan(workspace, runner=runner_finding_one_secret)
    second = scan(workspace, runner=runner_finding_one_secret)

    assert first.findings[0].fingerprint == second.findings[0].fingerprint


def test_a_finding_keeps_its_fingerprint_when_unrelated_lines_above_it_move(workspace):
    """The behaviour ADR-0003 exists for.

    Without this, fixing the first finding makes every finding below it look new,
    and the rescan diff becomes noise.
    """
    from conftest import FakeRunner, gitleaks_output

    before = scan(workspace, runner=FakeRunner(gitleaks_output(line=3), 1))
    after = scan(workspace, runner=FakeRunner(gitleaks_output(line=47), 1))

    assert before.findings[0].fingerprint == after.findings[0].fingerprint


def test_a_finding_keeps_its_fingerprint_when_the_file_is_reformatted(workspace):
    from conftest import FakeRunner, gitleaks_output

    original = scan(workspace, runner=FakeRunner(
        gitleaks_output(match='AWS_ACCESS_KEY_ID = "AKIAV7Q2XR4TVBN6WLKJ"'), 1))
    reformatted = scan(workspace, runner=FakeRunner(
        gitleaks_output(line=12, match="AWS_ACCESS_KEY_ID='AKIAV7Q2XR4TVBN6WLKJ'"), 1))

    assert original.findings[0].fingerprint == reformatted.findings[0].fingerprint


def test_a_finding_present_in_both_runs_is_persisting(workspace, runner_finding_one_secret):
    scan(workspace, runner=runner_finding_one_secret)
    second = scan(workspace, runner=runner_finding_one_secret)

    assert second.findings[0].status == "persisting"


def test_a_finding_absent_from_the_previous_run_is_new(workspace, runner_finding_nothing):
    from conftest import FakeRunner, gitleaks_output

    scan(workspace, runner=runner_finding_nothing)
    second = scan(workspace, runner=FakeRunner(gitleaks_output(), 1))

    assert second.findings[0].status == "new"


def test_every_finding_on_a_first_ever_scan_is_new(workspace, runner_finding_one_secret):
    """F5.9 — a fresh clone has no history. Everything is new, honestly."""
    run = scan(workspace, runner=runner_finding_one_secret)

    assert {f.status for f in run.findings} == {"new"}


def test_fixing_the_problem_reports_the_finding_as_fixed(
    workspace, runner_finding_one_secret, runner_finding_nothing
):
    scan(workspace, runner=runner_finding_one_secret)
    after_fix = scan(workspace, runner=runner_finding_nothing)

    assert len(after_fix.fixed) == 1


def test_a_fixed_finding_that_returns_is_regressed(
    workspace, runner_finding_one_secret, runner_finding_nothing
):
    scan(workspace, runner=runner_finding_one_secret)   # found
    scan(workspace, runner=runner_finding_nothing)      # fixed
    returned = scan(workspace, runner=runner_finding_one_secret)  # back again

    assert returned.findings[0].status == "regressed"


def test_fingerprints_do_not_depend_on_where_the_workspace_lives(
    tmp_path, runner_finding_one_secret
):
    """F5.4 — Suppressions are committed and shared, so fingerprints must match
    byte-for-byte on a colleague's machine with a different checkout path."""
    import shutil

    from conftest import FIXTURES

    here = tmp_path / "alice" / "checkout"
    there = tmp_path / "bob" / "some" / "deeper" / "path"
    shutil.copytree(FIXTURES / "broken-repo", here)
    shutil.copytree(FIXTURES / "broken-repo", there)

    alice = scan(here, runner=runner_finding_one_secret)
    bob = scan(there, runner=runner_finding_one_secret)

    assert alice.findings[0].fingerprint == bob.findings[0].fingerprint


def test_two_identical_matches_in_one_file_are_distinct_findings():
    """Only the SAST class needs a content hash, so only it can collide.
    Repeats are separated by ordinal (design 3.1)."""
    from valvur.fingerprint import for_sast

    first = for_sast("py.eval-call", "app.py", "eval(user_input)", ordinal=0)
    second = for_sast("py.eval-call", "app.py", "eval(user_input)", ordinal=1)

    assert first != second


def test_a_finding_reported_by_two_scanners_appears_once_naming_both():
    """F5.8 — Trivy and OSV overlap heavily. One Finding, both credited."""
    from valvur.findings import Finding, merge

    by_trivy = Finding(rule="CVE-2021-23337", path="package-lock.json", line=0,
                       title="Prototype pollution", fingerprint="fp-a", sources=("trivy",))
    by_osv = Finding(rule="CVE-2021-23337", path="package-lock.json", line=0,
                     title="Prototype pollution", fingerprint="fp-a", sources=("osv-scanner",))

    merged = merge([by_trivy, by_osv])

    assert len(merged) == 1
    assert set(merged[0].sources) == {"trivy", "osv-scanner"}


def test_bumping_a_vulnerable_dependency_changes_its_identity():
    """Cycle 12. Identity includes the installed version, so an upgrade retires the
    old Finding — which the status machinery then reports as `fixed`."""
    from valvur.fingerprint import for_dependency_vuln

    vulnerable = for_dependency_vuln("npm", "lodash", "4.17.11", "CVE-2021-23337")
    upgraded = for_dependency_vuln("npm", "lodash", "4.17.21", "CVE-2021-23337")

    assert vulnerable != upgraded
