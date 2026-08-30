"""Phase 1 — walking skeleton. Behaviours, verified through the public interface."""

import subprocess

import pytest

from valvur import scan


def test_scanning_a_workspace_with_a_planted_secret_reports_a_finding(
    workspace, runner_finding_one_secret
):
    run = scan(workspace, runner=runner_finding_one_secret)

    assert len(run.findings) == 1


def test_a_clean_workspace_reports_an_explicit_clean_status(
    clean_workspace, runner_finding_nothing
):
    run = scan(clean_workspace, runner=runner_finding_nothing)

    assert run.status == "clean"


def test_a_scan_run_writes_a_results_folder_containing_a_summary(
    workspace, runner_finding_one_secret
):
    scan(workspace, runner=runner_finding_one_secret)

    assert (workspace / ".security-scan" / "SUMMARY.md").is_file()


def test_the_results_folder_ignores_itself(workspace, runner_finding_one_secret):
    scan(workspace, runner=runner_finding_one_secret)

    assert (workspace / ".security-scan" / ".gitignore").read_text().strip() == "*"


def test_git_status_shows_no_untracked_scan_output(git_workspace, runner_finding_one_secret):
    """The F7.2 guarantee, verified the way a developer would notice it failing."""
    scan(git_workspace, runner=runner_finding_one_secret)

    porcelain = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=git_workspace, capture_output=True, text=True, check=True,
    ).stdout

    assert porcelain == ""


def test_a_secrets_value_never_appears_in_any_written_file(workspace, runner_finding_one_secret):
    """Redaction (F5.7).

    A security tool must not copy your credentials to a second place on disk.
    """
    scan(workspace, runner=runner_finding_one_secret)

    written = [p for p in (workspace / ".security-scan").rglob("*") if p.is_file()]
    leaked = [p.name for p in written if "AKIAV7Q2XR4TVBN6WLKJ" in p.read_text(encoding="utf-8")]

    assert leaked == []


def _snapshot(root):
    """Hash every file outside the Results Folder."""
    import hashlib

    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".security-scan" not in p.parts and ".git" not in p.parts:
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_the_workspace_is_unchanged_by_a_scan_run(workspace, runner_finding_one_secret):
    """F1.3 / N2.2 — valvur reads your code; it never writes to it."""
    before = _snapshot(workspace)

    scan(workspace, runner=runner_finding_one_secret)

    assert _snapshot(workspace) == before


def test_a_scan_exits_zero_when_findings_exist(workspace, runner_finding_one_secret):
    """N3.2 — findings never fail the run. Only infrastructure failure does."""
    from valvur.cli import main

    exit_code = main(["scan", str(workspace)], runner=runner_finding_one_secret)

    assert exit_code == 0


def test_findings_report_workspace_relative_paths(workspace, runner_finding_one_secret):
    """Container paths must never leak out. Fingerprint portability (F5.4) depends on this."""
    run = scan(workspace, runner=runner_finding_one_secret)

    assert run.findings[0].path == "config.py"


def test_a_scanner_that_produced_no_report_is_not_reported_as_clean(clean_workspace):
    """Fail loudly (F2.5, N3.1).

    A scanner that could not write its output must never look like a clean result.
    A silent failure manufactures false confidence and is worse than no scan.
    """
    from conftest import FakeRunner

    from valvur.api import ScannerFailed

    broken = FakeRunner(gitleaks_stdout="", exit_code=2)

    with pytest.raises(ScannerFailed):
        scan(clean_workspace, runner=broken)
