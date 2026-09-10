"""Block 3 — active versus suppressed, and what the verdict is allowed to claim.

Tasks 19.C.1, 19.C.2, 19.C.3, 19.E.2 and 10.4.12, plus corpus defects C2, C3 and C5.

The failure this block removes: **`status` answered four questions with one word.**
Did we find problems in your code? Are there accepted risks? Did we look at
everything? Was our data good enough? A scan with one accepted risk and no live
problem read `findings`; a repository containing a `Cargo.toml` could never read
`clean` at all. Neither is a statement about the user's code.
"""

from __future__ import annotations

import json

from valvur import coverage
from valvur.api import ScanRun
from valvur.findings import Finding


def _live(rule="aws-access-token", **kw):
    return Finding(rule=rule, path="config.py", line=1, title="a live problem", **kw)


def _accepted():
    return Finding(rule="CKV_DOCKER_7", path="Dockerfile", line=1, title="accepted",
                   suppressed="reviewed 2026-01-01, expires 2027-01-01")


def _note():
    return Finding(rule=coverage.RULE, path="Cargo.toml", line=0,
                   title="Rust (Cargo) dependencies were not checked for existence")


# ------------------------------------------------------------- 19.C.2 / 19.E.2

def test_only_accepted_risks_is_not_a_failing_verdict():
    """The motivating case. Four suppressed findings printed `findings: 4 finding(s)`
    — indistinguishable from four live problems, to the reader most likely to act."""
    run = ScanRun(findings=[_accepted(), _accepted()])

    assert run.status == "clean"
    assert run.active == []
    assert len(run.suppressed) == 2


def test_a_live_finding_beside_an_accepted_one_still_reports_findings():
    """The pair. Suppression must not launder a real problem out of the verdict."""
    run = ScanRun(findings=[_live(), _accepted()])

    assert run.status == "findings"
    assert len(run.active) == 1


def test_no_fourth_status_was_added():
    """19.C.2's decision, recorded as a test. `clean-with-suppressions` was rejected:
    three statuses are a documented contract (§7, F7.16) and every consumer switches
    on them, so a fourth is a breaking change buying a count already printed beside
    the verdict."""
    seen = {
        ScanRun(findings=[_live()]).status,
        ScanRun(findings=[_accepted()]).status,
        ScanRun(findings=[_note()]).status,
        ScanRun(findings=[], db_age_days=400).status,
        ScanRun(findings=[]).status,
    }

    assert seen <= {"findings", "clean", "inconclusive"}


def test_a_stale_database_still_outranks_everything_it_used_to():
    run = ScanRun(findings=[], db_age_days=400)

    assert run.status == "inconclusive"


# ------------------------------------------------------------------- 19.C.1

def test_the_summary_separates_active_from_suppressed(tmp_path):
    from valvur import results

    summary = results._summary(ScanRun(findings=[_live(), _accepted(), _note()]))

    assert "**Active findings:** 1" in summary
    assert "**suppressed:** 1" in summary
    assert "**not covered:** 1" in summary


def test_the_summary_leads_with_a_sentence_a_human_can_act_on():
    """10.4.12. A human opening this in an editor met twelve lines of instructions
    addressed to somebody else before anything about their own repository."""
    from valvur import results

    summary = results._summary(ScanRun(findings=[_live()]))
    head = summary.split("<!-- valvur results")[0]

    assert "active finding" in head
    assert "REMEDIATION.md" in head
    # F7.6 still holds: the machine block precedes every Finding.
    assert summary.index("If you are an AI agent") < summary.index("Most urgent")


def test_the_machine_block_explains_what_the_statuses_mean():
    """F7.6 requires the block to describe *the Status values and the ranking basis*.
    It never did — and after 19.E.2 changed what they mean, an agent reading
    `inconclusive` had nothing telling it not to report that as clean."""
    from valvur.results import MACHINE_HEADER

    for status in ("findings", "clean", "inconclusive"):
        assert f"`{status}`" in MACHINE_HEADER
    assert "KEV" in MACHINE_HEADER and "EPSS" in MACHINE_HEADER


# ---------------------------------------------------- corpus defect C3, and C2

def test_the_profile_caveat_survives_a_finding_being_present():
    """**C3.** This was gated on `not findings`, so one missing-licence finding was
    enough to suppress the notice that dependency-reality never ran. The reader was
    told least about missing coverage exactly when there was most else on screen."""
    from valvur import results

    noisy = results._summary(ScanRun(findings=[_live()], profile="offline"))
    quiet = results._summary(ScanRun(findings=[], profile="offline"))

    for summary in (noisy, quiet):
        assert "did not run every Scanner" in summary
        assert "dependency-reality" in summary


def test_a_coverage_note_is_reported_separately_from_a_profile_omission():
    """**C2.** Two different claims, both true at once: one says a Scanner did not
    run, the other says nothing here reads a whole ecosystem even when it does."""
    from valvur import results

    summary = results._summary(ScanRun(findings=[_note()], profile="offline"))

    assert "did not run every Scanner" in summary
    assert "not inspected at all" in summary
    assert "not something a different Profile fixes" in summary


def test_run_json_breaks_the_count_into_its_parts(tmp_path):
    """**19.C.1.** One number made an accepted risk, a live problem and a note about
    our own missing coverage indistinguishable to every machine consumer."""
    from valvur import results

    results.write(tmp_path, ScanRun(findings=[_live(), _accepted(), _note()]))
    counts = json.loads((tmp_path / ".security-scan" / "run.json").read_text())["findings"]

    assert counts == {"active": 1, "suppressed": 1, "not_covered": 1, "total": 3}


# --------------------------------------------------------------------- 19.C.3

def test_valvur_mcp_answers_help_and_version(capsys):
    """Silence on stdout is correct for stdio and terrible for a first-run diagnosis:
    someone checking the binary works got a process that sat there doing nothing."""
    from valvur.mcp.server import main

    assert main(["--version"]) == 0
    assert "valvur-mcp" in capsys.readouterr().out

    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "mcpServers" in out
    # It must not teach a scan-and-fix tool that deliberately does not exist.
    assert "scan_workspace" in out and "scan_and_fix" not in out


def test_valvur_mcp_refuses_an_unrecognised_flag(capsys):
    """Refused, not ignored. A flag that starts the server anyway is how a typo in an
    agent config becomes a silent misconfiguration nobody notices for weeks."""
    from valvur.mcp.server import main

    assert main(["--porfile", "full"]) == 2
    captured = capsys.readouterr()

    assert captured.out == "", "usage errors must never touch the JSON-RPC channel"
    assert "unrecognised argument" in captured.err


def test_the_version_it_reports_is_the_one_the_image_is_checked_against():
    """A `--version` that answers from somewhere other than the single source would be
    worse than none: it is the field F1.9 compares against the container image."""
    import valvur.mcp.server as server
    from valvur.mcp.server import USAGE  # noqa: F401
    from valvur.version import __version__

    printed: list[str] = []
    server.print = lambda *a, **k: printed.append(" ".join(map(str, a)))  # type: ignore[attr-defined]
    try:
        server.main(["--version"])
    finally:
        del server.print  # type: ignore[attr-defined]

    assert printed == [f"valvur-mcp {__version__}"]


# ------------------------------------------------- the non-exfiltration disclosure

def test_the_disclosure_names_every_destination_reached(tmp_path):
    """This sentence **is** the non-exfiltration claim (§3), not a description of it.

    A registry added without amending it makes the claim false, which is worse than
    never having made it — and 19.D.1 added the npm registry. Pinned so the next
    ecosystem cannot be added quietly.
    """
    from valvur import results

    results.write(tmp_path, ScanRun(findings=[], network_used=True))
    disclosed = json.loads(
        (tmp_path / ".security-scan" / "run.json").read_text()
    )["network"]["what_left_the_machine"]

    for destination in ("PyPI", "npm registry", "osv.dev", "FIRST"):
        assert destination in disclosed, f"{destination} is reached but not disclosed"
    assert "Never source code" in disclosed


def test_the_offline_profile_discloses_nothing_leaving(tmp_path):
    """The pair, and the load-bearing half: N2.1 is the product."""
    from valvur import results

    results.write(tmp_path, ScanRun(findings=[], network_used=False))
    disclosed = json.loads(
        (tmp_path / ".security-scan" / "run.json").read_text()
    )["network"]["what_left_the_machine"]

    assert disclosed == "nothing"
