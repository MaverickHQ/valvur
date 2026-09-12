"""ADR-0018 — a stale package-name index is `inconclusive`, not `clean`.

The same rule the vulnerability database follows (Phase 14, 16.1), applied to the
second dataset that decides whether a Finding exists. An index that quietly aged
into uselessness would be the silent-narrowing class again, inside the fix for it.
Every surface the database warning reaches, this one reaches too: the verdict,
`run.json`, `SUMMARY.md`, the terminal and the MCP responses.
"""

from __future__ import annotations

import json

import pytest

from valvur import cache, operations
from valvur.api import ScanRun
from valvur.results import _provenance, _summary

STALE = cache.NAME_INDEX_STALE_AFTER_DAYS + 5.0


# ------------------------------------------------------------------ the verdict

def test_a_stale_index_with_nothing_found_is_inconclusive():
    assert ScanRun(findings=[], profile="offline", name_index_age_days=STALE).status == (
        "inconclusive"
    )


@pytest.mark.parametrize("age", [0.0, 1.0, cache.NAME_INDEX_STALE_AFTER_DAYS - 0.5])
def test_a_fresh_index_leaves_a_clean_result_clean(age):
    assert ScanRun(findings=[], profile="offline", name_index_age_days=age).status == "clean"


def test_no_index_is_not_a_stale_index():
    """Absent is reported by the failed Check (`complete: false`), not by pretending
    to know an age. Fabricating `inconclusive` here would double-report one cause."""
    assert ScanRun(findings=[], profile="offline").status == "clean"


def test_a_live_finding_still_reads_as_findings_whatever_the_index_age():
    from valvur.findings import Finding

    live = Finding(rule="CVE-1", path="a.py", line=0, title="x", evidence="",
                   fingerprint="a" * 32, severity="high", sources=("trivy",))

    assert ScanRun(findings=[live], profile="offline", name_index_age_days=STALE).status == (
        "findings"
    )


def test_the_threshold_is_justified_not_chosen():
    """Thirty days: ~16,000 PyPI and ~48,000 npm names of drift, and the KEV
    threshold already reported beside it. Looser than the database's seven because
    the failure direction is the opposite — an old index overstates, it does not miss."""
    assert cache.NAME_INDEX_STALE_AFTER_DAYS == 30
    assert cache.NAME_INDEX_STALE_AFTER_DAYS > cache.DB_STALE_AFTER_DAYS


# --------------------------------------------------------------------- run.json

def test_run_json_records_the_index_age_so_a_clean_result_stays_falsifiable():
    document = json.loads(_provenance(
        ScanRun(findings=[], profile="offline", name_index_age_days=STALE)
    ))

    assert document["name_index"] == {
        "present": True,
        "age_days": STALE,
        "stale": True,
        "stale_after_days": cache.NAME_INDEX_STALE_AFTER_DAYS,
    }
    assert document["status"] == "inconclusive"


def test_run_json_distinguishes_no_index_from_a_fresh_one():
    document = json.loads(_provenance(ScanRun(findings=[], profile="offline")))

    assert document["name_index"]["present"] is False
    assert document["name_index"]["age_days"] is None
    assert document["name_index"]["stale"] is False


# ------------------------------------------------------------------- SUMMARY.md

def test_the_summary_names_the_index_and_its_failure_direction():
    text = _summary(ScanRun(findings=[], profile="offline", name_index_age_days=STALE))

    assert f"package-name index is {STALE:.0f} days old" in text
    assert "valvur update" in text
    # The verdict sentence blames the right dataset. Until this was checked it said
    # "vulnerability database" for both, because the sentence had one cause in mind.
    assert "The package-name index was too old" in text
    assert "The vulnerability database was too old" not in text
    assert "newer than the index may be reported as nonexistent" in text


def test_a_fresh_index_produces_no_warning_and_no_index_produces_none_either():
    assert "package-name index is" not in _summary(
        ScanRun(findings=[], profile="offline", name_index_age_days=2.0)
    )
    assert "package-name index is" not in _summary(ScanRun(findings=[], profile="offline"))


def test_both_stale_at_once_are_both_reported():
    text = _summary(ScanRun(findings=[], profile="offline", db_age_days=9.0,
                            name_index_age_days=STALE))

    assert "vulnerability database is 9 days old" in text
    assert f"package-name index is {STALE:.0f} days old" in text


# ------------------------------------------------------------------ the terminal

def test_the_cli_warns_about_a_stale_index(capsys):
    from valvur.cli import _warn_if_name_index_stale

    _warn_if_name_index_stale(ScanRun(findings=[], profile="offline", name_index_age_days=STALE))

    err = capsys.readouterr().err
    assert f"package-name index is {STALE:.0f} days old" in err
    assert "valvur update" in err


def test_the_cli_stays_quiet_when_the_index_is_fresh_or_absent(capsys):
    from valvur.cli import _warn_if_name_index_stale

    _warn_if_name_index_stale(ScanRun(findings=[], profile="offline", name_index_age_days=1.0))
    _warn_if_name_index_stale(ScanRun(findings=[], profile="offline"))

    assert capsys.readouterr().err == ""


# ------------------------------------------------------------------ the MCP surface

def _scanned(tmp_path, *, index_stale: bool, db_stale: bool = False):
    results = tmp_path / ".security-scan"
    results.mkdir(parents=True)
    status = "inconclusive" if (index_stale or db_stale) else "clean"
    (results / "findings.json").write_text(json.dumps({
        "schema": 1, "status": status, "findings": [],
    }))
    (results / "run.json").write_text(json.dumps({
        "status": status, "complete": True,
        "findings": {"active": 0, "suppressed": 0, "not_covered": 0, "total": 0},
        "scanners": [{"tool": "dependency-reality", "ok": True, "reason": ""}],
        "network": {"what_left_the_machine": "nothing"},
        "database": {"age_days": 60.0 if db_stale else 1.0, "stale": db_stale,
                     "stale_after_days": 7},
        "name_index": {"present": True, "age_days": STALE if index_stale else 1.0,
                       "stale": index_stale, "stale_after_days": 30},
    }))
    return tmp_path


def test_an_agent_finding_nothing_is_told_the_index_was_too_old(tmp_path):
    workspace = _scanned(tmp_path, index_stale=True)

    answer = operations.list_findings({"workspace": str(workspace)})

    assert "package-name index is" in answer
    assert "reported as nonexistent" in answer
    assert "valvur update" in answer
    # And NOT the database's sentence: the advice differs, and an agent told
    # "advisories are missing" would reason wrongly about a dependency finding.
    assert "vulnerability database" not in answer


def test_scan_status_explains_an_index_caused_inconclusive(tmp_path):
    workspace = _scanned(tmp_path, index_stale=True)

    answer = operations.scan_status({"workspace": str(workspace)})

    assert "inconclusive" in answer
    assert "package-name index was too old" in answer


def test_a_fresh_index_adds_nothing_to_the_mcp_answer(tmp_path):
    workspace = _scanned(tmp_path, index_stale=False)

    for tool in (operations.list_findings, operations.scan_status):
        assert "package-name index" not in tool({"workspace": str(workspace)})


def test_both_stale_at_once_are_both_named_on_the_mcp_surface(tmp_path):
    workspace = _scanned(tmp_path, index_stale=True, db_stale=True)

    answer = operations.list_findings({"workspace": str(workspace)})

    assert "vulnerability database is 60 days old" in answer
    assert "package-name index is" in answer


# ----------------------------------------------------- the update command, end to end

def test_update_if_stale_refreshes_only_the_index_when_only_it_is_due(monkeypatch, capsys):
    """A 116MB database download to refresh a 4MB list is not what --if-stale means."""
    from valvur import cli

    monkeypatch.setattr(cli, "_database_needs_refresh", lambda: False)
    monkeypatch.setattr(cli, "_name_index_needs_refresh", lambda: True)
    calls: list[str] = []
    monkeypatch.setattr(cli, "_refresh_name_index", lambda: calls.append("index") or True)

    class NeverRunner:
        def update_db(self):
            raise AssertionError("the database was refreshed")

    assert cli.main(["update", "--if-stale"], runner=NeverRunner()) == 0
    assert calls == ["index"]


def test_update_if_stale_does_nothing_when_both_are_current(monkeypatch, capsys):
    from valvur import cli

    monkeypatch.setattr(cli, "_database_needs_refresh", lambda: False)
    monkeypatch.setattr(cli, "_name_index_needs_refresh", lambda: False)
    monkeypatch.setattr(cache, "db_age_days", lambda: 1.0)
    monkeypatch.setattr(cli, "_refresh_name_index", lambda: pytest.fail("refreshed"))

    assert cli.main(["update", "--if-stale"], runner=None) == 0
    assert "Nothing to do" in capsys.readouterr().out


def test_a_failed_index_refresh_fails_the_update_command(monkeypatch, capsys):
    """Unlike KEV, which has a bundled snapshot to fall back on, a missing index
    makes the default Profile's dependency check fail — so an update that could not
    fetch it did not do its job, and says so with a non-zero exit."""
    from valvur import cli
    from valvur.runner import ScannerOutput

    class FineRunner:
        def update_db(self):
            return ScannerOutput("trivy-db", "", "", "", 0)

    monkeypatch.setattr(cli, "_refresh_kev", lambda: None)
    monkeypatch.setattr(cli, "_refresh_name_index", lambda: False)

    assert cli.main(["update"], runner=FineRunner()) == 1


def test_the_index_refresh_reports_a_failure_and_keeps_the_previous_index(
    monkeypatch, capsys, tmp_path
):
    from valvur import cli, name_index

    def fail(directory, progress):
        raise name_index.IndexUnavailable("pypi.org: timed out")

    monkeypatch.setattr(name_index, "refresh", fail)
    monkeypatch.setattr(cache, "name_index", lambda: tmp_path)
    monkeypatch.setattr(cache, "root", lambda: tmp_path)
    monkeypatch.setattr(cache, "name_index_present", lambda: True)

    assert cli._refresh_name_index() is False
    out = capsys.readouterr().out
    assert "timed out" in out and "previous index remains in use" in out


def test_the_index_needs_a_refresh_when_absent_or_stale(monkeypatch):
    from valvur import cli

    monkeypatch.setattr(cache, "name_index_age_days", lambda: None)
    assert cli._name_index_needs_refresh()
    monkeypatch.setattr(cache, "name_index_age_days", lambda: STALE)
    assert cli._name_index_needs_refresh()
    monkeypatch.setattr(cache, "name_index_age_days", lambda: 1.0)
    assert not cli._name_index_needs_refresh()
