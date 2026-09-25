"""Phase 14 — a clean result from a stale database is not a clean result.

F6.11 (age from the data), F7.16 (the third status), F7.17 (recorded in run.json),
F10.8 (refreshing is explicit and cheap).

This was the last live instance of the defect that has shaped this project. valvur
already warned when *exploit intelligence* was over 30 days old — the data that
decides how findings RANK — and said nothing about the vulnerability database, which
decides whether findings exist at all. `cache.db_age_days()` was written, and then
consulted nowhere for the life of the project.

The failure it permits is the worst one this tool has: no findings, no warning, and a
developer who stops looking.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from valvur import cache
from valvur.api import ScanRun
from valvur.provenance import render as _provenance
from valvur.summary import render as _summary


def _database(tmp_path, *, updated_days_ago: float, next_update_days_ago: float = 0.0):
    """A Trivy database directory with a chosen build time."""
    db = tmp_path / "trivy" / "db"
    db.mkdir(parents=True)
    now = datetime.now(UTC)
    (db / "metadata.json").write_text(json.dumps({
        "Version": 2,
        "UpdatedAt": (now - timedelta(days=updated_days_ago))
                     .isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(days=next_update_days_ago))
                      .isoformat().replace("+00:00", "Z"),
        "DownloadedAt": now.isoformat().replace("+00:00", "Z"),
    }))
    return db


# --------------------------------------------- the age is the DATA's, not the file's

def test_age_comes_from_when_the_data_was_built_not_when_it_was_downloaded(
    tmp_path, monkeypatch
):
    """The case that matters most to the users who need valvur most.

    An air-gapped mirror (F10.5) can hand over a six-month-old database this morning.
    The file's mtime reads as fresh while every advisory in it is half a year stale,
    so mtime would report a database that is dangerously old as brand new.
    """
    _database(tmp_path, updated_days_ago=180)
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")

    age = cache.db_age_days()

    assert age is not None and 179 < age < 181, f"got {age}, expected ~180"


def test_an_unreadable_database_age_is_unknown_rather_than_zero(tmp_path, monkeypatch):
    """None is not zero. A corrupt metadata file must not produce a confident
    "brand new" — that is the exact shape of the answer this phase removes."""
    db = tmp_path / "trivy" / "db"
    db.mkdir(parents=True)
    (db / "metadata.json").write_text("{ not json")
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")

    # Falls back to mtime, which is honest here — the file really was just written.
    # What must never happen is a parse failure silently becoming 0.
    from valvur.cache import _metadata_time

    assert _metadata_time(db / "metadata.json", "UpdatedAt") is None


def test_no_database_at_all_reports_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "nothing")

    assert cache.db_age_days() is None
    assert cache.db_overdue_days() is None


def test_the_threshold_is_tighter_than_the_enrichment_one():
    """Justified rather than chosen. Trivy rebuilds every 24 hours, so seven days is
    seven missed rebuilds. KEV's 30 days is looser on purpose: it changes how
    findings rank, not whether they are found."""
    assert cache.DB_STALE_AFTER_DAYS < cache.STALE_AFTER_DAYS
    assert cache.DB_STALE_AFTER_DAYS == 7


# ------------------------------------------------ a stale clean is not a clean

def test_a_stale_database_with_no_findings_refuses_to_read_as_clean():
    """The dangerous combination, and the whole reason for this phase."""
    text = _summary(ScanRun(findings=[], profile="offline", db_age_days=9.0))

    assert "vulnerability database is 9 days old" in text
    assert "not evidence that there is nothing" in text
    assert "valvur update" in text


def test_a_stale_database_with_findings_says_the_list_is_incomplete():
    """A different claim from the one above: what was found is real, what is missing
    is unknown. Saying "found nothing" here would be false."""
    from valvur.findings import Finding

    finding = Finding(rule="CVE-1", path="a.py", line=0, title="x", evidence="",
                      fingerprint="a" * 32, severity="high", sources=("trivy",))

    text = _summary(ScanRun(findings=[finding], profile="offline", db_age_days=9.0))

    assert "vulnerability database is 9 days old" in text
    assert "the list is not complete" in text
    assert "not evidence that there is nothing" not in text


@pytest.mark.parametrize("age", [0.1, 3.0, 6.9])
def test_a_fresh_database_produces_no_warning(age):
    """The pair that stops the warning becoming noise. A caveat on every scan is a
    caveat nobody reads, which is how the coverage caveat is gated too."""
    text = _summary(ScanRun(findings=[], profile="offline", db_age_days=age))

    assert "vulnerability database is" not in text


def test_an_unknown_database_age_does_not_fabricate_a_warning():
    """Absent data is not stale data. Warning here would train readers to ignore it."""
    assert "vulnerability database is" not in _summary(ScanRun(findings=[], profile="offline"))


# --------------------------------------------------- and it is falsifiable later

def test_run_json_records_enough_to_judge_a_clean_result_afterwards():
    """N3.1 — a clean result must stay falsifiable. Without the database's age
    recorded, nobody reviewing the artifact later can tell whether "no findings"
    meant anything."""
    document = json.loads(_provenance(
        ScanRun(findings=[], profile="offline", db_age_days=9.4, db_overdue_days=8.4)
    ))

    assert document["database"] == {
        "age_days": 9.4,
        "overdue_days": 8.4,
        "stale": True,
        "stale_after_days": cache.DB_STALE_AFTER_DAYS,
    }


def test_run_json_distinguishes_a_missing_database_from_a_fresh_one():
    document = json.loads(_provenance(ScanRun(findings=[], profile="offline")))

    assert document["database"]["age_days"] is None
    assert document["database"]["stale"] is False


# ------------------------------------------------ and the terminal says it too

def test_the_cli_warns_about_a_stale_database(capsys):
    """A user running `valvur scan` reads the terminal. They may never open
    SUMMARY.md, and the one case where that matters most is the one where there is
    nothing in it to draw them there."""
    from valvur.cli import _warn_if_database_stale

    _warn_if_database_stale(ScanRun(findings=[], profile="offline", db_age_days=9.0))

    err = capsys.readouterr().err
    assert "9 days old" in err
    assert "NOT EVIDENCE THERE IS NOTHING" in err


def test_the_cli_stays_quiet_when_the_database_is_fresh(capsys):
    from valvur.cli import _warn_if_database_stale

    _warn_if_database_stale(ScanRun(findings=[], profile="offline", db_age_days=1.0))

    assert capsys.readouterr().err == ""


def test_valvur_never_updates_a_database_it_has_by_itself(tmp_path, monkeypatch, workspace):
    """Decided in 14.2. A 1.2GB download started inside a scan is hostile; doing it
    on `full` alone would make the Profiles scan different data and break the
    equivalence asserted in Phase 11 cycle 3; and updating on the user's behalf is
    the same move as fixing on their behalf, which section 4 refuses.

    Narrowed by 24.1, not reversed: an ABSENT database is fetched by the first scan
    (`test_first_run.py`), because without one there is no scan at all. A database
    that is PRESENT, however stale, is never touched — this test is that line. Until
    24.1 it inspected `scan`'s source for the word `update_db`; a behaviour is a
    better pin than a word."""
    from conftest import FakeRunner

    from valvur import scan
    from valvur.adapters import GitleaksAdapter

    _database(tmp_path, updated_days_ago=45, next_update_days_ago=44)
    (tmp_path / "trivy" / "db" / "trivy.db").write_bytes(b"bolt")
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")
    monkeypatch.setattr(cache, "root", lambda: tmp_path)

    class Runner(FakeRunner):
        def image_present(self):
            return True

        def db_size_mb(self):
            return 118

        def update_db(self):
            pytest.fail("a scan updated the database by itself — see task 14.2 for why "
                        "it must not")

    run = scan(workspace, runner=Runner(), adapters=[GitleaksAdapter()])

    assert run.db_age_days is not None and run.db_age_days > cache.DB_STALE_AFTER_DAYS


# ------------------------- the machine-readable claim, not just the prose (14.2)

def test_a_stale_scan_with_no_findings_does_not_report_clean():
    """The hole Phase 14 left open, and the one that mattered most.

    Warning in `SUMMARY.md` fixed the prose and left the verdict intact: a 400-day-old
    database with no findings still reported `"status": "clean"`. The results contract
    tells agents to read SUMMARY.md *bounded* and query findings.json for detail — so
    the consumer most likely to act on the verdict was the one least likely ever to
    see the caveat explaining it meant nothing.
    """
    assert ScanRun(findings=[], db_age_days=400.0).status == "inconclusive"


def test_a_fresh_scan_with_no_findings_still_reports_clean():
    """The pair. `inconclusive` has to be rare or it becomes the new `clean`."""
    assert ScanRun(findings=[], db_age_days=1.0).status == "clean"
    assert ScanRun(findings=[], db_age_days=None).status == "clean"


def test_findings_are_findings_however_old_the_database():
    """What was found is real regardless of age; only absence is unprovable."""
    from valvur.findings import Finding

    finding = Finding(rule="CVE-1", path="a.py", line=0, title="x", evidence="",
                      fingerprint="a" * 32, severity="high", sources=("trivy",))

    assert ScanRun(findings=[finding], db_age_days=400.0).status == "findings"


# ------------------------------------------- keeping it current cheaply (14.2)

def test_the_freshness_check_needs_no_network(tmp_path, monkeypatch):
    """What makes `--if-stale` safe in a pre-commit hook or a cron entry. Trivy
    stamps NextUpdate in its own metadata, so being past due costs one file read."""
    import socket

    from valvur.cli import _database_needs_refresh

    _database(tmp_path, updated_days_ago=0.2, next_update_days_ago=-0.8)
    (tmp_path / "trivy" / "db" / "trivy.db").write_text("")
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")

    def blocked(*args, **kwargs):
        raise AssertionError("the freshness check opened a socket")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)

    assert _database_needs_refresh() is False


def test_a_database_past_its_own_next_update_needs_refreshing(tmp_path, monkeypatch):
    from valvur.cli import _database_needs_refresh

    _database(tmp_path, updated_days_ago=9, next_update_days_ago=8)
    (tmp_path / "trivy" / "db" / "trivy.db").write_text("")
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")

    assert _database_needs_refresh() is True


def test_a_missing_database_needs_refreshing(tmp_path, monkeypatch):
    from valvur.cli import _database_needs_refresh

    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "nothing")

    assert _database_needs_refresh() is True


def test_if_stale_refreshes_anything_the_scan_would_call_inconclusive(
    tmp_path, monkeypatch
):
    """The command that fixes staleness must agree with the code that detects it.

    `NextUpdate` is the database's own opinion of its shelf life; `UpdatedAt` is when
    the data was built. They can disagree — a mirror serving old data with a
    forward-dated NextUpdate reads as "not due" while being 45 days old. Until
    2026-09-05 `--if-stale` consulted only the first, so it declined to refresh
    exactly the database that makes a scan report `inconclusive`.
    """
    from valvur.cli import _database_needs_refresh

    _database(tmp_path, updated_days_ago=45, next_update_days_ago=-1)
    (tmp_path / "trivy" / "db" / "trivy.db").write_text("")
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")

    # The scan's verdict and the fix path must not contradict each other.
    assert ScanRun(findings=[], db_age_days=cache.db_age_days()).status == "inconclusive"
    assert _database_needs_refresh() is True


def test_if_stale_still_does_nothing_for_a_genuinely_current_database(
    tmp_path, monkeypatch
):
    """The pair. If it refreshed on every run it would cost 116MB a time and stop
    being safe to put in a pre-commit hook, which is the whole point of it."""
    from valvur.cli import _database_needs_refresh

    _database(tmp_path, updated_days_ago=0.2, next_update_days_ago=-0.8)
    (tmp_path / "trivy" / "db" / "trivy.db").write_text("")
    monkeypatch.setattr(cache, "trivy_db", lambda: tmp_path / "trivy")

    assert _database_needs_refresh() is False
