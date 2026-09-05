"""Phase 14 — a clean result from a stale database is not a clean result.

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
from valvur.results import _provenance, _summary


def _database(tmp_path, *, updated_days_ago: float, next_update_days_ago: float = 0.0):
    """A Trivy database directory with a chosen build time."""
    db = tmp_path / "trivy" / "db"
    db.mkdir(parents=True)
    now = datetime.now(UTC)
    (db / "metadata.json").write_text(json.dumps({
        "Version": 2,
        "UpdatedAt": (now - timedelta(days=updated_days_ago)).isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(days=next_update_days_ago)).isoformat().replace("+00:00", "Z"),
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


def test_valvur_never_updates_the_database_by_itself():
    """Decided in 14.2. A 1.2GB download started inside a scan is hostile; doing it
    on `full` alone would make the Profiles scan different data and break the
    equivalence asserted in Phase 11 cycle 3; and updating on the user's behalf is
    the same move as fixing on their behalf, which section 4 refuses."""
    import inspect

    from valvur import api

    source = inspect.getsource(api.scan)

    assert "update_db" not in source, (
        "a scan now updates the database by itself — see task 14.2 for why it must not"
    )
