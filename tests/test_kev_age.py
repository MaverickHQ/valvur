"""R11.1: KEV's age is its catalog's (D23, F6.12).

It was the file's modification time: a package installed on 2026-09-26 called the
2026-08-27 catalog three days old, and the 30-day staleness could never fire. F6.11
forbade exactly this for the vulnerability database. The catalog says when it was
released; that is its age.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from valvur import enrichment

BUNDLED_RELEASE = datetime(2026, 8, 27, 17, 0, 36, tzinfo=UTC)


def _days_since(moment: datetime) -> float:
    return (datetime.now(UTC) - moment).total_seconds() / 86400


@pytest.fixture
def bundle(tmp_path, monkeypatch) -> Path:
    """The package's snapshot, copied where its file time can be set, and no cached
    copy beside it."""
    copy = tmp_path / "bundled-kev.json"
    shutil.copy(enrichment._BUNDLED, copy)
    monkeypatch.setattr(enrichment, "_BUNDLED", copy)
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    monkeypatch.setattr(enrichment.cache, "root", lambda: cache_root)
    return copy


def test_the_bundled_snapshot_is_as_old_as_its_catalog_however_new_its_file(bundle):
    now = time.time()
    os.utime(bundle, (now, now))

    provider = enrichment.LocalProvider()

    assert provider.kev_age_days == pytest.approx(_days_since(BUNDLED_RELEASE), abs=0.01)
    assert provider.kev_catalog == "2026-08-27"
    assert provider.kev_source == "bundled snapshot"


def test_the_newer_catalog_wins_not_the_newer_file(bundle):
    cached = enrichment.cache.root() / "kev.json"
    newer = {"catalogVersion": "2026.09.28", "dateReleased": "2026-09-28T16:00:00Z",
             "entries": {"CVE-2026-0001": {"r": False, "d": "2026-09-28"}}}
    cached.write_text(json.dumps(newer))
    a_week_ago = time.time() - 7 * 86400
    os.utime(cached, (a_week_ago, a_week_ago))          # an older file, a newer catalog

    assert enrichment.LocalProvider().kev_catalog == "2026-09-28"

    older = {**newer, "catalogVersion": "2026.08.01", "dateReleased": "2026-08-01T16:00:00Z"}
    cached.write_text(json.dumps(older))                 # a newer file, an older catalog

    assert enrichment.LocalProvider().kev_catalog == "2026-08-27"


def test_a_copy_that_carries_no_release_date_is_aged_by_its_fetch_and_says_so(bundle):
    cached = enrichment.cache.root() / "kev.json"
    cached.write_text(json.dumps({"catalogVersion": "", "entries": {}}))
    shutil.copy(cached, bundle)                          # neither says when it was released

    provider = enrichment.LocalProvider()

    assert provider.kev_catalog == ""
    assert provider.kev_age_basis == "fetched"


def test_run_json_and_doctor_state_the_catalog_its_age_and_its_source(bundle):
    from valvur import doctor, provenance
    from valvur.api import ScanRun

    run = ScanRun(kev_age_days=33.2, kev_source="bundled snapshot", kev_catalog="2026-08-27")
    enrichment_record = json.loads(provenance.render(run))["enrichment"]
    check = doctor._check_kev()

    assert enrichment_record["kev_catalog"] == "2026-08-27"
    assert enrichment_record["kev_source"] == "bundled snapshot"
    assert enrichment_record["kev_age_days"] == 33.2
    assert "2026-08-27" in check.detail and "bundled" in check.detail
