"""R11.2: an OSV database's age is its export's, not its file's (D23, F6.12).

OSV's bucket says when each ecosystem's export last changed, in `Last-Modified`. The
fetch keeps that beside the database, and staleness is judged by it. A mirror that
serves an old export today would otherwise read as new, as a mirrored vulnerability
database would have before F6.11. A copy that carries no date is aged by its fetch,
and says so.
"""

from __future__ import annotations

import io
import os
import time
from datetime import UTC, datetime

import pytest

from valvur import osv_offline


class _Response(io.BytesIO):
    def __init__(self, body: bytes, headers: dict[str, str]):
        super().__init__(body)
        self.headers = headers


def _opener(headers: dict[str, str]):
    return lambda url, timeout: _Response(b"PK\x05\x06" + b"\x00" * 18, headers)


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")


def test_a_fetch_keeps_the_exports_date_and_the_age_is_read_from_it():
    osv_offline.fetch("PyPI", opener=_opener({"Last-Modified": "Sat, 26 Sep 2026 10:00:00 GMT"}))

    age, basis = osv_offline.age("PyPI")
    expected = (datetime.now(UTC) - datetime(2026, 9, 26, 10, tzinfo=UTC)).total_seconds() / 86400

    assert basis == "published"
    assert age == pytest.approx(expected, abs=0.01)


def test_without_a_date_the_age_is_the_fetch_and_says_so():
    osv_offline.fetch("npm", opener=_opener({}))

    age, basis = osv_offline.age("npm")

    assert basis == "fetched"
    assert age == pytest.approx(0, abs=0.01)


def test_staleness_is_the_exports_age_however_new_the_file():
    ten_days = time.gmtime(time.time() - 10 * 86400)
    osv_offline.fetch("Go", opener=_opener(
        {"Last-Modified": time.strftime("%a, %d %b %Y %H:%M:%S GMT", ten_days)}))
    now = time.time()
    os.utime(osv_offline.path("Go"), (now, now))

    from valvur import datasets

    assert osv_offline.stale(["Go"], datasets.OSV.due) == ["Go"]
