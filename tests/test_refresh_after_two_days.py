"""R11.3: a scan refreshes the index and KEV past two days (D24, F10.9, ADR-0027).

The index is published daily and was refreshed only past thirty days, so a real
package published since read as hallucinated at high. KEV was never refreshed by a
scan at all. Past D24's two days each is fetched, announced and recorded under
`network.fetched`, as ADR-0025 does for the database. `fetch = "never"` fetches
nothing. A failed refresh keeps the old data and says so, and the verdict thresholds,
which are unchanged, decide.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from test_first_run import (  # the fixture `host_cache`, reused
    _Runner,
    _scan,
    _write_db,
    _write_index,
    host_cache,  # noqa: F401
)

from valvur import enrichment, name_index, updating


def _stamp(days_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def _kev(root, days_ago: float) -> None:
    bundled = json.loads(enrichment._BUNDLED.read_text())
    (root / "kev.json").write_text(json.dumps({**bundled, "dateReleased": _stamp(days_ago)}))


def _refreshers(monkeypatch, host_cache, *, kev_ok: bool = True):  # noqa: F811
    calls: list[str] = []

    def index(*args, **kwargs):
        calls.append("index")
        return {}

    def kev(say):
        calls.append("kev")
        if not kev_ok:
            say("KEV refresh skipped (no route to host); the bundled snapshot remains in use.")
            return False
        _kev(host_cache, 0)
        return True

    monkeypatch.setattr(name_index.build, "refresh", index)
    monkeypatch.setattr(updating, "refresh_kev", kev)
    return calls


def test_an_index_and_kev_three_days_old_are_refreshed_announced_and_recorded(
    workspace, host_cache, monkeypatch  # noqa: F811
):
    _write_db(host_cache)
    _write_index(host_cache, built_at=_stamp(3))
    _kev(host_cache, 3)
    calls = _refreshers(monkeypatch, host_cache)

    run, said = _scan(workspace, _Runner(host_cache))

    assert calls == ["index", "kev"]
    assert any(line.startswith("refreshing the package-name index (3 days old)")
               for line in said), said
    assert any(line.startswith("refreshing KEV (3 days old)") for line in said), said
    assert [f["what"] for f in run.fetched] == ["package-name index", "KEV catalog"]


def test_within_two_days_nothing_is_fetched(workspace, host_cache, monkeypatch):  # noqa: F811
    _write_db(host_cache)
    _write_index(host_cache, built_at=_stamp(1))
    _kev(host_cache, 1)
    calls = _refreshers(monkeypatch, host_cache)

    run, _ = _scan(workspace, _Runner(host_cache))

    assert calls == [] and run.fetched == []


def test_with_fetch_never_neither_is_refreshed(workspace, host_cache, monkeypatch):  # noqa: F811
    monkeypatch.setenv("VALVUR_FETCH", "never")
    _write_db(host_cache)
    _write_index(host_cache, built_at=_stamp(3))
    _kev(host_cache, 3)
    calls = _refreshers(monkeypatch, host_cache)

    run, _ = _scan(workspace, _Runner(host_cache))

    assert calls == [] and run.fetched == []


def test_a_failed_refresh_keeps_the_old_catalog_and_says_so(
    workspace, host_cache, monkeypatch  # noqa: F811
):
    _write_db(host_cache)
    _write_index(host_cache, built_at=_stamp(1))
    _kev(host_cache, 3)
    _refreshers(monkeypatch, host_cache, kev_ok=False)

    run, said = _scan(workspace, _Runner(host_cache))

    assert any("KEV refresh skipped" in line for line in said), said
    assert run.fetched == []
    assert 2.9 < run.kev_age_days < 3.1                  # the old catalog, still in use
