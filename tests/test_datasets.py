"""Every dataset a scan reads, once (D52a): `valvur.datasets`.

Whether data was stale was decided in about twelve code paths, with thresholds in
four modules and a literal in a fifth, and they disagreed: a scan refreshed the Name
Index past 2 days, `update --if-stale` only past 30, and left KEV and EPSS alone
while the database was current (the review of 2026-10-03, §3.3).
"""

from __future__ import annotations

from valvur import datasets


def test_the_table_holds_d24():
    """A scan refreshes the database and OSV's databases past 7 days, and the index,
    the malicious list, KEV and EPSS past 2; a nil result is `inconclusive` past 7
    days of database and 30 of index, as before (D24, ADR-0027, F7.16)."""
    held = {d.key: (d.refresh_after_days, d.inconclusive_after_days) for d in datasets.ALL}

    assert held == {"database": (7, 7), "name_index": (2, 30), "malicious": (2, None),
                    "kev": (2, None), "epss": (2, None), "osv": (7, None)}


def test_each_dataset_names_its_mirror_setting_and_its_verifier():
    for dataset in datasets.ALL:
        assert dataset.setting.endswith(("_url", "_repository")), dataset.key
        assert dataset.verifier, dataset.key


def test_due_is_absent_or_past_the_refresh_threshold():
    index = datasets.NAME_INDEX

    assert index.due(None) and index.due(2.5) and not index.due(1.0)
    assert index.stale(31.0) and not index.stale(29.0) and not index.stale(None)
    assert not datasets.KEV.stale(400.0)       # KEV ranks; it never makes a verdict


# ------------------------------------------- update --if-stale does what a scan does

import dataclasses  # noqa: E402

import pytest  # noqa: E402

#: The datasets' ages for each case, in days; None is absent. What a scan fetches
#: and refreshes is decided from these alone.
CASES = {
    "all current": {},
    "the index past two days": {"name_index": 3.0},
    "the malicious list past two days": {"malicious": 3.0},
    "KEV past two days": {"kev": 3.0},
    "EPSS absent": {"epss": None},
    "the database past a week": {"database": 10.0},
    "everything old": {"database": 40.0, "name_index": 40.0, "malicious": 40.0,
                       "kev": 40.0, "epss": 40.0},
}


def _aged(monkeypatch, ages: dict) -> None:
    """Every dataset current (a day old) but those `ages` names."""
    table = []
    for dataset in datasets.ALL:
        age = ages.get(dataset.key, 1.0)
        aged = dataclasses.replace(dataset, reader=lambda _, age=age: age)
        monkeypatch.setattr(datasets, dataset.key.upper(), aged)
        table.append(aged)
    monkeypatch.setattr(datasets, "ALL", tuple(table))


def _recording(monkeypatch) -> tuple[list[str], object]:
    """Each fetch the scan or `update` makes, recorded by dataset and not made."""
    from valvur import name_index, updating
    from valvur.invocation import ScannerOutput

    fetched: list[str] = []
    monkeypatch.setattr(name_index.build, "refresh",
                        lambda *a, **k: fetched.append("name_index") or {})
    monkeypatch.setattr(updating, "refresh_malicious",
                        lambda say, **k: fetched.append("malicious") or True)
    monkeypatch.setattr(updating, "refresh_kev", lambda say: fetched.append("kev") or True)
    monkeypatch.setattr(updating, "refresh_epss", lambda say: fetched.append("epss") or True)

    class Runner:
        image = "valvur:dev"
        cancelled = False

        def image_present(self):
            return True

        def db_size_mb(self):
            return None

        def update_db(self):
            fetched.append("database")
            return ScannerOutput("trivy", "", "", "", 0)

    return fetched, Runner()


@pytest.mark.parametrize("case", list(CASES))
def test_update_if_stale_refreshes_exactly_what_a_scan_would(monkeypatch, case):
    from valvur import api, updating

    _aged(monkeypatch, CASES[case])
    by_scan, runner = _recording(monkeypatch)
    api._ensure_data(runner, None)
    by_update, runner = _recording(monkeypatch)
    updating.run(lambda _: None, runner, if_stale=True)

    assert sorted(by_update) == sorted(by_scan), case
