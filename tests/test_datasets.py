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
