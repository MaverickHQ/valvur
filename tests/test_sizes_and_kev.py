"""29.3.2 — sizes and the KEV line say which (the gate's B9).

`doctor` and the README said 118 MB and 34 MB (what is fetched); `valvur cache`
said 1.45 GB and 123 MB (what is on disk); `valvur cache` said `kev: absent`
while `doctor` said *bundled snapshot from the image*. Both true, read as a
contradiction. Every surface now says both numbers with their names, from one
table, and the KEV row reads the same in both places.
"""

from __future__ import annotations

import re
from pathlib import Path

from test_doctor import healthy  # noqa: F401 — the fixture, registered here by import

from valvur import cache, doctor

REPO = Path(__file__).resolve().parent.parent


def test_the_fetch_sizes_live_in_one_table_and_the_readme_holds_to_them():
    assert cache.FETCH_MB == {"database": 123, "index": 36}   # docs/acceptance/r7.md
    readme = (REPO / "README.md").read_text()
    for name, mb in cache.FETCH_MB.items():
        assert f"{mb} MB to fetch" in readme, f"the README does not say what the {name} costs"
    assert "on disk" in readme


def test_doctor_says_both_numbers_for_the_database_and_the_index(healthy):  # noqa: F811
    by = {c.name: c for c in doctor.run(healthy)}
    database, index = cache.fetch_note("database"), cache.fetch_note("index")
    assert re.search(rf"\d+\.\d days old; [\d.]+ [KMG]?B on disk \({database}\)",
                     by["database"].detail), by["database"].detail
    assert re.search(rf" on disk \({index}\)$", by["index"].detail), by["index"].detail

    cache.trivy_db().rename(cache.trivy_db().with_name("gone"))
    absent = doctor._check_database()
    assert f"{database}, about 1.4 GB on disk" in absent.detail, absent.detail


def test_the_kev_line_reads_the_same_on_both_surfaces(healthy, capsys):  # noqa: F811
    from valvur.cli import _print_cache

    # With no cached copy, the bundled snapshot is named with its catalog's day and
    # age (R11.1), and both surfaces say what that means.
    assert doctor._check_kev().detail.startswith("bundled snapshot, catalog 2026-08-27, ")
    assert doctor._check_kev().detail.endswith(cache.KEV_ABSENT_MEANS)
    _print_cache(clear=False)
    out = capsys.readouterr().out
    assert f"kev       absent — {cache.KEV_ABSENT_MEANS}" in out

    kev = cache.root() / "kev.json"
    kev.write_text("{}")
    assert doctor._check_kev().detail.startswith("host cache, ")
    assert "a fresher copy than the image's snapshot" in doctor._check_kev().detail
    _print_cache(clear=False)
    out = capsys.readouterr().out
    assert re.search(r"kev\s+\S+ B\s+0\.0 days old — a fresher copy than the image's snapshot",
                     out), out


def test_valvur_cache_says_what_a_present_database_costs_to_fetch(healthy, capsys):  # noqa: F811
    from valvur.cli import _print_cache

    _print_cache(clear=False)
    out = capsys.readouterr().out
    database, index = cache.fetch_note("database"), cache.fetch_note("index")
    assert re.search(rf"database\s+[\d.]+ [KMG]?B\s+0\.3 days old — {database}", out), out
    assert re.search(rf"index\s+[\d.]+ [KMG]?B\s+0\.0 days old — .*{index}", out), out
