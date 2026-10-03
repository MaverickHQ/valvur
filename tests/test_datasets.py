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

        fetches = True                 # it fetches before a scan (24.1)

        def update_db(self):
            fetched.append("database")
            return ScannerOutput("trivy", "", "", "", 0)

    return fetched, Runner()


@pytest.mark.parametrize("case", list(CASES))
def test_update_if_stale_refreshes_exactly_what_a_scan_would(monkeypatch, case):
    from valvur import fetching, updating

    _aged(monkeypatch, CASES[case])
    by_scan, runner = _recording(monkeypatch)
    fetching.ensure_data(runner, None)
    by_update, runner = _recording(monkeypatch)
    updating.run(lambda _: None, runner, if_stale=True)

    assert sorted(by_update) == sorted(by_scan), case


def test_doctor_run_json_and_the_reply_read_ages_through_the_table(tmp_path, monkeypatch):
    """One row changed in the table, and each surface says what the row says."""
    import json
    import shutil
    from pathlib import Path

    from valvur import api, doctor, engine_host, operations
    from valvur.adapters import GitleaksAdapter

    fixtures = Path(__file__).parent / "fixtures"
    monkeypatch.setattr(datasets, "DATABASE", dataclasses.replace(
        datasets.DATABASE, reader=lambda _: 9.5, refresh_after_days=8,
        inconclusive_after_days=8))
    monkeypatch.setattr(engine_host, "for_scan",
                        lambda: engine_host.LocalRuntime(fixtures / "fake-tools"))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    ws = tmp_path / "ws"
    shutil.copytree(fixtures / "clean-repo", ws)

    [line] = [c for c in doctor.run(ws) if c.name == "database"]
    assert "9.5 days old (threshold 8)" in line.detail

    from valvur import service

    service.run_scan(ws, runner=engine_host.LocalRuntime(fixtures / "fake-tools"))
    record = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert record["database"]["age_days"] == 9.5
    assert (record["database"]["stale"], record["database"]["stale_after_days"]) == (True, 8)
    assert record["data"]["database"] == {"age_days": 9.5, "basis": "built"}

    _, fields = operations.status_of(ws)
    assert any("database is 10 days old" in line for line in fields["caveats"])


#: The registry walk's own cadence, which builds the index for the publishing
#: workflow and `--build-index`: how soon a walk may repeat, and when npm's change
#: feed is too old to follow. Neither decides a refresh or a verdict.
_WALK_CADENCE = {"src/valvur/name_index/build.py"}


def _compares_an_age_with_a_number(node) -> bool:
    import ast

    if not isinstance(node, ast.Compare) or not any(
            isinstance(op, ast.Lt | ast.LtE | ast.Gt | ast.GtE) for op in node.ops):
        return False
    operands = [node.left, *node.comparators]

    def names(operand) -> set[str]:
        return {part for n in ast.walk(operand)
                for part in (n.id if isinstance(n, ast.Name) else
                             n.attr if isinstance(n, ast.Attribute) else "").lower().split("_")}

    aged = any("age" in names(o) for o in operands)
    numbered = any((isinstance(o, ast.Constant) and isinstance(o.value, int | float)
                    and not isinstance(o.value, bool) and o.value != 0)
                   or ast.unparse(o).endswith("_DAYS") for o in operands)
    return aged and numbered


def test_no_other_module_compares_a_datasets_age_with_a_number():
    import ast
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    found = []
    for path in sorted((repo / "src" / "valvur").rglob("*.py")):
        rel = path.relative_to(repo).as_posix()
        if rel in {"src/valvur/datasets.py", *_WALK_CADENCE}:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if _compares_an_age_with_a_number(node):
                found.append(f"{rel}:{node.lineno}: {ast.unparse(node)}")

    assert found == []


def test_the_check_sees_a_threshold_compared_by_hand():
    import ast

    for written in ("age > 30", "db_age <= cache.DB_STALE_AFTER_DAYS",
                    "run.kev_age_days >= 2.0"):
        assert _compares_an_age_with_a_number(ast.parse(written, mode="eval").body), written
    for written in ("age is None", "overdue > 0", "len(pages) > 30", "age > other_age"):
        assert not _compares_an_age_with_a_number(ast.parse(written, mode="eval").body)
