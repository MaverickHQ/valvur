"""29.1.2 — the pre-flight count (the gate's B1, B7; P1).

Measured at the first gate: 107,544 files were walked by eight Scanners before
anyone counted them, and the failure that followed named neither the count nor
the directory. One pruned walk before the fleet — 0.02 s on that tree with its
exclude, 0.69 s without (103,578 files) — puts the count and the largest
directories on the first status line, in `run.json`, in the budget's refusal
and in `doctor`, and names the directory that would drop them before the
budget is spent rather than after.
"""

from __future__ import annotations

import json
import time

import pytest
from test_budget import _Adapter, _Runner, _scan

from valvur import api, exclusions


def _tree(root, spec: dict[str, int]) -> None:
    for top, count in spec.items():
        (root / top).mkdir(parents=True, exist_ok=True)
        for i in range(count):
            (root / top / f"f{i}.txt").write_text("")


def test_count_files_prunes_what_the_scan_skips_and_names_the_largest(tmp_path):
    _tree(tmp_path, {"src": 3, "data": 50, "node_modules": 40, "tests/fixtures": 20, "docs": 5})
    (tmp_path / "README.md").write_text("")

    files, largest = exclusions.count_files(tmp_path, ("tests/fixtures",))

    assert files == 3 + 50 + 5 + 1, "vendored and excluded directories are not read, so not counted"
    assert largest == (("data", 50), ("docs", 5), ("src", 3))


def test_the_first_progress_line_is_the_workspace(workspace):
    _, said = _scan(workspace, _Runner(), [_Adapter("fast", 0.05)])

    assert said[0].startswith("workspace: ") and "files to scan; largest:" in said[0], said[0]
    assert said[1].startswith("fleet: ")


def test_a_large_tree_names_the_directory_before_the_fleet_starts(workspace, monkeypatch):
    _tree(workspace, {"archive": 30})
    monkeypatch.setattr(exclusions, "LARGE_TREE", 20)

    _, said = _scan(workspace, _Runner(), [_Adapter("fast", 0.05)])

    warning = next(line for line in said if "holds" in line)
    assert warning.startswith("workspace: archive holds 30 of them")
    assert '[scan] exclude = ["archive"]' in warning
    assert said.index(warning) < said.index("fleet: 1 Scanners, 1 at a time")


def test_run_json_carries_the_count(workspace):
    _scan(workspace, _Runner(), [_Adapter("fast", 0.05)])

    run = json.loads((workspace / ".security-scan" / "run.json").read_text())
    assert run["workspace"]["files"] > 0
    assert isinstance(run["workspace"]["largest"], list) and len(run["workspace"]["largest"]) <= 3


def test_the_budget_refusal_names_the_count(workspace):
    _tree(workspace, {"data": 40})

    with pytest.raises(api.BudgetExhausted) as caught:
        _scan(workspace, _Runner(), [_Adapter("slow", 5.0)], budget_s=0.3)

    text = str(caught.value)
    assert "The workspace holds 54 files (data 40" in text, text
    assert text.index("The workspace holds") < text.index("To finish:")


def test_scan_status_gives_the_workspace_its_own_line(tmp_path, monkeypatch):
    from valvur.mcp import jobs
    from valvur.operations import scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    hold = jobs.threading.Event()

    def work(workspace, profile, progress):
        progress("workspace: 5 files to scan; largest: src 5")
        progress("fleet: 1 Scanners, 1 at a time")
        hold.wait(5)

    job = jobs.start(tmp_path, "offline", work)
    time.sleep(0.2)
    try:
        status = scan_status({"workspace": str(tmp_path)})
    finally:
        hold.set()
        job.settled.wait(5)
        jobs.reset()

    assert "Workspace: 5 files to scan; largest: src 5" in status
    assert "Completed so far: starting" in status, "the count is not a completion"


def test_doctor_counts_the_workspace_and_names_a_large_directory(tmp_path, monkeypatch):
    from valvur import doctor

    _tree(tmp_path, {"src": 3, "archive": 30})
    ok = doctor._check_workspace(tmp_path)
    assert ok.name == "workspace" and ok.level == "ok"
    assert "33 files to scan" in ok.detail and "archive 30" in ok.detail

    monkeypatch.setattr(exclusions, "LARGE_TREE", 20)
    warn = doctor._check_workspace(tmp_path)
    assert warn.level == "warn" and "archive holds 30" in warn.detail
    assert '[scan] exclude = ["archive"]' in warn.fix

    (tmp_path / ".security-scan.toml").write_text('[scan]\nexclude = ["archive"]\n')
    after = doctor._check_workspace(tmp_path)
    # The config file just written is a file a scan reads: 3 + 1.
    assert after.level == "ok" and "4 files to scan" in after.detail
    assert "excluded: archive" in after.detail
