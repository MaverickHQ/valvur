"""R3.9: the File Set is what every surface reports, and the only exclusion.

The per-tool skip flags, the built-in vendored list, the generated Gitleaks
config and `honour_gitignore` are gone (ADR-0021, ADR-0022): the File Set is
decided once, before the Snapshot, and every Scanner reads only the Snapshot. So
the record says what the File Set was and what it left out, with the reason.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api
from valvur.engine_host import LocalRuntime

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


@pytest.fixture
def ws(tmp_path, monkeypatch) -> Path:
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    root = tmp_path / "ws"
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "package.json").write_text('{"name": "left-pad"}')
    (root / "archive").mkdir()
    (root / "archive" / "old.py").write_text("x = 1\n")
    (root / "app.py").write_text("print('hi')\n")
    (root / ".security-scan.toml").write_text('[scan]\nexclude = ["archive"]\n')
    return root


def _scan(ws: Path):
    from valvur.adapters import GitleaksAdapter

    said: list[str] = []
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()],
                   on_progress=said.append)
    return run, said


def test_the_record_says_what_was_read_and_what_was_left_out_and_why(ws):
    run, said = _scan(ws)
    assert run.scope["scope"] == "tree" and run.scope["files"] == 2
    assert len(run.scope["sha256"]) == 64
    assert ("node_modules", "a dependency cache") in run.not_read
    assert ("archive", "excluded by .security-scan.toml") in run.not_read
    assert said[0].startswith("workspace: 2 files to scan")

    record = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert record["scope"] == run.scope
    assert {"path": "node_modules", "reason": "a dependency cache"} in record["not_read"]
    summary = (ws / ".security-scan" / "SUMMARY.md").read_text()
    assert "`node_modules` (a dependency cache)" in summary


def test_no_scanner_is_told_what_to_skip_because_none_is_given_it(ws, monkeypatch):
    from valvur import adapters, cache
    from valvur.adapters.check import single_command

    monkeypatch.setattr(cache, "db_present", lambda: True)
    for cls in ("TrivyAdapter", "CheckovAdapter", "SyftAdapter", "OpengrepAdapter",
                "OsvAdapter", "GitleaksAdapter"):
        invocation = getattr(adapters, cls)().command(ws)
        argv = " ".join(invocation.argv)
        for flag in ("--skip-dirs", "--skip-path", "--exclude", "--experimental-exclude"):
            assert flag not in argv, (cls, flag)
        # Opengrep's one file is an ignore list that ignores nothing (R3.9).
        assert all(name == ".semgrepignore" for name, _ in invocation.files), cls
    # Gitleaks reads the project's own `.gitleaks.toml` from what it scans.
    assert "--config" not in adapters.GitleaksAdapter().command(ws).argv
    assert single_command("ai-artifact", ws, network=False).env == ()


def test_checkov_is_decided_by_the_file_set_not_the_tree(tmp_path):
    from valvur.applicability import iac_present

    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "main.tf").write_text('resource "x" "y" {}\n')
    (tmp_path / "app.py").write_text("x = 1\n")
    assert iac_present(tmp_path) == (False, "")
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text('resource "x" "y" {}\n')
    assert iac_present(tmp_path) == (True, "infra/main.tf")


def test_a_manifest_outside_the_file_set_is_not_a_coverage_gap(tmp_path):
    from valvur.coverage import dependency_gaps

    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "Pipfile").write_text("[packages]\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    assert dependency_gaps(tmp_path) == []


def test_the_cli_and_scan_status_name_what_was_not_read(ws, capsys, monkeypatch):
    from valvur import cli, engine_host
    from valvur.adapters import GitleaksAdapter
    from valvur.operations import scan_status_reply

    monkeypatch.setattr(engine_host, "for_scan", lambda: LocalRuntime(FAKE_TOOLS))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    assert cli.main(["scan", str(ws)]) == 0
    assert "not read: node_modules (a dependency cache)" in capsys.readouterr().out
    text, fields = scan_status_reply({"workspace": str(ws)})
    assert "not read by any Scanner: " in text and "node_modules (a dependency cache)" in text
    assert {"path": "node_modules", "reason": "a dependency cache"} in fields["not_read"]


def test_a_checks_walk_never_descends_into_an_excluded_prefix(tmp_path):
    """Inside the Scan Container the Workspace is the File Set; the walk still
    honours a prefix it is given, and never walks version control or valvur's
    own folder."""
    from valvur import exclusions

    for rel in ("src/a.py", "src/distribution/y.py", "tests/fixtures/d/x.py",
                "tests/unit.py", ".git/HEAD", ".security-scan/run.json"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")

    found = sorted(p.relative_to(tmp_path).as_posix()
                   for p in exclusions.walk_files(tmp_path, ("tests/fixtures",)))

    assert found == ["src/a.py", "src/distribution/y.py", "tests/unit.py"]
