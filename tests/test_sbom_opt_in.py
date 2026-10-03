"""The SBOM is opt-in (the owner's decision, 2026-09-28; D9).

Syft ran on every scan for an SBOM no Finding depends on. It now runs when a scan
asks: `scan --sbom`, or `sbom = true` under `[scan]` in `.security-scan.toml`. The
dependency licence policy (F4.4 to F4.6) reads that SBOM, so it is opt-in with it,
and a scan that did not run Syft says so, as it says any Scanner it skipped.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.adapters import GitleaksAdapter, SyftAdapter
from valvur.engine_host import LocalRuntime

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    return ws


def test_by_default_no_sbom_is_written_and_the_skip_says_how_to_ask(tmp_path):
    from valvur import api

    ws = _workspace(tmp_path)
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter(), SyftAdapter()])

    folder = ws / ".security-scan"
    assert not (folder / "sbom.cdx.json").exists()
    run = json.loads((folder / "run.json").read_text())
    reason = run["scanners_skipped"]["syft"]
    assert "--sbom" in reason and "licence" in reason
    assert f"**syft** — {reason}" in (folder / "SUMMARY.md").read_text()


def test_the_project_or_the_command_line_asks_for_it(tmp_path):
    ws = _workspace(tmp_path)
    assert SyftAdapter().applies_to(ws)[0] is False
    assert SyftAdapter(enabled=True).applies_to(ws) == (True, "")

    (ws / ".security-scan.toml").write_text("[scan]\nsbom = true\n")
    assert SyftAdapter().applies_to(ws) == (True, "")


def test_scan_sbom_reaches_the_scan(tmp_path, monkeypatch):
    from valvur import cli, service

    seen = {}

    def fake_scan(workspace, *, profile, jobs=None, sbom=False, **asked):
        seen["sbom"] = sbom
        from valvur.api import ScanRun

        return ScanRun()

    monkeypatch.setattr(service, "run_scan", fake_scan)
    ws = _workspace(tmp_path)
    assert cli.main(["scan", str(ws), "--sbom"], runner=LocalRuntime(FAKE_TOOLS)) == 0
    assert seen["sbom"] is True


def test_the_project_file_schema_takes_the_key():
    from valvur import project_schema

    assert project_schema.problem({"scan": {"sbom": True}}) is None
    assert project_schema.problem({"scan": {"sbom": "yes"}}) is not None
