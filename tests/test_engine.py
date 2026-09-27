"""R3.1 onwards: the in-image engine, tested without a container.

`LocalRuntime` runs `python -m valvur.engine` as a host process, with stand-in tools
from `tests/fixtures/fake-tools` first on its PATH: the container runtime is the one
boundary this suite fakes (tasks.md §3). The engine itself runs for real.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.adapters import GitleaksAdapter
from valvur.engine_host import LocalRuntime, snapshot

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
KEY = "AKIA" + "QX3ZR5TW7YB2MN4P"          # assembled: push protection is on


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{KEY}"\n')
    (ws / "README.md").write_text("# two files\n")
    return ws


def test_the_engine_unpacks_a_snapshot_and_leaves_a_report_and_a_manifest(tmp_path):
    ws = _workspace(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    tar = snapshot(ws, ["config.py", "README.md"])
    code = LocalRuntime(FAKE_TOOLS).run([GitleaksAdapter().command(ws)], tar, scratch)

    assert code == 0
    manifest = json.loads((scratch / "manifest.json").read_text())
    assert manifest["received"] == 2
    [entry] = manifest["tools"]
    assert (entry["tool"], entry["exit_code"], entry["timed_out"]) == ("gitleaks", 0, False)
    report = json.loads((scratch / "gitleaks.json").read_text())
    assert [item["File"] for item in report] == ["/workspace/config.py"]
