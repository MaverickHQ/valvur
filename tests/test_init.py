"""R6.8: `valvur init` prints and never writes (D10).

For each MCP client found on this machine or in this project, the file it reads
and the block to paste; and a starter `.security-scan.toml` whose excludes come
from the pre-flight count, suggested and commented, since an exclusion is the
human's decision. Nothing on disk changes: `init --write` is the owner's to decide.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from valvur import cli


def _tree(root: Path) -> dict[str, float]:
    return {str(p.relative_to(root)): p.stat().st_mtime for p in root.rglob("*")}


@pytest.fixture
def project(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    ws = tmp_path / "project"
    (ws / ".kiro" / "steering").mkdir(parents=True)
    (ws / "src").mkdir()
    (ws / "src" / "app.py").write_text("print('hi')\n")
    for i in range(40):
        (ws / "data" / f"{i:03}.json").parent.mkdir(exist_ok=True)
        (ws / "data" / f"{i:03}.json").write_text("{}\n")
    return ws


def test_init_prints_the_found_clients_block_and_a_starter_and_writes_nothing(project,
                                                                             capsys):
    before = _tree(project)

    assert cli.main(["init", str(project)]) == 0
    out = capsys.readouterr().out

    assert "Kiro reads .kiro/settings/mcp.json" in out and '"valvur"' in out
    assert "Claude Code reads" not in out, "a client not found here was offered"
    starter = out.split("```toml\n", 1)[1].split("```", 1)[0]
    parsed = tomllib.loads(starter)
    assert parsed["scan"]["exclude"] == []
    assert '# exclude = ["data"]' in starter
    assert "data/ 40" in starter
    assert _tree(project) == before, "init wrote something"


def test_with_no_client_found_it_names_the_two_this_is_for(project, capsys):
    import shutil

    shutil.rmtree(project / ".kiro")

    assert cli.main(["init", str(project)]) == 0
    out = capsys.readouterr().out

    assert "No MCP client configuration was found" in out
    assert "Claude Code reads .mcp.json" in out and "Kiro reads" in out
