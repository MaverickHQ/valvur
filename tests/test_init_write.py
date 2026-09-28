"""`valvur init --write` (the owner's decision, 2026-09-28; D10, R6.8).

`init` printed and never wrote, because writing into the project was the owner's to
allow (CLAUDE.md §10). Allowed now, `--write` writes what `init` prints: the starter
`.security-scan.toml` when there is none, and the valvur server into each client's
project file, merged beside what is there. It never overwrites: a file that already
names valvur is left, a file it cannot read is left and said, and a client whose file
lives outside the project is said, not written.
"""

from __future__ import annotations

import json
import tomllib

from test_init import _tree, project  # noqa: F401 — the fixture, registered by import

from valvur import cli, project_schema


def test_write_creates_the_project_file_and_the_found_clients_file(project, capsys):  # noqa: F811
    assert cli.main(["init", str(project), "--write"]) == 0
    out = capsys.readouterr().out

    policy = tomllib.loads((project / ".security-scan.toml").read_text())
    assert project_schema.problem(policy) is None
    kiro = json.loads((project / ".kiro" / "settings" / "mcp.json").read_text())
    assert kiro["mcpServers"]["valvur"]["args"] == ["--from", "valvur", "valvur-mcp"]
    assert "wrote .security-scan.toml" in out and "wrote .kiro/settings/mcp.json" in out

    before = _tree(project)
    assert cli.main(["init", str(project), "--write"]) == 0
    again = capsys.readouterr().out
    assert _tree(project) == before, "a second --write changed something"
    assert "left .security-scan.toml as it is" in again
    assert "already names valvur" in again


def test_write_merges_beside_other_servers_and_never_overwrites(project, capsys):  # noqa: F811
    settings = project / ".kiro" / "settings"
    settings.mkdir(parents=True)
    (settings / "mcp.json").write_text(json.dumps(
        {"mcpServers": {"other": {"command": "other-mcp"}}, "note": "kept"}))
    (project / ".security-scan.toml").write_text('[scan]\nexclude = ["data"]\n')

    assert cli.main(["init", str(project), "--write"]) == 0

    kiro = json.loads((settings / "mcp.json").read_text())
    assert kiro["mcpServers"]["other"] == {"command": "other-mcp"}
    assert kiro["note"] == "kept"
    assert "valvur" in kiro["mcpServers"]
    assert (project / ".security-scan.toml").read_text() == '[scan]\nexclude = ["data"]\n'


def test_a_file_it_cannot_read_is_left_and_said(project, capsys):  # noqa: F811
    settings = project / ".kiro" / "settings"
    settings.mkdir(parents=True)
    (settings / "mcp.json").write_text("{ not json")

    assert cli.main(["init", str(project), "--write"]) == 1
    out = capsys.readouterr().out

    assert (settings / "mcp.json").read_text() == "{ not json"
    assert "not valid JSON" in out
    assert (project / ".security-scan.toml").is_file()


def test_a_client_whose_file_is_outside_the_project_is_said_not_written(project,  # noqa: F811
                                                                      capsys):
    assert cli.main(["init", str(project), "--write", "--client", "codex"]) == 1
    out = capsys.readouterr().out

    assert "~/.codex/config.toml" in out and "outside the project" in out
    assert not (project / ".codex").exists()


def test_without_write_nothing_changes(project):  # noqa: F811
    before = _tree(project)
    assert cli.main(["init", str(project)]) == 0
    assert _tree(project) == before
