"""29.2.2 — `doctor` knows every client (the gate's B8; 10.2 claim 3).

`_check_mcp` read Claude Code's and Kiro's files. It now reads every file in
`mcp.clients`, each in its own shape, says whether the program a server names is
on PATH, and `valvur doctor --client <name>` prints the snippet from the same
table the README renders from.
"""

from __future__ import annotations

import json

import pytest
from test_doctor import healthy  # noqa: F401 — the fixture, registered here by import

from valvur import doctor
from valvur.mcp import clients

EXPECTED = "valvur (uvx --from valvur valvur-mcp)"


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_every_client_in_the_table_is_read_in_its_own_shape(healthy, monkeypatch):  # noqa: F811 — the imported fixture
    from pathlib import Path

    home = Path.home()
    for entry in clients.CLIENTS:
        label, path = clients.lookups(entry, healthy, home, "Darwin")[0]
        _write(path, clients.snippet(entry))
    monkeypatch.setattr("shutil.which", lambda program: "/usr/local/bin/uvx")

    detail = doctor._check_mcp(healthy).detail

    for entry in clients.CLIENTS:
        label, _ = clients.lookups(entry, healthy, home, "Darwin")[0]
        assert f"{label}: {EXPECTED}" in detail, (entry.key, detail)


def test_a_server_whose_program_is_not_on_path_is_said(healthy, monkeypatch):  # noqa: F811 — the imported fixture
    _write(healthy / ".mcp.json", json.dumps({"mcpServers": {"valvur": {
        "command": "valvur-mcp-that-does-not-exist", "args": []}}}))
    monkeypatch.setattr("shutil.which", lambda program: None)

    detail = doctor._check_mcp(healthy).detail

    assert ".mcp.json: valvur (valvur-mcp-that-does-not-exist), " \
           "`valvur-mcp-that-does-not-exist` is not on PATH" in detail


def test_a_malformed_toml_or_json_is_said_unreadable(healthy):  # noqa: F811 — the imported fixture
    from pathlib import Path

    _write(Path.home() / ".codex" / "config.toml", "[mcp_servers.valvur\ncommand = ")
    _write(healthy / ".cursor" / "mcp.json", "{ not json")

    detail = doctor._check_mcp(healthy).detail

    assert "~/.codex/config.toml: unreadable (not TOML)" in detail
    assert ".cursor/mcp.json: unreadable (not JSON)" in detail


def test_nothing_configured_names_the_printer(healthy):  # noqa: F811 — the imported fixture
    detail = doctor._check_mcp(healthy).detail
    assert detail.startswith("no MCP client configuration names valvur here")
    assert "valvur doctor --client" in detail


@pytest.mark.parametrize("key", [c.key for c in clients.CLIENTS])
def test_doctor_client_prints_the_snippet_from_the_table(key, capsys):
    from valvur.cli import main

    assert main(["doctor", "--client", key]) == 0
    out = capsys.readouterr().out
    entry = clients.client(key)
    assert clients.snippet(entry) in out
    assert entry.files[0] in out and entry.after in out
