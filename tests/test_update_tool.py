"""R6.6: an `update` MCP tool fetches, and says what it fetched (ADR-0025; F10.8).

The agent path had no way to refresh the data a scan reads: `valvur update` is a
shell command. The tool runs the same steps as the command, each line sent as
progress on the way, and answers with the list of what it fetched. It is an
explicit request, so `fetch = never` does not refuse it: an air-gapped site runs
it against its mirrors.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import McpSession

from valvur import cache, engine_host, name_index
from valvur.runner import ScannerOutput


class _Runner:
    """A runtime with the image, whose database fetch writes the database."""

    image = "ghcr.io/maverickhq/valvur:9.9.9"
    runtime = "/usr/local/bin/docker"

    def __init__(self, root: Path):
        self.root = root

    def image_present(self) -> bool:
        return True

    def db_size_mb(self):
        return 118

    fetches = True                 # it fetches before a scan (24.1)

    def update_db(self) -> ScannerOutput:
        db = self.root / "trivy" / "db"
        db.mkdir(parents=True, exist_ok=True)
        (db / "trivy.db").write_bytes(b"bolt")
        return ScannerOutput("trivy-db", "", "", "", 0)


@pytest.fixture
def machine(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "cache"
    monkeypatch.setattr(cache, "root", lambda: root)
    monkeypatch.setattr(cache, "trivy_db", lambda: root / "trivy")
    monkeypatch.setattr(engine_host, "for_scan", lambda: _Runner(root))
    monkeypatch.setattr(name_index.build, "refresh", lambda *a, **k: {})
    monkeypatch.setenv("VALVUR_KEV_URL", "file:///nowhere")      # not http: skipped, said
    monkeypatch.setenv("VALVUR_FETCH", "never")                   # does not refuse update
    return root


def test_the_update_tool_fetches_and_says_what_it_fetched(machine):
    session = McpSession()
    try:
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "update", "arguments": {}, "_meta": {"progressToken": "u"}}})
        result = session.reply(1)["result"]
    finally:
        session.close()

    fields = result["structuredContent"]
    assert result["isError"] is False and fields["ok"] is True
    assert fields["fetched"] == ["vulnerability database", "package-name index"]
    assert (machine / "trivy" / "db" / "trivy.db").is_file()
    text = result["content"][0]["text"]
    assert "Fetched: vulnerability database, package-name index." in text
    progress = [m["params"]["message"] for m in session.seen
                if m.get("method") == "notifications/progress"]
    assert any("vulnerability database" in line for line in progress), progress


def test_the_update_tool_changes_the_machine_and_says_so():
    from valvur.mcp.tools import registry

    [tool] = [t for t in registry() if t.name == "update"]

    assert tool.read_only is False and tool.destructive is False
