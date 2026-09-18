"""Task 23.5.2 — the MCP `tools/list` reply, snapshotted.

`tools/list` is the JSON both clients see: every tool's name, description and input
schema, and the annotations that say nothing here mutates the user's code. The rc
offered a `standard` Profile in that schema, and nothing would have shown the
change from the Profile rename until an agent chose it and was refused. So the
reply is a committed file, `tests/fixtures/mcp/tools-list.json`, and a change to it
is a deliberate diff in review rather than something a client finds.

Taken through the real server over stdio, not from the registry in memory, so what
is pinned is what leaves the process.
"""

from __future__ import annotations

import io
import json
import os
import warnings
from pathlib import Path

import pytest

from valvur.mcp import protocol
from valvur.mcp.server import build
from valvur.mcp.tools import registry

SNAPSHOT = Path(__file__).parent / "fixtures" / "mcp" / "tools-list.json"
UPDATE_FLAG = "UPDATE_MCP_SNAPSHOT"


def tools_list() -> list[dict]:
    """The `tools` array exactly as `valvur-mcp` answers `tools/list`."""
    stdin = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
    stdout = io.StringIO()
    protocol.serve(build(registry()), stdin=stdin, stdout=stdout)
    [reply] = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    return reply["result"]["tools"]


def _canonical(tools: list[dict]) -> str:
    return json.dumps(tools, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def check_snapshot(path: Path, tools: list[dict], *, update: bool) -> str | None:
    """None when the snapshot matches; otherwise the reason — unless `update`, in
    which case the file is rewritten, a warning says so, and the check passes on
    the file it just wrote."""
    current = _canonical(tools)
    recorded = path.read_text(encoding="utf-8") if path.is_file() else None
    if recorded == current:
        return None
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(current, encoding="utf-8")
        warnings.warn(f"{path.name} rewritten; commit it with the change that moved it",
                      stacklevel=2)
        return None
    return (
        f"the MCP tools/list reply no longer matches {path.relative_to(path.parents[2])}. "
        "If the change is intended, regenerate the snapshot deliberately with "
        f"`{UPDATE_FLAG}=1 uv run pytest {Path(__file__).name}` and commit both — "
        "this is the JSON every client sees."
    )


def test_tools_list_matches_the_committed_snapshot():
    reason = check_snapshot(SNAPSHOT, tools_list(), update=bool(os.environ.get(UPDATE_FLAG)))

    assert reason is None, reason


def test_a_stale_snapshot_fails_with_the_regeneration_command(tmp_path):
    """The failure has to say how to move the snapshot on purpose, or the next
    person deletes the test."""
    stale = tmp_path / "tools-list.json"
    stale.write_text("[]\n", encoding="utf-8")

    reason = check_snapshot(stale, tools_list(), update=False)

    assert reason and f"{UPDATE_FLAG}=1" in reason
    assert stale.read_text() == "[]\n", "a failing check must not rewrite the file"


def test_the_snapshot_is_rewritten_only_on_request(tmp_path):
    stale = tmp_path / "tools-list.json"
    stale.write_text("[]\n", encoding="utf-8")

    with pytest.warns(UserWarning, match="rewritten"):
        reason = check_snapshot(stale, tools_list(), update=True)

    assert reason is None
    assert json.loads(stale.read_text()) == json.loads(_canonical(tools_list()))
    assert check_snapshot(stale, tools_list(), update=False) is None


# ---------------------------------------------------- what the snapshot must say

def _recorded() -> list[dict]:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def test_the_snapshot_offers_only_the_profiles_that_exist():
    """The rc's defect, pinned: `standard`, `deep` and `quick` are retired names
    (ADR-0016) that still resolve for old callers and must never be offered."""
    from valvur import profiles

    scan = next(t for t in _recorded() if t["name"] == "scan")
    offered = scan["inputSchema"]["properties"]["profile"]["enum"]

    assert offered == [profiles.OFFLINE, profiles.FULL]
    text = SNAPSHOT.read_text(encoding="utf-8")
    for retired in ("standard", "deep", "quick"):
        assert f'"{retired}"' not in text


def test_every_tool_in_the_snapshot_is_advertised_read_only():
    """ADR-0009 on the wire: a client can show the user that nothing here mutates
    their code, and the snapshot makes removing that hint a visible diff."""
    for tool in _recorded():
        assert tool["annotations"] == {"readOnlyHint": True, "destructiveHint": False}, tool["name"]


def test_the_snapshot_holds_exactly_the_tools_the_help_text_names():
    from valvur.mcp.server import USAGE as HELP

    names = {t["name"] for t in _recorded()}
    assert names == {"scan", "scan_status", "scan_cancel", "list_findings",
                     "explain_finding", "doctor"}
    for name in names:
        assert name in HELP, f"{name} is offered over MCP but --help does not name it"


def test_the_snapshot_is_the_canonical_form_so_a_diff_is_a_real_change():
    """Sorted keys, two-space indent, trailing newline: a re-serialisation with no
    change to the tools must be byte-identical, so every diff means something."""
    assert SNAPSHOT.read_text(encoding="utf-8") == _canonical(_recorded())
