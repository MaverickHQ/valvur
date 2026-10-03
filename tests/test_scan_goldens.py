"""What a scan says, on both surfaces, held across R23's restructuring (D51).

The CLI's text and the MCP `scan` reply, for three workspaces through
`LocalRuntime`: one with findings, one clean, one inconclusive. R23 moves the scan
behind one service and renders both surfaces from one read model; these goldens
were recorded before it began, and the same scans must say the same things after.

Times, generation ids, dates and the temporary paths are normalised; everything
else is byte for byte. The scans run as every unit test does, on a machine that
has run `valvur update` (the conftest's index, database, KEV and EPSS).

Regenerate deliberately, never to make a red test green:

    uv run python tests/test_scan_goldens.py

which runs these tests with `SCAN_GOLDENS_OUT` naming a scratch directory, where
each writes what it said, and copies that here. No test writes the repository.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
GOLDEN = HERE / "fixtures" / "scan-goldens"
FIXTURES = HERE / "fixtures"
FAKE_TOOLS = FIXTURES / "fake-tools"

#: Each workspace, built from a fixture, and the verdict it must reach.
CASES = {
    "findings": ("broken-repo", None, "findings"),
    "clean": ("clean-repo", None, "clean"),
    # Trivy applies to the lockfile and has no database (the test removes it): it
    # fails, Gitleaks finds nothing, and nothing found beside a Scanner that did not
    # complete is not evidence (F7.19).
    "inconclusive": ("clean-repo", ("requirements.txt", "requests==2.31.0\n"),
                     "inconclusive"),
}

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SECONDS = re.compile(r"\b\d+(?:\.\d+)?s\b")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)?")
_DAYS = re.compile(r"\b\d+(?:\.\d+)? days?\b")
#: Fields whose values are times or ages, normalised wherever they appear.
_TIMED = {"elapsed_s", "duration_s", "seconds", "age_days", "overdue_days", "waited_s",
          "kev_age_days", "epss_age_days", "db_age_days"}


def normalise(text: str, root: Path) -> str:
    for spelling in sorted({str(root), str(root.resolve())}, key=len, reverse=True):
        text = text.replace(spelling, "<TMP>")
    text = _UUID.sub("<GENERATION>", text)
    text = _DATE.sub("<DATE>", text)
    text = _DAYS.sub("<N> days", text)
    return _SECONDS.sub("<T>s", text)


def _scrub(value, key: str = ""):
    if isinstance(value, dict):
        return {k: _scrub(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, key) for v in value]
    if key in _TIMED and isinstance(value, int | float) and not isinstance(value, bool):
        return "<N>"
    return value


def _workspace(root: Path, name: str) -> Path:
    fixture, extra, _ = CASES[name]
    ws = root / name
    shutil.copytree(FIXTURES / fixture, ws)
    if extra is not None:
        (ws / extra[0]).write_text(extra[1], encoding="utf-8")
    return ws


def _isolate(root: Path, name: str, patch) -> None:
    """The container runtime, the boundary the suite fakes (tasks.md §3), as
    `LocalRuntime` over the fake tools; and the inconclusive case's absent database."""
    from valvur import api, cache, engine_host
    from valvur.adapters import GitleaksAdapter, TrivyAdapter

    patch(engine_host, "for_scan", lambda: engine_host.LocalRuntime(FAKE_TOOLS))
    patch(api, "DEFAULT_ADAPTERS", [GitleaksAdapter(), TrivyAdapter()])
    if name == "inconclusive":
        (root / "no-database").mkdir(exist_ok=True)
        patch(cache, "trivy_db", lambda: root / "no-database")


def cli_text(root: Path, name: str) -> str:
    from valvur import cli

    ws = _workspace(root / "cli", name)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["scan", str(ws)])
    return normalise(f"exit {code}\n--- stdout\n{out.getvalue()}--- stderr\n{err.getvalue()}",
                     root)


def mcp_reply(root: Path, name: str) -> str:
    sys.path.insert(0, str(HERE))
    from conftest import McpSession

    from valvur.mcp import jobs

    ws = _workspace(root / "mcp", name)
    session = McpSession()
    try:
        session.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "scan", "arguments": {"workspace": str(ws)}}})
        result = session.reply(1, seconds=60)["result"]
    finally:
        session.close()
        jobs.reset()
    text = result["content"][0]["text"]
    fields = _scrub(result["structuredContent"])
    return normalise(f"--- text\n{text}\n--- structuredContent\n"
                     f"{json.dumps(fields, indent=2, sort_keys=True)}\n", root)


#: Set by `_write`: a scratch directory each test writes what it said into.
OUT_ENV = "SCAN_GOLDENS_OUT"


def _compare(said: str, golden: str) -> None:
    import os

    if out := os.environ.get(OUT_ENV):
        (Path(out) / golden).write_text(said, encoding="utf-8")
        return
    assert said == (GOLDEN / golden).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", list(CASES))
def test_the_cli_says_what_it_said(tmp_path, monkeypatch, name):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    _isolate(tmp_path, name, monkeypatch.setattr)
    _compare(cli_text(tmp_path, name), f"{name}.cli.txt")


@pytest.mark.parametrize("name", list(CASES))
def test_the_mcp_reply_says_what_it_said(tmp_path, monkeypatch, name):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    _isolate(tmp_path, name, monkeypatch.setattr)
    _compare(mcp_reply(tmp_path, name), f"{name}.mcp.txt")


@pytest.mark.parametrize("name", list(CASES))
def test_each_golden_holds_its_verdict(name):
    """A golden that recorded the wrong verdict would hold the wrong thing."""
    verdict = CASES[name][2]
    assert f"\n{verdict}: " in (GOLDEN / f"{name}.cli.txt").read_text(encoding="utf-8")
    assert f'"verdict": "{verdict}"' in (GOLDEN / f"{name}.mcp.txt").read_text(
        encoding="utf-8")


def _write() -> int:                                   # pragma: no cover
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        os.environ[OUT_ENV] = scratch
        code = pytest.main(["-q", "-p", "no:cacheprovider", __file__, "-k", "says_what"])
        if code != 0:
            return int(code)
        GOLDEN.mkdir(exist_ok=True)
        for said in sorted(Path(scratch).iterdir()):
            shutil.copyfile(said, GOLDEN / said.name)
            print(f"wrote {GOLDEN / said.name}")
    return 0


if __name__ == "__main__":                             # pragma: no cover
    sys.exit(_write())
