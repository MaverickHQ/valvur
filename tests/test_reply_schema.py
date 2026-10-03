"""R6.2: reply schema 2 (D7, ADR-0024; F9.8 to F9.10).

Structured first: Claude Code hands the model only `structuredContent` when a reply
has both forms (29.2.4), and the status reply's fields and text had come to say
different things (C4, C7). Every state is schema 2, the text is rendered from the
fields alone, a state without a result says why in `error.kind` and what to do in
`next`, and a finished scan carries its summary as `report`.
"""

from __future__ import annotations

import copy
import threading
import time
from pathlib import Path

import pytest

from valvur import reply
from valvur.mcp import jobs
from valvur.mcp.handlers import scan_status_reply
from valvur.runner import NoContainerRuntime

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


@pytest.fixture(autouse=True)
def _quick(monkeypatch):
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
    yield
    jobs.reset()


def _every_state(tmp_path, monkeypatch) -> dict[str, tuple[str, dict]]:
    from valvur import api, cache
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("print('hi')\n")
    seen = {"none": scan_status_reply({"workspace": str(ws)})}
    release = threading.Event()

    def running(workspace, profile, progress):
        progress("fleet: 1 Scanners, 1 at a time")
        progress("gitleaks: started")
        release.wait(5)
        return ""

    def failed(workspace, profile, progress):
        raise NoContainerRuntime("No container runtime found.")

    job = jobs.start(ws, "offline", running)
    time.sleep(0.15)
    seen["running"] = scan_status_reply({"workspace": str(ws)})
    release.set()
    assert job.wait(2)
    jobs.reset()
    release.clear()

    assert jobs.start(ws, "offline", failed).wait(2)
    seen["failed"] = scan_status_reply({"workspace": str(ws)})
    jobs.reset()

    def stopped(workspace, profile, progress):
        release.wait(5)
        raise RuntimeError("stopped")      # what a killed fleet raises

    job = jobs.start(ws, "offline", stopped)
    time.sleep(0.1)
    jobs.cancel(ws)
    seen["cancelling"] = scan_status_reply({"workspace": str(ws)})
    release.set()
    assert job.wait(2)
    seen["cancelled"] = scan_status_reply({"workspace": str(ws)})
    jobs.reset()

    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()])
    seen["done"] = scan_status_reply({"workspace": str(ws)})
    return seen


def test_every_state_is_schema_2_with_its_text_rendered_from_its_fields(tmp_path, monkeypatch):
    seen = _every_state(tmp_path, monkeypatch)
    kinds = {"none": "no-scan", "running": None, "failed": "precondition",
             "cancelling": "cancelled", "cancelled": "cancelled", "done": None}

    for state, (text, fields) in seen.items():
        assert fields["schema"] == 2 and fields["state"] == state, state
        assert reply.text(copy.deepcopy(fields)) == text, f"{state}: text is not the fields'"
        assert (fields["error"] or {}).get("kind") == kinds[state], state
        if state != "done":
            assert fields["next"], f"{state} says nothing about what to do"


def test_a_finished_scan_carries_its_verdict_counts_and_summary(tmp_path, monkeypatch):
    _, done = _every_state(tmp_path, monkeypatch)["done"]
    summary = (tmp_path / "ws" / ".security-scan" / "SUMMARY.md").read_text()

    assert done["verdict"] in ("findings", "clean", "inconclusive")
    assert done["reason"] and done["complete"] is True and done["generation"]
    assert set(done["counts"]) >= {"active", "suppressed", "not_covered", "fixed"}
    assert done["scope"]["files"] == 1
    assert done["report"] == summary
    assert all(set(e) == {"tool", "kind", "reason"} for e in done["not_run"])


# ------------------------------------------- behaviour 2: under Claude Code's limit

#: Claude Code's limit on a tool's output (MAX_MCP_OUTPUT_TOKENS), and a
#: conservative three characters a token: paths and JSON tokenise worse than prose.
TOKEN_LIMIT, CHARS_PER_TOKEN = 25_000, 3


def test_a_reply_stays_under_the_token_limit_whatever_the_repository_holds(tmp_path):
    """Measured on the acceptance set, the largest reply is repository 2's, about
    3,400 tokens. The bound must hold for what no fixture holds: thousands of
    ignored directories, and a summary at its line cap with long lines."""
    import json

    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "run.json").write_text(json.dumps({
        "status": "findings", "status_reason": "1 active finding(s)", "complete": True,
        "generation": "g", "profile": "offline",
        "findings": {"active": 1, "suppressed": 0, "not_covered": 0, "total": 1},
        "not_read": [{"path": f"vendor/pkg{i:04}/" + "d" * 80, "reason": "ignored by git"}
                     for i in range(3_000)],
        "scanners": [{"tool": f"tool{i}", "ok": True, "duration_s": 1.0} for i in range(12)],
    }))
    (results / "SUMMARY.md").write_text("\n".join("x" * 400 for _ in range(200)) + "\n")

    fields = reply.fields(tmp_path)
    size = len(json.dumps(fields)) + len(reply.text(fields))

    assert size / CHARS_PER_TOKEN < TOKEN_LIMIT, f"{size:,} characters"
    assert fields["counts"]["active"] == 1 and "SUMMARY.md" in fields["report"]
