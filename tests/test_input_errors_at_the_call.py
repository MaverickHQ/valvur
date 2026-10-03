"""R1.5: input errors fail at the call, and `doctor` is suggested only when it can
help (F9.10; the second gate's C3 and C4).

`budget_s: -5` answered *Started…* and then *FAILED after 0s — ValueError: …*;
`budget_s: "ten"` and `profile: "bogus"` were refused in Python's words; and
`doctor_may_help` was true on every state, a Busy refusal included. Driven through
the real server over streams, as a client drives it.
"""

from __future__ import annotations

import io
import json

import pytest

from valvur import api
from valvur.mcp import jobs, protocol
from valvur.mcp.server import build
from valvur.mcp.tools import registry


def _call(tool_name: str, arguments: dict) -> dict:
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": tool_name, "arguments": arguments}}
    stdout = io.StringIO()
    protocol.serve(build(registry()), stdin=io.StringIO(json.dumps(message) + "\n"),
                   stdout=stdout)
    return json.loads(stdout.getvalue().splitlines()[0])["result"]


def _text(result: dict) -> str:
    return result["content"][0]["text"]


@pytest.mark.parametrize("arguments", [
    {"budget_s": -5}, {"budget_s": "ten"}, {"profile": "bogus"},
])
def test_a_bad_scan_argument_is_refused_at_the_call_in_one_plain_sentence(tmp_path, arguments):
    jobs.reset()
    result = _call("scan", {"workspace": str(tmp_path), **arguments})
    text = _text(result)
    assert result["isError"] is True, text
    assert "Error:" not in text and "Started" not in text, text
    assert text.count(".") <= 2 and "\n" not in text.strip(), text
    assert jobs.current(tmp_path.resolve()) is None, "a refused call started a job"


def test_a_number_sent_as_a_string_is_still_a_number():
    from valvur.operations import checked_budget

    assert checked_budget("300") == 300.0


@pytest.mark.parametrize("tool, arguments", [
    ("findings", {"limit": "many"}),
    ("findings", {"limit": 0}),
    ("findings", {"fingerprint": "no-such-fingerprint"}),
    ("findings", {}),                            # no scan has run here yet
])
def test_a_readers_bad_argument_is_refused_in_one_plain_sentence(tmp_path, tool, arguments):
    result = _call(tool, {"workspace": str(tmp_path), **arguments})
    text = _text(result)
    assert result["isError"] is True, text
    assert "Error:" not in text, text


# ------------------------------------------------ doctor, only when it can help


def _settled(tmp_path, work):
    from valvur.mcp.handlers import scan_status_reply

    jobs.reset()
    job = jobs.start(tmp_path, "offline", work)
    assert job.wait(5)
    text, fields = scan_status_reply({"workspace": str(tmp_path)})
    jobs.reset()
    return text, fields


def test_a_running_scan_does_not_suggest_doctor(tmp_path, monkeypatch):
    import threading

    from valvur.mcp.handlers import scan_status_reply

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.05)   # answer while it runs
    jobs.reset()
    release = threading.Event()
    jobs.start(tmp_path, "offline", lambda ws, profile, progress: release.wait(5) and "")
    _, fields = scan_status_reply({"workspace": str(tmp_path)})
    release.set()
    # Schema 2 (R6.2): doctor is advised by `error.kind`, and a running scan has none.
    assert fields["state"] == "running" and fields["error"] is None
    jobs.reset()


def test_a_finished_scan_does_not_suggest_doctor(tmp_path, runner_finding_nothing):
    def work(ws, profile, progress):
        api.scan(ws, runner=runner_finding_nothing)
        return "clean: 0 finding(s)."

    _, job = _settled(tmp_path, work)
    assert job["state"] == "done" and job["error"] is None


def test_a_missing_runtime_suggests_doctor(tmp_path):
    from valvur.runner import NoContainerRuntime

    def work(ws, profile, progress):
        raise NoContainerRuntime("No container runtime found.")

    text, job = _settled(tmp_path, work)
    assert job["error"]["kind"] == "precondition"
    assert "doctor" in text


def test_an_unexpected_failure_does_not_suggest_doctor(tmp_path):
    def work(ws, profile, progress):
        raise KeyError("a bug, not a missing precondition")

    text, job = _settled(tmp_path, work)
    assert job["error"]["kind"] == "failed"
    assert "doctor" not in text


def test_a_busy_workspace_says_to_wait_and_does_not_suggest_doctor(tmp_path):
    from valvur.locking import Busy

    def work(ws, profile, progress):
        raise Busy("a scan is already running in this workspace")

    text, job = _settled(tmp_path, work)
    assert job["error"]["kind"] == "busy"
    assert "doctor" not in text
    assert any("wait" in move for move in job["next"]), job["next"]
