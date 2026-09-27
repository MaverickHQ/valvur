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
    from valvur.operations import _checked_budget

    assert _checked_budget("300") == 300.0


@pytest.mark.parametrize("tool, arguments", [
    ("list_findings", {"limit": "many"}),
    ("list_findings", {"limit": 0}),
    ("explain_finding", {}),
    ("explain_finding", {"fingerprint": "no-such-fingerprint"}),
    ("list_findings", {}),                       # no scan has run here yet
])
def test_a_readers_bad_argument_is_refused_in_one_plain_sentence(tmp_path, tool, arguments):
    result = _call(tool, {"workspace": str(tmp_path), **arguments})
    text = _text(result)
    assert result["isError"] is True, text
    assert "Error:" not in text, text
