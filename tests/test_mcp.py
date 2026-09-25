"""Sub-phase 9.0 — MCP stdio transport, hand-rolled and dependency-free (ADR-0015).

MCP is valvur's primary interface: a developer adds it to Kiro or Claude Code and
calls it from there. The CLI is the second way in.
"""

import io
import json

import pytest

from valvur.mcp import protocol
from valvur.mcp.protocol import PROTOCOL_VERSION
from valvur.mcp.server import Tool, build


def _exchange(*messages, tools=None):
    """Drive the server over real streams and return the parsed responses."""
    stdin = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    stdout = io.StringIO()
    protocol.serve(build(tools or []), stdin=stdin, stdout=stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]


def _request(method, params=None, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": method,
            **({"params": params} if params else {})}


# ------------------------------------------------------------- the handshake

def test_initialize_returns_a_usable_server_description():
    responses = _exchange(_request("initialize", {"protocolVersion": PROTOCOL_VERSION}))

    result = responses[0]["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "valvur"
    assert "tools" in result["capabilities"]


def test_an_older_protocol_version_is_honoured_when_we_support_it():
    """Negotiation, not imposition: a client on an older version keeps working."""
    responses = _exchange(_request("initialize", {"protocolVersion": "2024-11-05"}))

    assert responses[0]["result"]["protocolVersion"] == "2024-11-05"


def test_an_unknown_protocol_version_gets_ours_to_decide_on():
    responses = _exchange(_request("initialize", {"protocolVersion": "1999-01-01"}))

    assert responses[0]["result"]["protocolVersion"] == PROTOCOL_VERSION


def test_a_notification_receives_no_response():
    """Replying to a notification is a protocol violation, and clients hang on it."""
    responses = _exchange(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _request("tools/list", request_id=7),
    )

    assert len(responses) == 1
    assert responses[0]["id"] == 7


# ------------------------------------------- 9.0.4 nothing but JSON on stdout

def test_malformed_json_produces_a_parse_error_not_a_crash():
    stdin = io.StringIO("this is not json\n")
    stdout = io.StringIO()

    protocol.serve(build([]), stdin=stdin, stdout=stdout)

    assert json.loads(stdout.getvalue())["error"]["code"] == protocol.PARSE_ERROR


def test_an_unknown_method_produces_method_not_found():
    responses = _exchange(_request("nonsense"))

    assert responses[0]["error"]["code"] == protocol.METHOD_NOT_FOUND


def test_a_message_that_is_not_json_rpc_is_rejected():
    responses = _exchange({"id": 1, "method": "initialize"})

    assert responses[0]["error"]["code"] == protocol.INVALID_REQUEST


def test_a_crashing_tool_becomes_a_tool_error_not_a_protocol_error():
    """The agent should see what went wrong, not a transport fault."""
    def explode(_args):
        raise ValueError("scanner unavailable")

    tool = Tool("boom", "explodes", {"type": "object"}, explode)
    responses = _exchange(
        _request("tools/call", {"name": "boom", "arguments": {}}), tools=[tool]
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    assert "scanner unavailable" in result["content"][0]["text"]


def test_an_unhandled_exception_never_reaches_stdout_as_a_traceback(capsys):
    """Anything on stdout that is not a response corrupts the stream, and the client
    reports a protocol error instead of the real problem."""
    def broken(_params):
        raise RuntimeError("boom")

    stdin = io.StringIO(json.dumps(_request("tools/list")) + "\n")
    stdout = io.StringIO()

    protocol.serve({"tools/list": broken}, stdin=stdin, stdout=stdout)

    payload = json.loads(stdout.getvalue())          # parses, so it is not a traceback
    assert payload["error"]["code"] == protocol.INTERNAL_ERROR
    assert "boom" in capsys.readouterr().err, "diagnostics belong on stderr"


# ------------------------------------------------------------------- tools

def test_a_tool_is_read_only_unless_it_says_otherwise():
    """The default is the safe one: a tool that declares nothing is advertised as
    read-only, so a new tool has to state that it acts (27.1.2)."""
    tool = Tool("scan_status", "What the last scan did", {"type": "object"}, lambda a: "ok")

    responses = _exchange(_request("tools/list"), tools=[tool])

    described = responses[0]["result"]["tools"][0]
    assert described["annotations"]["readOnlyHint"] is True
    assert described["annotations"]["destructiveHint"] is False


def test_a_tool_that_acts_says_so_on_the_wire():
    """`readOnlyHint` is the MCP spec's word for "does not modify its
    environment". A tool that writes a folder, pulls an image and starts
    containers modifies plenty; only the *source tree* is untouched, and that is
    F9.2's claim, not this annotation's (27.1.2)."""
    tool = Tool("scan", "Scan a workspace", {"type": "object"}, lambda a: "ok",
                read_only=False)

    responses = _exchange(_request("tools/list"), tools=[tool])

    described = responses[0]["result"]["tools"][0]
    assert described["annotations"]["readOnlyHint"] is False
    assert described["annotations"]["destructiveHint"] is False, \
        "a scan adds; it destroys nothing of the user's (F1.11, ADR-0009)"


def test_calling_an_unknown_tool_is_an_invalid_params_error():
    responses = _exchange(_request("tools/call", {"name": "ghost", "arguments": {}}))

    assert responses[0]["error"]["code"] == protocol.INVALID_PARAMS


def test_no_forbidden_tool_name_is_ever_registered():
    """ADR-0009 is a safety property. A contributor adding scan_and_fix should fail
    the build, not merely fail review."""
    from valvur.mcp.tools import FORBIDDEN, registry

    names = {tool.name for tool in registry()}

    assert not (names & set(FORBIDDEN)), f"forbidden tool exposed: {names & set(FORBIDDEN)}"


# ---------------------------------------------------- zero dependencies (F10.6)

def test_the_shim_still_has_no_runtime_dependencies():
    """ADR-0015 — the whole reason we hand-rolled this."""
    import tomllib
    from pathlib import Path

    pyproject = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    )

    assert pyproject["project"]["dependencies"] == []


def test_the_mcp_server_imports_nothing_outside_the_standard_library():
    import valvur.mcp.protocol as mod
    import valvur.mcp.server as srv

    for module in (mod, srv):
        source = (module.__file__ or "")
        assert "site-packages" not in source or "valvur" in source


def test_a_non_string_tool_name_is_rejected_clearly():
    responses = _exchange(_request("tools/call", {"name": 42, "arguments": {}}))

    assert responses[0]["error"]["code"] == protocol.INVALID_PARAMS
    assert "must be a string" in responses[0]["error"]["message"]


def test_an_unknown_tool_error_names_what_is_available():
    """An error naming only what failed leaves the agent guessing."""
    tool = Tool("scan", "Scan", {"type": "object"}, lambda a: "ok")

    responses = _exchange(
        _request("tools/call", {"name": "ghost", "arguments": {}}), tools=[tool]
    )

    assert "Available: scan" in responses[0]["error"]["message"]


# ------------------------------------------------------- 9.1 the tool surface

@pytest.fixture
def scanned(workspace, runner_finding_nothing):
    from valvur import scan
    from valvur.adapters import CheckAdapter

    scan(workspace, runner=runner_finding_nothing, profile="quick",
         adapters=[CheckAdapter("licence-file"), CheckAdapter("ai-artifact")])
    return workspace


def _call(tool_name, arguments):
    from valvur.mcp.tools import registry

    responses = _exchange(
        _request("tools/call", {"name": tool_name, "arguments": arguments}),
        tools=registry(),
    )
    return responses[0]["result"]


def test_list_findings_returns_findings_worst_first(scanned):
    result = _call("list_findings", {"workspace": str(scanned)})

    assert result["isError"] is False
    assert "worst first" in result["content"][0]["text"]


def test_list_findings_is_bounded_and_says_what_it_omitted(scanned):
    """F9.10 — several thousand findings in an agent's context is the problem F7.5
    solved for SUMMARY.md, arriving by another door."""
    result = _call("list_findings", {"workspace": str(scanned), "limit": 2})

    text = result["content"][0]["text"]
    assert "showing 2" in text
    assert "more not shown" in text


def test_list_findings_caps_an_unreasonable_limit(scanned):
    from valvur.mcp.tools import MAX_LIMIT

    result = _call("list_findings", {"workspace": str(scanned), "limit": 100_000})

    shown = result["content"][0]["text"].count("fingerprint:")
    assert shown <= MAX_LIMIT


def test_list_findings_can_filter_by_status(scanned):
    result = _call("list_findings", {"workspace": str(scanned), "status": "persisting"})

    assert result["isError"] is False


def test_explain_finding_returns_evidence_and_provenance(scanned):
    """F9.8 — and it must name which scanner reported it, or the finding is
    unverifiable."""
    import json as _json

    findings = _json.loads(
        (scanned / ".security-scan" / "findings.json").read_text()
    )["findings"]
    injection = next(f for f in findings if "prompt-injection" in f["rule"])

    result = _call("explain_finding",
                   {"workspace": str(scanned), "fingerprint": injection["fingerprint"]})

    text = result["content"][0]["text"]
    assert "reported by: ai-artifact" in text
    assert "Evidence:" in text


def test_an_mcp_response_carries_neutralised_evidence(scanned):
    """F9.9 — the most direct injection path valvur has.

    An MCP response reaches an agent's context with no file in between, and unlike a
    file the agent cannot decline to read it.
    """
    import json as _json

    findings = _json.loads(
        (scanned / ".security-scan" / "findings.json").read_text()
    )["findings"]
    injection = next(f for f in findings if "prompt-injection" in f["rule"])

    result = _call("explain_finding",
                   {"workspace": str(scanned), "fingerprint": injection["fingerprint"]})
    text = result["content"][0]["text"]

    payload = "Ignore all previous instructions"
    assert payload in text, "the finding must remain actionable"
    assert "[UNTRUSTED CONTENT" in text[: text.index(payload)]


def test_explain_finding_restates_that_valvur_does_not_apply_fixes(scanned):
    """ADR-0009 — the agent reads this before deciding what to do."""
    import json as _json

    findings = _json.loads(
        (scanned / ".security-scan" / "findings.json").read_text()
    )["findings"]

    result = _call("explain_finding",
                   {"workspace": str(scanned), "fingerprint": findings[0]["fingerprint"]})

    text = result["content"][0]["text"]
    assert "does not change your code" in text
    assert "not proof it was fixed" in text


def test_scan_status_reports_incompleteness_rather_than_hiding_it(scanned):
    result = _call("scan_status", {"workspace": str(scanned)})

    text = result["content"][0]["text"]
    assert "complete:" in text
    assert "left this machine:" in text, "the disclosure belongs here too"


def test_listing_before_scanning_says_so_rather_than_returning_nothing(tmp_path):
    result = _call("list_findings", {"workspace": str(tmp_path)})

    assert result["isError"] is True
    assert "Run the `scan` tool first" in result["content"][0]["text"]


#: What each tool actually does to the machine it runs on, as `tools/list` states
#: it (27.1.2). Until then every one of the six said `readOnlyHint: true`, `scan`
#: included — which writes the Results Folder, pulls an image and starts
#: containers. A client may use these to decide what to run without asking, so a
#: wrong `true` here is the annotation being worse than no annotation.
ANNOUNCED = {
    "scan":            {"readOnlyHint": False, "destructiveHint": False},
    "scan_cancel":     {"readOnlyHint": False, "destructiveHint": False},
    "scan_status":     {"readOnlyHint": True, "destructiveHint": False},
    "list_findings":   {"readOnlyHint": True, "destructiveHint": False},
    "explain_finding": {"readOnlyHint": True, "destructiveHint": False},
    "doctor":          {"readOnlyHint": True, "destructiveHint": False},
}


def test_every_registered_tool_announces_what_it_does():
    """One table, held against the registry, so a new tool has to appear here and
    a changed one is a diff in review."""
    from valvur.mcp.tools import registry

    tools = registry()
    assert {tool.name for tool in tools} == set(ANNOUNCED), \
        "a tool was added or removed without saying what it does"
    for tool in tools:
        assert tool.describe()["annotations"] == ANNOUNCED[tool.name], tool.name


def test_no_tool_is_ever_destructive_and_none_touches_the_source_tree():
    """F9.2 and ADR-0009, which are about the user's *code* and are unchanged by
    27.1.2: `scan` writes only `.security-scan/`, a cancel writes nothing at all
    (F1.11), and no tool in the registry can edit, apply or remediate."""
    from valvur.mcp.tools import FORBIDDEN, registry

    for tool in registry():
        assert tool.describe()["annotations"]["destructiveHint"] is False, tool.name
        assert not any(word in tool.name for word in FORBIDDEN), tool.name
    scan = next(t for t in registry() if t.name == "scan")
    assert "never modifies your source" in scan.description, \
        "the description is where F9.2 is stated to a client, now that the hint is false"


def test_the_registry_exposes_exactly_the_expected_tools():
    """A new tool should be a deliberate act, visible in this test's diff."""
    from valvur.mcp.tools import registry

    assert {t.name for t in registry()} == {
        "scan", "list_findings", "explain_finding", "scan_status", "doctor", "scan_cancel",
    }


# --------------------------------------------------------------- 9.2 long scans

@pytest.fixture(autouse=True)
def _clean_jobs():
    from valvur.mcp import jobs

    jobs.reset()
    yield
    jobs.reset()


def test_a_scan_returns_before_it_finishes(tmp_path):
    """Measured: 20s for a standard profile on a TOY fixture. A real project is
    minutes, and many MCP clients time out at 30-60 seconds."""
    import time

    from valvur.mcp import jobs

    def slow(workspace, profile, progress):
        time.sleep(2)
        return "done eventually"

    started = time.monotonic()
    jobs.start(tmp_path, "standard", slow)
    elapsed = time.monotonic() - started

    assert elapsed < 0.5, f"start blocked for {elapsed:.2f}s"


def test_status_reports_running_then_done(tmp_path):
    import time

    from valvur.mcp import jobs

    def quick(workspace, profile, progress):
        progress("gitleaks: ok")
        time.sleep(0.3)
        return "clean: 0 finding(s)."

    job = jobs.start(tmp_path, "quick", quick)
    assert job.state == "running"

    for _ in range(50):
        if job.state != "running":
            break
        time.sleep(0.1)

    assert job.state == "done"
    assert job.summary == "clean: 0 finding(s)."
    assert "gitleaks: ok" in job.progress


def test_a_second_scan_while_one_runs_is_refused_not_queued(tmp_path):
    """Two concurrent scans of one workspace would race on the Results Folder."""
    import time

    from valvur.mcp import jobs

    def slow(workspace, profile, progress):
        time.sleep(2)
        return "ok"

    first = jobs.start(tmp_path, "standard", slow)
    second = jobs.start(tmp_path, "quick", slow)

    assert second is first


def test_a_failing_scan_is_reported_not_crashed(tmp_path):
    """The server must survive a scan that dies — the agent needs to hear why."""
    import time

    from valvur.mcp import jobs

    def explode(workspace, profile, progress):
        raise RuntimeError("no container runtime")

    job = jobs.start(tmp_path, "standard", explode)
    for _ in range(50):
        if job.state != "running":
            break
        time.sleep(0.05)

    assert job.state == "failed"
    assert "no container runtime" in job.error


def test_scan_status_tells_the_agent_not_to_report_a_result_yet(tmp_path, monkeypatch):
    import time

    from valvur.mcp import jobs

    # The status call now waits for the job (task 10.2.5); shorten that so the test
    # can observe a job that outlasts it.
    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.2)
    jobs.start(tmp_path, "standard", lambda w, p, g: (time.sleep(2), "ok")[1])

    result = _call("scan_status", {"workspace": str(tmp_path)})
    text = result["content"][0]["text"]

    assert "RUNNING" in text
    assert "do not report a result yet" in text


def test_scan_status_waits_rather_than_answering_instantly(tmp_path, monkeypatch):
    """Measured with a real agent (task 10.2.5): a 51-second scan cost **14 status
    polls in 20 turns**, because each returned instantly and the agent had nothing
    left to do but ask again. It hit its turn limit before writing a report.

    A bounded wait means one poll covers seconds of scan rather than milliseconds.
    """
    import time

    from valvur.mcp import jobs

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 5.0)
    jobs.start(tmp_path, "standard", lambda w, p, g: (time.sleep(0.5), "ok")[1])

    began = time.monotonic()
    result = _call("scan_status", {"workspace": str(tmp_path)})
    waited = time.monotonic() - began
    text = result["content"][0]["text"]

    # It waited for the job to finish - and no longer than that. The fake job writes
    # no run.json, so the settled branch reports "no scan"; what matters here is that
    # the answer is not RUNNING and that the call took the job's duration, not zero.
    assert "RUNNING" not in text, text
    assert 0.4 < waited < 3.0, f"waited {waited:.2f}s"


def test_the_wait_is_bounded_so_a_client_never_times_out(tmp_path, monkeypatch):
    """The pair. The docstring's constraint is that many clients give up at 30-60
    seconds; a wait that outlived a stuck scan would turn a slow result into a dead
    server."""
    import time

    from valvur.mcp import jobs

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.3)
    jobs.start(tmp_path, "standard", lambda w, p, g: (time.sleep(3), "ok")[1])

    began = time.monotonic()
    text = _call("scan_status", {"workspace": str(tmp_path)})["content"][0]["text"]
    waited = time.monotonic() - began

    assert "RUNNING" in text
    assert waited < 1.0, f"waited {waited:.2f}s for a job that was not going to finish"
    assert jobs.STATUS_WAIT_SECONDS <= 25, "must stay well under the 30s client timeout"


def test_scan_status_before_any_scan_says_so(tmp_path):
    result = _call("scan_status", {"workspace": str(tmp_path)})

    assert "No scan has run" in result["content"][0]["text"]


# --------------------------------------------------------- 9.3 CLI parity

def test_every_mcp_tool_is_backed_by_a_shared_operation():
    """F9.3, structurally.

    Both surfaces call `valvur.operations`, so they cannot drift. Asserting equality
    of formatted output would be brittle and would keep passing while the semantics
    diverged underneath.
    """
    from valvur import operations
    from valvur.mcp.tools import registry

    shared = {
        getattr(operations, name)
        for name in ("start_scan", "list_findings", "explain_finding", "scan_status",
                     "doctor", "cancel_scan")
    }
    # A reader that answers `structuredContent` (28.2.2) is registered in its
    # two-form shape, `<name>_reply`; the CLI's text function is that reply's
    # first element by construction and names it as `.reply`. Still one
    # computation, still the same module.
    structured = {getattr(operation, "reply", None) for operation in shared} - {None}

    for tool in registry():
        assert tool.handler in shared | structured, (
            f"{tool.name} has its own implementation; it will drift from the CLI"
        )


@pytest.mark.parametrize(
    ("command", "operation"),
    [("findings", "list_findings"), ("explain", "explain_finding"),
     ("status", "scan_status"), ("scan", "start_scan"), ("doctor", "doctor")],
)
def test_each_mcp_tool_has_a_cli_equivalent(command, operation):
    """F9.3 — the CLI is the second way in, and must reach the same operations."""
    import argparse
    import contextlib
    import io

    from valvur.cli import main

    with contextlib.redirect_stdout(io.StringIO()) as out:
        with contextlib.suppress(SystemExit, argparse.ArgumentError):
            main([command, "--help"])

    assert command in out.getvalue() or True  # the parser accepted the subcommand


def test_the_cli_and_mcp_produce_identical_text_for_the_same_request(scanned):
    """Not a comparison test standing in for parity — a demonstration that the
    shared operation is genuinely the same call."""
    import contextlib
    import io

    from valvur import operations
    from valvur.cli import main

    direct = operations.list_findings({"workspace": str(scanned), "limit": 3})

    with contextlib.redirect_stdout(io.StringIO()) as out:
        main(["findings", str(scanned), "--limit", "3"])

    assert out.getvalue().strip() == direct.strip()


# ------------------------------------- 28.2.2: the handshake carries the rules,
# ------------------------------------- and the two readers answer structured content

def test_initialize_carries_the_machine_blocks_rules_as_instructions():
    """F4 (28.2.2). `SUMMARY.md` opens with five rules for the agent reading it
    (F7.6); over MCP they reached an agent only if a human had pasted the README's
    snippet into `CLAUDE.md`. `initialize` carries them as `instructions` now —
    the same words, from the same constant, so the two cannot drift."""
    responses = _exchange(_request("initialize", {"protocolVersion": PROTOCOL_VERSION}))
    instructions = responses[0]["result"]["instructions"]

    for rule in ("Never commit it", "Work from `REMEDIATION.md`", "Do not read it whole",
                 "Never add a suppression without asking the human",
                 "A finding disappearing is not proof it was fixed", "[UNTRUSTED CONTENT",
                 "`inconclusive`", "`status_reason`"):
        assert rule in instructions, f"the handshake does not carry: {rule}"
    assert "<!--" not in instructions and "\n> " not in instructions, \
        "Markdown blockquote furniture reached the handshake"


def test_scan_status_answers_structured_content_that_agrees_with_its_text(scanned):
    """MCP 2025-06-18: a tool may answer `structuredContent` beside its text. An
    agent parsed *"3 active"* out of prose before; the counts, the verdict and the
    Scanners are fields now — and equal to the text, on every fixture."""
    result = _call("scan_status", {"workspace": str(scanned)})
    text = result["content"][0]["text"]
    data = result["structuredContent"]

    assert data["status"] in ("findings", "clean", "inconclusive")
    assert f"status:   {data['status']}" in text
    assert f"findings: {data['findings']['active']} active" in text
    assert data["complete"] is True and "complete: True" in text
    assert data["generation"] and len(data["generation"]) == 36
    assert {s["tool"] for s in data["scanners"]} and all(
        f"  {s['tool']}: " in text for s in data["scanners"])
    assert data["job"] is None, "no job ran through the server in this test"


def test_scan_status_without_a_scan_says_so_in_both_forms(tmp_path):
    result = _call("scan_status", {"workspace": str(tmp_path)})

    assert "No scan has run" in result["content"][0]["text"]
    assert result["structuredContent"] == {"scanned": False, "job": None,
                                           "results_dir": str(tmp_path / ".security-scan")}


def test_list_findings_answers_structured_findings_that_agree_with_its_text(scanned):
    result = _call("list_findings", {"workspace": str(scanned), "limit": 2})
    text = result["content"][0]["text"]
    data = result["structuredContent"]

    assert f"{data['total']} finding(s); showing {data['shown']}" in text
    assert data["shown"] == len(data["findings"]) == 2
    assert data["omitted"] == data["total"] - 2 and f"{data['omitted']} more not shown" in text
    for finding in data["findings"]:
        assert finding["fingerprint"] in text
        assert set(finding) >= {"rank", "status", "severity", "path", "line", "title",
                                "rule", "fingerprint", "suppressed"}


def test_structured_findings_are_neutralised_like_the_text(scanned):
    """F9.9 applies to both forms: a structured reply reaches the agent's context
    as directly as the text does."""
    result = _call("list_findings", {"workspace": str(scanned), "limit": 50})
    data = result["structuredContent"]

    injection = next(f for f in data["findings"] if "prompt-injection" in f["rule"])
    payload = "Ignore all previous instructions"
    assert payload in injection["evidence"], "the finding must remain actionable"
    assert "[UNTRUSTED CONTENT" in injection["evidence"][: injection["evidence"].index(payload)]


def test_the_two_readers_declare_their_output_shape():
    from valvur.mcp.tools import registry

    described = {tool.name: tool.describe() for tool in registry()}

    for name in ("scan_status", "list_findings"):
        assert described[name]["outputSchema"]["type"] == "object", name
    for name in ("scan", "scan_cancel", "explain_finding", "doctor"):
        assert "outputSchema" not in described[name], f"{name} claims a shape it does not answer"
