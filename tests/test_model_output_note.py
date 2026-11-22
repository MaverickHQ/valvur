"""R49.7: valvur says where it stops following a model's output (D82j, Requirement 6).

The four `valvur.llm.*` rules follow a model's output to a sink inside one function.
Opengrep's `--taint-intrafile` was measured again on the version the image ships: it caught
every generated case and none of the five published advisories, so it is not adopted. A
project that calls a model and has a sink, with no flow reported between them, is told so,
under *What valvur could not read*. It is a note and not a doubt: a project that calls a
model can still be `clean`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from valvur import api, verdict
from valvur import fingerprint as _fp
from valvur.engine_host import LocalRuntime
from valvur.findings import Finding
from valvur.invocation import Invocation

REPO = Path(__file__).resolve().parents[1]
FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"
NOTE = ("This project calls a model in at least 2 file(s). valvur follows a model's output "
        "to a sink inside one function, and not through a call to another")


def _finding(rule: str, path: str, **more) -> Finding:
    return Finding(rule=rule, path=path, line=3, title=f"{rule} found something",
                   fingerprint=_fp.derive(rule, path), sources=("opengrep",),
                   severity=more.pop("severity", "low"), **more)


CALLS = [_finding("valvur.llm.model-call", "app/agent.py"),
         _finding("valvur.llm.model-call", "app/tools/planner.py")]
SINK = _finding("valvur.python.dangerous-exec", "app/tools/run.py", inventory=True)
FLOW = _finding("valvur.llm.output-to-shell", "app/agent.py", severity="high")


class _Opengrep:
    artifact = None
    kind = "scanner"
    version = "1"
    name = "opengrep"

    def __init__(self, found: list[Finding]):
        self.found = found

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool=self.name, version="1", report="opengrep.json", timeout=60,
                          argv=("fake-report", "0", "[]", "/results/opengrep.json"))

    def parse(self, output):
        return list(self.found)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _scan(workspace: Path, *found: Finding):
    for finding in found:
        (workspace / finding.path).parent.mkdir(parents=True, exist_ok=True)
        (workspace / finding.path).write_text("x = 1\n")
    run = api.scan(workspace, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Opengrep(list(found))])
    records = json.loads((workspace / RESULTS / "findings.json").read_text())["findings"]
    return run, records, " ".join((workspace / RESULTS / "SUMMARY.md").read_text().split())


def test_a_model_call_and_a_sink_with_no_flow_between_them_has_the_note(workspace):
    run, records, summary = _scan(workspace, *CALLS, SINK)

    assert "**What valvur could not read:**" in summary and NOTE in summary
    notes = [r for r in records if r["rule"] == verdict.MODEL_OUTPUT_RULE]
    assert [(n["title"], n["path"]) for n in notes] == [(NOTE, "app/agent.py")]
    assert "app/tools/planner.py" in notes[0]["evidence"]
    # Its Status is what it was without the note: the sink alone reads clean.
    assert run.status == "clean"


def test_a_model_call_is_never_a_finding_by_itself(workspace):
    run, records, summary = _scan(workspace, *CALLS)

    assert records == [] and run.status == "clean"
    assert "could not read" not in summary


def test_a_scan_with_no_model_call_has_no_note(workspace):
    _run, records, summary = _scan(workspace, SINK)

    assert [r["rule"] for r in records] == ["valvur.python.dangerous-exec"]
    assert "calls a model" not in summary


def test_a_flow_that_was_found_needs_no_note(workspace):
    run, records, summary = _scan(workspace, *CALLS, SINK, FLOW)

    assert sorted(r["rule"] for r in records) == ["valvur.llm.output-to-shell",
                                                  "valvur.python.dangerous-exec"]
    assert "calls a model" not in summary and run.status == "findings"


def test_it_is_a_note_and_not_a_doubt():
    assert verdict.MODEL_OUTPUT_RULE in verdict.NOTE_RULES
    assert verdict.MODEL_OUTPUT_RULE not in verdict.DOUBT_RULES


_CLAIM = re.compile(
    r"\b(follow|track|trace)(s|ed|ing)?\b[^.|\n]{0,90}\b(across|between)\s+"
    r"(functions|files|modules)\b", re.I)
_DENIAL = re.compile(r"\b(not|never|cannot|no|does not|without)\b", re.I)


def claims(text: str) -> list[str]:
    """Each sentence that says valvur follows a flow across functions or files."""
    sentences = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
    return [s for s in sentences if _CLAIM.search(s) and not _DENIAL.search(s)]


def test_no_document_says_the_rules_follow_a_flow_between_files():
    for path in [REPO / "README.md", *sorted((REPO / "docs").glob("*.md")),
                 *sorted((REPO / "rules").glob("*.yaml"))]:
        assert claims(path.read_text()) == [], path.name


def test_a_planted_claim_is_seen():
    text = (REPO / "README.md").read_text() + "\n\nvalvur follows model output across files.\n"

    [seen] = claims(text)
    assert seen.endswith("valvur follows model output across files.")
    assert claims("valvur does not follow a model's output across functions.") == []


CROSSING = '''\
import anthropic

client = anthropic.Anthropic()


def run(code):
    exec(code)


def agent(prompt):
    reply = client.messages.create(model="m", max_tokens=100,
                                   messages=[{"role": "user", "content": prompt}])
    run(reply.content[0].text)
'''
INSIDE = '''\
import anthropic

client = anthropic.Anthropic()


def agent(prompt):
    reply = client.messages.create(model="m", max_tokens=100,
                                   messages=[{"role": "user", "content": prompt}])
    exec(reply.content[0].text)
'''


#: Not a model: Click's test runner has an `invoke` too, and Twilio's client a
#: `messages.create`. On the corpus the mark first said two web frameworks call a model.
NOT_A_MODEL = '''\
from click.testing import CliRunner
from twilio.rest import Client


def run(code):
    exec(code)


def test_cli(cli):
    result = CliRunner().invoke(cli, ["init-db"])
    Client().messages.create(body=result.output, to="+10000000000")
    run(result.output)
'''


@pytest.mark.e2e
@pytest.mark.parametrize("source, noted, flows", [(CROSSING, True, 0), (INSIDE, False, 1),
                                                  (NOT_A_MODEL, False, 0)])
def test_through_opengrep_a_flow_across_a_function_gets_the_note(mountable_tmp, source, noted,
                                                                 flows):
    """The real rule marks the call: output handed to another function is the case valvur
    does not follow, and says so; inside one function it reports the flow instead."""
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "app" / "agent.py").write_text(source)

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    rules = [f.rule for f in run.findings]
    assert "valvur.llm.model-call" not in rules
    assert (verdict.MODEL_OUTPUT_RULE in rules) is noted
    assert rules.count("valvur.llm.output-to-code-execution") == flows
    assert "valvur.python.dangerous-exec" in rules
