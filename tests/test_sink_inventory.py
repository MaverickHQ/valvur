"""R20.3: the sink inventory is inventory (D47a).

`dangerous-eval`, `dangerous-exec` and `string-built-sql` name a sink, at INFO: on
their own they are an inventory of where model output or input could do harm, and
the LLM-output rules report the flow into one. On the corpus they were 9 of the 26
false alarms (R20.1), and each made a verdict `findings` by itself. They stay in
`findings.json`, marked `inventory`, and `SUMMARY.md` counts them under *Sinks to
review*; they no longer count toward the verdict, and `findings` lists them only
when asked.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from valvur import verdict
from valvur.adapters.opengrep import OpengrepAdapter
from valvur.findings import Finding
from valvur.runner import ScannerOutput
from valvur.scanrun import ScanRun

RULES = Path(__file__).resolve().parents[1] / "rules"
INVENTORY = {"valvur.python.dangerous-eval", "valvur.python.dangerous-exec",
             "valvur.python.string-built-sql"}


def _sink(**kw) -> Finding:
    return Finding(**{"rule": "valvur.python.dangerous-exec", "path": "app.py", "line": 3,
                      "title": "A code-execution sink", "fingerprint": "f" * 16,
                      "severity": "low", "inventory": True, **kw})


def test_the_three_sink_rules_and_no_other_declare_themselves_inventory():
    declared = set()
    for path in RULES.glob("*.yaml"):
        for block in path.read_text().split("\n  - id: ")[1:]:
            if re.search(r"^\s+inventory: true$", block, re.M):
                declared.add(block.split("\n", 1)[0].strip())
    assert declared == INVENTORY


def test_an_inventory_rules_finding_is_marked_so():
    report = {"results": [{
        "check_id": "opt.valvur-rules.valvur.python.dangerous-exec", "path": "/workspace/a.py",
        "start": {"line": 3}, "extra": {"message": "sink", "lines": "exec(code)",
                                        "severity": "INFO",
                                        "metadata": {"inventory": True, "cwe": ["CWE-95"]}}},
        {"check_id": "opt.valvur-rules.valvur.python.subprocess-shell-true",
         "path": "/workspace/a.py", "start": {"line": 4},
         "extra": {"message": "shell", "lines": "run(x, shell=True)", "severity": "ERROR",
                   "metadata": {}}}]}
    found = OpengrepAdapter().parse(ScannerOutput("opengrep", "1", json.dumps(report), "", 0))
    assert [(f.rule, f.inventory) for f in found] == [
        ("valvur.python.dangerous-exec", True), ("valvur.python.subprocess-shell-true", False)]


def test_it_is_not_active_and_a_project_with_only_inventory_reads_clean():
    from valvur.summary import render

    run = ScanRun(findings=[_sink()], profile="offline", db_age_days=1.0,
                  name_index_age_days=1.0)
    assert not verdict.active(run.findings[0])
    assert not verdict.active({"rule": "valvur.python.dangerous-exec", "inventory": True})
    assert run.status == "clean"
    summary = render(run)
    assert "**Sinks to review:** 1" in summary


def test_a_finding_at_the_same_line_that_is_not_inventory_still_counts():
    shell = Finding(rule="valvur.python.subprocess-shell-true", path="app.py", line=3,
                    title="shell", fingerprint="e" * 16, severity="high")
    run = ScanRun(findings=[_sink(), shell], profile="offline", db_age_days=1.0,
                  name_index_age_days=1.0)
    assert run.active == [shell] and run.status == "findings"


def test_findings_json_and_sarif_carry_the_mark():
    from valvur.artifacts import findings_json, sarif

    record = json.loads(findings_json([_sink()], status="clean", complete=True))["findings"][0]
    assert record["inventory"] is True
    result = json.loads(sarif([_sink()], version="1"))["runs"][0]["results"][0]
    assert result["properties"]["inventory"] is True


def test_the_findings_tool_lists_inventory_only_when_asked(tmp_path):
    from valvur import operations
    from valvur.artifacts import findings_json

    shell = Finding(rule="valvur.python.subprocess-shell-true", path="app.py", line=4,
                    title="shell", fingerprint="e" * 16, severity="high")
    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "findings.json").write_text(
        findings_json([_sink(), shell], status="findings", complete=True))

    _, plain = operations.findings_reply({"workspace": str(tmp_path)})
    _, asked = operations.findings_reply({"workspace": str(tmp_path), "inventory": True})

    assert [f["rule"] for f in plain["findings"]] == ["valvur.python.subprocess-shell-true"]
    assert {f["rule"] for f in asked["findings"]} == {
        "valvur.python.subprocess-shell-true", "valvur.python.dangerous-exec"}
