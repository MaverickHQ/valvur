"""R25.5: every rule valvur ships carries its CWE into `findings.json` and SARIF.

R13.4 tested the path with one made-up rule. R25 added eight rules, and an agent
reading `findings.json` or a SARIF viewer grouping by CWE knows a finding's weakness
only from there. So each rule in `rules/*.yaml` goes through the adapter with its own
declared metadata, and its CWE must come out the other side in both artifacts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from valvur import artifacts
from valvur.adapters import OpengrepAdapter
from valvur.invocation import ScannerOutput

RULES = Path(__file__).resolve().parent.parent / "rules"


def _declared() -> dict[str, list[str]]:
    """Each own rule's id and the CWE list its `metadata` declares."""
    found = {}
    for path in sorted(RULES.glob("*.yaml")):
        for block in re.split(r"^  - id: ", path.read_text(), flags=re.M)[1:]:
            line = re.search(r"^\s+cwe:\s*\[(.*)\]\s*$", block, re.M)
            assert line, f"{path.name}: {block.split()[0]} declares no CWE list"
            found[block.split()[0]] = re.findall(r'"([^"]+)"', line.group(1))
    return found


def test_each_shipped_rule_s_cwe_reaches_findings_json_and_sarif():
    declared = _declared()
    assert {"valvur.python.path-traversal", "valvur.javascript.ssrf"} <= set(declared)
    results = [{"check_id": f"opt.valvur-rules.{rule}", "path": f"/workspace/f{i}.py",
                "start": {"line": 1},
                "extra": {"message": "m", "lines": "x", "severity": "ERROR",
                          "metadata": {"cwe": cwes}}}
               for i, (rule, cwes) in enumerate(declared.items())]
    findings = OpengrepAdapter().parse(
        ScannerOutput("opengrep", "1.29.0", json.dumps({"results": results}), "", 0))

    records = json.loads(artifacts.findings_json(findings, status="findings",
                                                 complete=True))["findings"]
    sarif_rules = json.loads(artifacts.sarif(findings, version="1"))["runs"][0]["tool"][
        "driver"]["rules"]

    expected = {rule: [c.split(":")[0] for c in cwes] for rule, cwes in declared.items()}
    assert {r["rule"]: r.get("cwe") for r in records} == expected
    assert {r["id"]: r["properties"].get("cwe") for r in sarif_rules} == expected
