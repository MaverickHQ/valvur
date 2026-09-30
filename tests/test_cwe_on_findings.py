"""R13.4: a finding carries its rule's CWE (F5.10).

Opengrep hands each result its rule's metadata, and every rule valvur ships declares a
CWE: its own as a list with a name (`["CWE-95: Eval Injection"]`), GitLab's as one
string (`"CWE-89"`). The finding keeps it as `CWE-n`, and `findings.json` and SARIF
carry it when there is one. Schema 1's rule for additions holds: an optional field
does not move the version. Ranking and grouping never read it.
"""

from __future__ import annotations

import json

from valvur import artifacts
from valvur.adapters import OpengrepAdapter
from valvur.findings import Finding
from valvur.invocation import ScannerOutput


def _parse(metadata: dict) -> Finding:
    report = {"results": [{"check_id": "opt.valvur-rules.python_sql_rule-x",
                           "path": "/workspace/app.py", "start": {"line": 2},
                           "extra": {"message": "SQL", "lines": "cur.execute(q % n)",
                                     "severity": "WARNING", "metadata": metadata}}]}
    [finding] = OpengrepAdapter().parse(
        ScannerOutput("opengrep", "1.29.0", json.dumps(report), "", 0))
    return finding


def test_a_rules_cwe_reaches_its_finding_in_either_form():
    assert _parse({"cwe": "CWE-89"}).cwe == ("CWE-89",)
    assert _parse({"cwe": ["CWE-95: Eval Injection"]}).cwe == ("CWE-95",)
    assert _parse({}).cwe == ()


def test_findings_json_carries_it_only_when_there_is_one():
    with_cwe = Finding(rule="r", path="a.py", line=1, title="t", fingerprint="f1",
                       cwe=("CWE-89",))
    without = Finding(rule="s", path="b.py", line=1, title="t", fingerprint="f2")

    document = json.loads(artifacts.findings_json([with_cwe, without], status="findings",
                                                  complete=True))

    assert document["schema"] == 1
    assert document["findings"][0]["cwe"] == ["CWE-89"]
    assert "cwe" not in document["findings"][1]


def test_sarif_carries_it_on_the_rule():
    finding = Finding(rule="r", path="a.py", line=1, title="t", fingerprint="f",
                      cwe=("CWE-89",))

    [rule] = json.loads(artifacts.sarif([finding], version="1"))["runs"][0]["tool"][
        "driver"]["rules"]

    assert rule["properties"]["cwe"] == ["CWE-89"]
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]


def test_ranking_grouping_and_merging_do_not_read_it():
    from valvur.findings import merge
    from valvur.ranking import sort_key

    plain = Finding(rule="r", path="a.py", line=1, title="t", fingerprint="f",
                    severity="high")
    tagged = Finding(rule="r", path="a.py", line=1, title="t", fingerprint="f",
                     severity="high", cwe=("CWE-89",))

    assert sort_key(plain) == sort_key(tagged)
    [merged] = merge([plain, tagged])
    assert merged.cwe == ("CWE-89",)                 # kept from whichever carried it
