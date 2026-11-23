"""R51.3: the identifiers in every output (D82o, ADR-0037, Requirement 8).

`identifiers.toml` mapped every rule and nothing wrote the mapping. A Finding now carries
`owasp` beside `cwe`, in `findings.json`, in SARIF as taxonomies, relationships and tags,
in the reply and in `SUMMARY.md`'s table, and `findings --owasp` lists a category's.
Neither field is identity: every Fingerprint is what it was.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api
from valvur.engine_host import LocalRuntime
from valvur.findings import Dependency, Finding
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"
SQL = Finding(rule="valvur.python.string-built-sql", path="app/db.py", line=4,
              title="SQL built from a string", severity="high", fingerprint="a" * 32,
              sources=("opengrep",), cwe=("CWE-89",))
SECRET = Finding(rule="aws-access-token", path="app/settings.py", line=2,
                 title="AWS access token", severity="critical", fingerprint="b" * 32,
                 sources=("gitleaks",))
ADVISORY = Finding(rule="CVE-2026-0001", path="requirements.txt", line=0,
                   title="requests: a flaw", severity="high", fingerprint="c" * 32,
                   sources=("trivy",), cwe=("CWE-79",),
                   dependency=Dependency(ecosystem="pip", package="requests", version="2.19.1"))
UNKNOWN_LICENCE = Finding(rule="valvur.licence.dependency-unknown", path="requirements.txt",
                          line=0, title="requests: no licence known", severity="low",
                          fingerprint="d" * 32, sources=("valvur",))


class _Scanner:
    artifact = None
    kind = "scanner"
    version = "1"
    network = False

    def __init__(self, name: str, found: list[Finding]):
        self.name, self.found = name, found

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        empty = "[]" if self.name == "gitleaks" else "{}"
        return Invocation(tool=self.name, version="1", report=f"{self.name}.json", timeout=60,
                          argv=("fake-report", "0", empty, f"/results/{self.name}.json"))

    def parse(self, output):
        return list(self.found)


@pytest.fixture
def scanned(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "app" / "db.py").write_text("import sqlite3\n")
    (ws / "app" / "settings.py").write_text("DEBUG = False\n")
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[
        _Scanner("opengrep", [SQL]), _Scanner("gitleaks", [SECRET]),
        _Scanner("trivy", [ADVISORY, UNKNOWN_LICENCE])])
    return ws


def _written(ws: Path) -> dict[str, dict]:
    document = json.loads((ws / RESULTS / "findings.json").read_text())
    assert document["schema"] == 1 and document["fp_version"] == 1
    return {f["rule"]: f for f in document["findings"]}


def test_an_opengrep_finding_carries_owasp_beside_its_cwe(scanned):
    found = _written(scanned)[SQL.rule]

    assert (found["cwe"], found["owasp"]) == (["CWE-89"], ["A05:2025"])
    assert found["fingerprint"] == SQL.fingerprint


def test_a_gitleaks_finding_carries_its_scanners_entry(scanned):
    found = _written(scanned)[SECRET.rule]

    assert (found["cwe"], found["owasp"]) == (["CWE-798"], ["A07:2025"])


def test_a_dependency_finding_keeps_its_advisorys_cwe_and_takes_its_scanners_category(scanned):
    """The weakness inside the package is the advisory's to name. Where the Finding sorts
    is the supply chain: the fix is an upgrade, whatever the weakness."""
    found = _written(scanned)[ADVISORY.rule]

    assert (found["cwe"], found["owasp"]) == (["CWE-79"], ["A03:2025"])


def test_a_finding_whose_entry_says_none_carries_neither_key(scanned):
    found = _written(scanned)[UNKNOWN_LICENCE.rule]

    assert "owasp" not in found and "cwe" not in found


def _sarif(ws: Path) -> dict:
    return json.loads((ws / RESULTS / "results.sarif").read_text())


def test_sarif_carries_the_taxonomies_and_each_rules_relationships(scanned):
    import jsonschema

    document = _sarif(scanned)
    schema = json.loads((Path(__file__).parent / "fixtures" / "schema"
                         / "sarif-2.1.0.json").read_text())
    jsonschema.validate(instance=document, schema=schema)
    [run] = document["runs"]

    taxonomies = {t["name"]: t for t in run["taxonomies"]}
    assert sorted(taxonomies) == ["CWE", "OWASP Top 10"]
    assert taxonomies["OWASP Top 10"]["version"] == "2025"
    assert {t["id"]: t["name"] for t in taxonomies["OWASP Top 10"]["taxa"]} == {
        "A03:2025": "Software Supply Chain Failures", "A05:2025": "Injection",
        "A07:2025": "Authentication Failures"}
    assert [t["id"] for t in taxonomies["CWE"]["taxa"]] == ["CWE-79", "CWE-89", "CWE-798"]
    assert run["tool"]["driver"]["supportedTaxonomies"] == [
        {"name": "CWE"}, {"name": "OWASP Top 10"}]

    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules[SQL.rule]["relationships"] == [
        {"target": {"id": "CWE-89", "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]},
        {"target": {"id": "A05:2025", "toolComponent": {"name": "OWASP Top 10"}},
         "kinds": ["relevant"]}]
    assert "relationships" not in rules[UNKNOWN_LICENCE.rule]


def test_a_run_with_nothing_mapped_writes_no_taxonomy(tmp_path):
    from valvur import artifacts

    [run] = json.loads(artifacts.sarif([UNKNOWN_LICENCE], version="1"))["runs"]

    assert "taxonomies" not in run and "supportedTaxonomies" not in run["tool"]["driver"]


def test_sarif_carries_the_tags_code_scanning_tools_read(scanned):
    rules = {r["id"]: r for r in _sarif(scanned)["runs"][0]["tool"]["driver"]["rules"]}

    assert rules[SQL.rule]["properties"]["tags"] == ["external/cwe/cwe-89",
                                                      "external/owasp/a05:2025"]
    assert rules[SECRET.rule]["properties"]["tags"] == ["external/cwe/cwe-798",
                                                         "external/owasp/a07:2025"]
    assert rules[SQL.rule]["properties"]["owasp"] == ["A05:2025"]
    assert "tags" not in rules[UNKNOWN_LICENCE.rule]["properties"]


def test_the_reply_carries_them_and_its_schema_is_still_two(scanned):
    from valvur import operations
    from valvur.mcp.tools import registry

    _text, reply = operations.findings_reply({"workspace": str(scanned)})

    by_rule = {entry["rule"]: entry for entry in reply["findings"]}
    assert (by_rule[SQL.rule]["cwe"], by_rule[SQL.rule]["owasp"]) == (["CWE-89"], ["A05:2025"])
    assert "owasp" not in by_rule[UNKNOWN_LICENCE.rule]
    tools = {t.name: t for t in registry()}
    assert tools["scan"].output_schema["properties"]["schema"] == {"const": 2}
    shape = tools["findings"].output_schema["properties"]["findings"]["items"]["properties"]
    assert shape["cwe"]["items"] == shape["owasp"]["items"] == {"type": "string"}
    assert "mapped to" in shape["owasp"]["description"]


def test_one_finding_in_full_names_what_it_is_mapped_to(scanned):
    from valvur import operations

    text, reply = operations.findings_reply({"workspace": str(scanned),
                                             "fingerprint": SQL.fingerprint})

    assert "  mapped to:   CWE-89; A05:2025 Injection (OWASP Top 10 2025)" in text.splitlines()
    assert reply["detail"]["owasp"] == [{"id": "A05:2025", "name": "Injection",
                                         "list": "OWASP Top 10", "edition": "2025"}]


def test_findings_lists_a_categorys_in_the_tool(scanned):
    from valvur import operations

    text, reply = operations.findings_reply({"workspace": str(scanned), "owasp": "a05:2025"})

    assert [entry["rule"] for entry in reply["findings"]] == [SQL.rule]
    assert reply["filters"] == {"owasp": "A05:2025"}
    assert text.startswith("1 finding(s)")


def test_a_category_no_list_holds_is_refused_with_the_editions_it_could_be(scanned):
    """`A03:2021` matching nothing would read as *no injection here*."""
    from valvur import operations
    from valvur.refusal import Refusal

    with pytest.raises(Refusal, match="A03:2021") as refused:
        operations.findings_reply({"workspace": str(scanned), "owasp": "A03:2021"})

    assert "OWASP Top 10 2025" in str(refused.value)
    assert "A01:2025" in str(refused.value)


def test_findings_lists_a_categorys_on_the_command_line(scanned, capsys):
    from valvur import cli

    assert cli.main(["findings", str(scanned), "--owasp", "A07:2025"]) == 0

    out = capsys.readouterr().out
    assert SECRET.rule in out and SQL.rule not in out


def test_the_summary_counts_active_findings_by_category(scanned):
    summary = (scanned / RESULTS / "SUMMARY.md").read_text()

    at = summary.index("## By OWASP category")
    section = summary[at:].split("\n## ")[0]
    assert ("| OWASP Top 10 2025 | A03:2025 Software Supply Chain Failures 1; "
            "A05:2025 Injection 1; A07:2025 Authentication Failures 1 |") in section
    assert "mapped to" in section and "`findings --owasp" in section
    assert summary.index("## Most urgent") < at
    assert "cover" not in section.lower() and "compl" not in section.lower()


def test_a_run_with_nothing_mapped_has_no_such_table(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Scanner("trivy", [UNKNOWN_LICENCE])])

    assert "By OWASP category" not in (ws / RESULTS / "SUMMARY.md").read_text()


def _summary_of(tmp_path, monkeypatch, count: int) -> str:
    from dataclasses import replace

    from valvur import cache, summary

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("import sqlite3\n")
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Scanner("opengrep", [SQL])])
    [one] = [f for f in run.findings if f.rule == SQL.rule]
    return summary.render(replace(run, findings=[
        replace(one, path=f"app/m{n}.py", fingerprint=f"{n:032d}", rank=n + 1)
        for n in range(count)]))


def test_one_category_beside_the_entries_it_counts_is_not_a_table(tmp_path, monkeypatch):
    """R5.2 measured a small repository's summary at one screen. A row that says
    *Injection 2* under the two Findings it counts would spend six lines to say nothing."""
    assert "By OWASP category" not in _summary_of(tmp_path, monkeypatch, 2)


def test_one_category_is_a_table_once_most_urgent_cannot_show_them_all(tmp_path, monkeypatch):
    from valvur import summary

    text = _summary_of(tmp_path, monkeypatch, summary.TOP_N + 1)

    assert f"| OWASP Top 10 2025 | A05:2025 Injection {summary.TOP_N + 1} |" in text


def test_the_table_is_bounded_with_every_category_of_every_list(tmp_path, monkeypatch):
    """Three rows at most, one per list, so thirty categories cost what three do."""
    from dataclasses import replace

    from valvur import cache, identifiers, summary

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Scanner("trivy", [ADVISORY])])
    every = [c for one in identifiers.table().lists.values() if one.mapped
             for c in one.categories]
    made = [replace(run.findings[0], rule=f"made-{n}", fingerprint=f"{n:032d}", rank=n + 1,
                    owasp=(category,)) for n, category in enumerate(every)]

    text = summary.render(replace(run, findings=made))

    section = text[text.index("## By OWASP category"):].split("\n## ")[0]
    assert len(every) == 30 and all(f"{category} " in section for category in every)
    assert len([row for row in section.splitlines() if row.startswith("| OWASP")]) == 3
    assert len(text.splitlines()) <= summary.LINE_CAP and "truncated" not in text
