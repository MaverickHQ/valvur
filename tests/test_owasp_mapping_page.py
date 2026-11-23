"""R51.4: the mapping as a page, and the wording (D82o, ADR-0037, Requirement 8.4 and 8.5).

`docs/OWASP-MAPPING.md` is written from `identifiers.toml` by `scripts/generate_docs.py`:
every rule beside its identifiers, then each list's categories that nothing is mapped to.
And one rule of wording, held over the documents and over a scan's outputs: a list is
*mapped to*. No sentence that names a list says valvur covers it, complies with it or is
certified against it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from valvur import identifiers

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs" / "OWASP-MAPPING.md"


def _generator():
    spec = importlib.util.spec_from_file_location("generate_docs",
                                                  REPO / "scripts" / "generate_docs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_docs"] = module
    spec.loader.exec_module(module)
    return module


def _rows(text: str) -> dict[str, list[str]]:
    rows = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| `") and len(cells) >= 3:
            rows[cells[0].strip("`")] = cells[1:]
    return rows


def test_the_page_lists_every_rule_with_its_identifiers():
    rows = _rows(PAGE.read_text())
    table = identifiers.table()

    assert sorted(set(table.rules) - set(rows)) == []
    assert rows["valvur.python.string-built-sql"] == ["CWE-89", "A05:2025 Injection"]
    assert rows["valvur.llm.output-to-shell"] == [
        "CWE-78", "A05:2025 Injection; LLM05:2025 Improper Output Handling; "
                  "ASI05 Unexpected Code Execution"]
    assert rows["valvur.licence.missing"][1].startswith("none: A licence is a legal matter")
    assert rows["gitleaks"] == ["CWE-798", "A07:2025 Authentication Failures"]


def test_the_page_names_each_list_its_edition_and_the_day_it_was_read():
    text = PAGE.read_text()

    for one in identifiers.table().lists.values():
        assert f"| {one.name} | {one.edition} | {one.read.isoformat()} |" in text, one.name
    assert "T14" in text, "the list that was read and is not mapped to says why"


def test_the_page_lists_each_lists_categories_that_nothing_is_mapped_to():
    text = PAGE.read_text()
    section = text[text.index("## The categories nothing is mapped to"):]

    assert ("- **OWASP Top 10 2025:** A06:2025 Insecure Design; A09:2025 Security Logging "
            "and Alerting Failures; A10:2025 Mishandling of Exceptional Conditions") in section
    assert "LLM04:2025 Data and Model Poisoning" in section
    assert "ASI10 Rogue Agents" in section
    assert "A05:2025" not in section and "LLM01:2025" not in section


def test_check_fails_on_a_page_that_is_not_current(tmp_path, capsys):
    generate = _generator()
    page = tmp_path / "OWASP-MAPPING.md"
    page.write_text(PAGE.read_text().replace("| CWE-89 | A05:2025 Injection |",
                                             "| CWE-89 | A03:2021 Injection |", 1))

    assert generate.main(["--check"], files=[PAGE]) == 0
    assert generate.main(["--check"], files=[page]) == 1
    assert "stale: identifier-rules" in capsys.readouterr().out


# ------------------------------------------------------------------ the wording

DOCUMENTS = sorted([REPO / "README.md", REPO / "CHANGELOG.md", REPO / "CONTEXT.md",
                    REPO / "SECURITY.md",
                    *(REPO / "docs").glob("*.md"),
                    *(REPO / "src" / "valvur" / "data" / "skills").rglob("*.md"),
                    REPO / "src" / "valvur" / "data" / "identifiers.toml",
                    REPO / "tests" / "fixtures" / "mcp" / "tools-list.json"])


def test_a_planted_sentence_is_refused_in_a_document_and_a_mention_is_not():
    from wording import claims

    assert claims("Results sort well.\n\nvalvur covers the OWASP Top 10 and\nmore.\n") == [
        "valvur covers the OWASP Top 10 and more."]
    assert claims("It complies with CWE-89.") and claims("Certified against the LLM Top 10.")
    assert claims("| OWASP Top 10 | full coverage |")
    assert claims("The word is *mapped to*: never *covers* or *complies* of the OWASP "
                  "Top 10.") == []
    assert claims("A coverage note is valvur's own limit. CWE-89 is mapped to A05:2025.") == []


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: str(p.relative_to(REPO)))
def test_no_document_says_valvur_covers_or_complies_with_a_list(path):
    from wording import claims

    assert claims(path.read_text(encoding="utf-8")) == []


def test_no_output_of_a_scan_says_it_either(tmp_path, monkeypatch):
    from test_identifiers_in_outputs import ADVISORY, FAKE_TOOLS, SECRET, SQL, _Scanner
    from wording import claims

    from valvur import api, cache, operations
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[
        _Scanner("opengrep", [SQL]), _Scanner("gitleaks", [SECRET]),
        _Scanner("trivy", [ADVISORY])])
    text, reply = operations.findings_reply({"workspace": str(ws), "fingerprint":
                                             SQL.fingerprint})
    said = {name: (ws / ".security-scan" / name).read_text()
            for name in ("SUMMARY.md", "REMEDIATION.md", "findings.json", "results.sarif")}
    said["the reply"] = text + "\n" + json.dumps(reply)

    assert "OWASP Top 10" in said["results.sarif"] and "A05:2025" in said["SUMMARY.md"]
    assert {name: claims(body) for name, body in said.items() if claims(body)} == {}
    planted = said["results.sarif"].replace("mapped to", "certified against", 1)
    assert claims(planted), "the planted sentence in an output is seen"
