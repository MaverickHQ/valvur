"""R29.4: what valvur misses, by a second engine (D65c).

CodeQL's default queries run over the corpus in a CI workflow, and what they report at
lines valvur does not becomes a list of candidate rules in `docs/acceptance/r29.md`.
Nothing of CodeQL ships: no query, no result, no binary. Its terms were read first
(GitHub CodeQL Terms and Conditions, from `github/codeql-cli-binaries`): analysis of an
Open Source Codebase, one under an OSI-approved licence, and automated analysis in CI of
one hosted on GitHub.com. So the CC0 project, not OSI-approved, is left out.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = (REPO / ".github" / "workflows" / "codeql-corpus.yml").read_text()

_spec = importlib.util.spec_from_file_location("codeql_corpus",
                                               REPO / "scripts" / "codeql_corpus.py")
codeql = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(codeql)


def test_only_osi_licensed_python_and_javascript_projects_are_analysed():
    entries = [
        {"name": "a", "language": "python", "licence": "MIT", "url": "u", "commit": "c"},
        {"name": "b", "language": "typescript", "licence": "Apache-2.0", "url": "u",
         "commit": "c"},
        {"name": "c", "language": "markdown", "licence": "CC0-1.0", "url": "u", "commit": "c"},
        {"name": "d", "language": "javascript", "licence": "CC0-1.0", "url": "u",
         "commit": "c"},
        {"name": "e", "language": "go", "licence": "MIT", "url": "u", "commit": "c"},
    ]

    matrix = codeql.matrix(entries)

    assert [(m["name"], m["codeql"]) for m in matrix] == [
        ("a", "python"), ("b", "javascript-typescript")]


def test_the_real_corpus_gives_at_least_thirty_projects():
    assert len(codeql.matrix(codeql.corpus())) >= 30


def _sarif(*results: tuple[str, str, int]) -> dict:
    return {"runs": [{"results": [
        {"ruleId": rule, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path}, "region": {"startLine": line}}}]}
        for rule, path, line in results] + [{"ruleId": "py/no-location", "locations": []}]}]}


def test_each_projects_results_are_read_from_its_sarif_artifact(tmp_path):
    """`gh run download` leaves one directory per artifact, `codeql-<project>`."""
    (tmp_path / "codeql-flask").mkdir()
    (tmp_path / "codeql-flask" / "python.sarif").write_text(json.dumps(
        _sarif(("py/path-injection", "app/views.py", 12))))

    assert codeql.results(tmp_path) == [
        {"repo": "flask", "rule": "py/path-injection", "path": "app/views.py", "line": 12}]


def test_candidates_are_codeql_results_valvur_does_not_report():
    found = [{"repo": "flask", "rule": "py/path-injection", "path": "app/views.py", "line": 12},
             {"repo": "flask", "rule": "py/sql-injection", "path": "app/db.py", "line": 40}]
    valvur = {"flask": [{"path": "app/db.py", "line": 40, "rule": "valvur.python.sqli"}]}

    assert codeql.candidates(found, valvur) == found[:1]


# ---------------------------------------------------------------- the workflow

def test_it_runs_on_the_pull_request_that_changes_it_or_the_corpus_and_on_dispatch():
    on = WORKFLOW.split("\non:", 1)[1].split("\npermissions:", 1)[0]

    assert "workflow_dispatch:" in on and "pull_request:" in on
    assert '".github/workflows/codeql-corpus.yml"' in on and '"tests/corpus/corpus.toml"' in on


def test_nothing_leaves_for_code_scanning_and_nothing_is_written():
    assert "upload: never" in WORKFLOW
    assert "security-events" not in WORKFLOW and "contents: write" not in WORKFLOW
    top = re.search(r"^permissions:\n((?:  .*\n)+)", WORKFLOW, re.M)
    assert top and top.group(1).strip() == "contents: read"


def test_every_action_is_pinned_and_the_project_never_reaches_a_template():
    for uses in re.findall(r"uses:\s*(\S+)", WORKFLOW):
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", uses), uses
    for run in re.findall(r"run: \|\n((?:\s{10}.*\n)+)", WORKFLOW):
        assert "${{" not in run, "a matrix value reaches the shell through env, never inline"


def test_it_cites_the_terms_that_allow_it():
    assert "GitHub CodeQL Terms and Conditions" in WORKFLOW
    assert "Open Source Codebase" in WORKFLOW


def test_codeql_reads_the_project_and_never_valvurs_own_tree():
    """Measured on #204's run 37309665546: with valvur checked out in the workspace,
    CodeQL's `build-mode: none` extracted the workspace, valvur's own `src/` and
    `tests/`, and ignored `source-root`, on every project. The job that analyses checks
    out nothing of valvur: the project at its pin is the workspace."""
    analyse = WORKFLOW.split("\n  analyse:", 1)[1]

    assert "actions/checkout" not in analyse
    assert "source-root:" not in analyse and "checkout_path:" not in analyse
    assert 'cd "$GITHUB_WORKSPACE"' in analyse


def test_each_projects_sarif_is_kept_as_an_artifact_for_the_comparison():
    analyse = WORKFLOW.split("\n  analyse:", 1)[1]

    assert "actions/upload-artifact@" in analyse
    assert "name: codeql-${{ matrix.project.name }}" in analyse


def test_the_corpus_projects_are_codeql_s_only_input_and_nothing_of_it_ships():
    assert "scripts/codeql_corpus.py matrix" in WORKFLOW
    assert not any("codeql" in p.name.lower() for p in (REPO / "rules").rglob("*"))
    assert json.loads(json.dumps(codeql.TERMS))["source"].endswith("codeql-cli-binaries")
