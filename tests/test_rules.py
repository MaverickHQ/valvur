"""Sub-phase 4.2 — LLM-output-to-sink and pinning hygiene rules."""

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import OpengrepAdapter


def _rules(workspace):
    run = scan(workspace, runner=GoldenRunner(opengrep=golden("opengrep")),
               adapters=[OpengrepAdapter()])
    return {f.rule for f in run.findings}


def test_model_output_reaching_code_execution_is_a_finding(workspace):
    """F3.10, OWASP LLM05 — the value looks internal because the code generated it."""
    assert "valvur.llm.output-to-code-execution" in _rules(workspace)


def test_model_output_reaching_a_shell_is_a_finding(workspace):
    assert "valvur.llm.output-to-shell" in _rules(workspace)


def test_string_built_sql_is_a_finding(workspace):
    """Injection is injection regardless of whether a human or a model wrote it."""
    assert "valvur.llm.output-to-sql" in _rules(workspace)


def test_a_dependency_on_a_mutable_git_ref_is_a_finding(workspace):
    """F3.11 — the same defect we found in the AWS sample that started this project."""
    assert "valvur.pinning.mutable-git-ref" in _rules(workspace)


def test_an_action_pinned_to_a_mutable_tag_is_a_finding(workspace):
    """F3.11 — added 2026-09-05 after our own workflow went unflagged.

    The rule above only matched pip-style `git+...@main`, so it missed the commonest
    instance of the defect it describes. A tag is a mutable pointer: in March 2025
    tj-actions/changed-files had its tags moved to code that dumped CI secrets into
    build logs, reaching tens of thousands of repositories.
    """
    assert "valvur.pinning.mutable-action-ref" in _rules(workspace)


def test_an_action_pinned_to_a_commit_sha_is_not_a_finding():
    """The half that stops the rule being noise. Verified against the real scanner:
    a 40-character SHA is ignored, and so are local (`./…`) and `docker://` refs,
    which have no SHA to pin to."""
    import json

    from conftest import golden

    captured = json.loads(golden("opengrep"))
    flagged = [
        r["extra"]["lines"].strip()
        for r in captured["results"]
        if r["check_id"].endswith("mutable-action-ref")
    ]

    assert flagged, "the fixture no longer exercises this rule"
    assert all("@v" in line or "@main" in line for line in flagged), flagged
    assert not any(len(line.split("@")[-1].split()[0]) == 40 for line in flagged)
