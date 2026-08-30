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
