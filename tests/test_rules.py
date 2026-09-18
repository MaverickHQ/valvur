"""Sub-phase 4.2 — LLM-output-to-sink and pinning hygiene rules."""

import pytest
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


def test_model_output_reaching_a_query_is_a_finding(workspace):
    """Since 23.5.3 a taint rule like the other three — LangChain's `invoke` into
    `cursor.execute` on the fixture — where it had been a plain string-built-SQL
    pattern with no model source at all. That pattern is now the INFO inventory
    entry `valvur.python.string-built-sql`, a sink on its own."""
    rules = _rules(workspace)

    assert "valvur.llm.output-to-sql" in rules
    assert "valvur.python.string-built-sql" in rules


def test_model_output_reaching_the_dom_is_a_finding(workspace):
    """The fourth rule had no fixture until 23.5.3 — "those four fire on our
    fixture" was true of three. Six JavaScript sources now flow into innerHTML."""
    assert "valvur.js.output-to-innerhtml" in _rules(workspace)


# ---------------------------------------------- 23.5.3: every source, by name

def _llm_hits(rule: str) -> list[tuple[str, int, str]]:
    import json

    captured = json.loads(golden("opengrep"))
    return sorted(
        (r["path"].rsplit("/", 1)[-1], r["start"]["line"], r["extra"]["lines"].strip())
        for r in captured["results"] if r["check_id"].endswith(rule)
    )


def test_every_planted_python_source_reaches_its_sink():
    """One function per SDK family in `llm_app.py`, each flowing into a sink the
    INFO rules inventory. Counted by the line the sink sits on, so a source that
    stops being recognised is a named loss, not a smaller number."""
    code = _llm_hits("llm.output-to-code-execution")
    shell = _llm_hits("llm.output-to-shell")
    sql = _llm_hits("llm.output-to-sql")

    reached = {line for _, _, line in code + shell + sql}
    for expected in (
        "return eval(response.content[0].text)",                 # Anthropic
        "exec(completion.choices[0].message.content)",           # OpenAI chat completions
        "subprocess.run(response.output_text, shell=True)",      # OpenAI Responses API
        'os.popen(reply["choices"][0]["message"]["content"])',   # openai < 1.0
        "return eval(result.text)",                              # Gemini
        "return cur.execute(answer.content)",                    # LangChain invoke
        "return yaml.load(reply.choices[0].message.content)",    # litellm, yaml sink
        'return os.system(reply["message"]["content"])',         # ollama
    ):
        assert expected in reached, f"no taint finding on: {expected}"


def test_every_planted_javascript_source_reaches_inner_html():
    lines = [line for _, _, line in _llm_hits("js.output-to-innerhtml")]

    assert len(lines) == 6, lines
    assert all(line.startswith("out.innerHTML = ") for line in lines)
    assert not any("textContent" in line for line in lines)


def test_the_intra_procedural_limit_is_stated_by_the_fixture_not_hidden():
    """`run_via_helper` execs what `ask` returns. Opengrep's taint is
    intra-procedural, so the flow is invisible to the llm rule — and visible to the
    INFO sink inventory, which is the honest division of labour the README
    describes: the inventory is what fires on real code."""
    taint = {line for _, _, line in _llm_hits("llm.output-to-code-execution")}
    inventory = {line for _, _, line in _llm_hits("python.dangerous-exec")}

    assert "return exec(ask(prompt))" not in taint
    assert "return exec(ask(prompt))" in inventory


def test_string_built_sql_is_inventoried_at_info_not_reported_as_a_flow():
    from valvur.adapters import OpengrepAdapter
    from valvur.runner import ScannerOutput

    output = ScannerOutput("opengrep", "1.29.0", golden("opengrep"), "", 0)
    findings = OpengrepAdapter().parse(output)
    [sql] = [f for f in findings if f.rule == "valvur.python.string-built-sql"]
    inventory = {f.severity for f in findings if f.rule == "valvur.python.dangerous-eval"}

    assert {sql.severity} == inventory, "the same class as the other inventory entries"
    assert "lookup" not in {line for _, _, line in _llm_hits("llm.output-to-sql")}


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


@pytest.mark.e2e
def test_the_golden_matches_what_the_image_reports_on_the_fixture(mountable_tmp):
    """The tests above pin the golden; this pins the golden to the image. A source
    pattern removed from `rules/` fails here, not in a recapture someone forgot."""
    import json
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "rules"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    live = json.loads(ContainerRunner().run_opengrep(ws).stdout)
    recorded = json.loads(golden("opengrep"))

    def hits(data):
        return sorted((r["check_id"], r["path"], r["start"]["line"]) for r in data["results"])

    assert hits(live) == hits(recorded)
