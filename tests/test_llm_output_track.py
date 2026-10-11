"""R41 (D80): the ninth track, model output reaching a sink.

valvur's four LLM-output rules are its core claim for AI-generated code, and until R41
nothing measured them: `docs/RULES.md` called them *unmeasured*. The track holds
generated twins, a vulnerable case and its fixed version for every sink and SDK source
the rules name, and the flows the rules are known to miss, through a helper. It holds
real cases too: the vulnerable code of published advisories in LLM frameworks, pinned
in `tests/eval/sources.toml`, and reported apart, since valvur writes its own twins.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "eval"))

import twins  # noqa: E402  # type: ignore[import-not-found]

#: The four rules, by the sink they report.
RULES = {"code-execution": "valvur.llm.output-to-code-execution",
         "shell": "valvur.llm.output-to-shell",
         "query": "valvur.llm.output-to-sql",
         "dom": "valvur.js.output-to-innerhtml"}
PYTHON_SOURCES = {"anthropic", "openai-chat", "openai-responses", "openai-legacy", "gemini",
                  "langchain", "litellm", "ollama"}
JS_SOURCES = {"anthropic", "openai-chat", "openai-responses", "gemini", "langchain", "ollama"}


def _generated(tmp_path):
    return [c for c in twins.build("llm-output", tmp_path / "t") if c.id.startswith("llm-gen-")]


def test_each_sink_has_a_vulnerable_case_and_its_fixed_twin_for_every_source(tmp_path):
    cases = _generated(tmp_path)

    for category, sources in (("code-execution", PYTHON_SOURCES), ("shell", PYTHON_SOURCES),
                              ("query", PYTHON_SOURCES), ("dom", JS_SOURCES)):
        mine = [c for c in cases if c.category == category]
        for source in sources:
            pair = {c.vulnerable for c in mine if c.id.removesuffix("-fixed")
                    == f"llm-gen-{category}-{source}"}
            assert pair == {True, False}, (category, source)
        assert {c.rules for c in mine} == {(RULES[category],)}
    for case in cases:
        assert (tmp_path / "t" / case.path).is_file(), case.path


def test_the_flows_the_rules_are_known_to_miss_are_cases_too(tmp_path):
    """A helper that returns the model's text hides the flow from Opengrep's
    intra-procedural taint (`rules/llm-output-sinks.yaml`): measured, not only stated."""
    cases = _generated(tmp_path)
    helpers = [c for c in cases if "-helper" in c.id]

    assert {c.category for c in helpers if c.vulnerable} == set(RULES)
    for case in helpers:
        text = (tmp_path / "t" / case.path).read_text()
        assert "def ask(" in text or "function ask(" in text, case.path


def test_one_seed_writes_one_tree(tmp_path):
    first = twins.build("llm-output", tmp_path / "a", seed=7)
    second = twins.build("llm-output", tmp_path / "b", seed=7)

    assert first == second
    for case in first:
        if case.id.startswith("llm-gen-"):
            assert (tmp_path / "a" / case.path).read_bytes() == \
                (tmp_path / "b" / case.path).read_bytes()
