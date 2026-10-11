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


# ------------------------------------------------------------- the real cases

import llm_real  # noqa: E402  # type: ignore[import-not-found]


def test_the_real_cases_are_pinned_with_their_licence_advisory_and_files():
    """`tests/eval/sources.toml`, as the Benchmark is: each case's vulnerable commit,
    its fixed one where a clean fix exists, the advisory, and the files that hold the
    flow. Three at least, or D80's fallback holds."""
    import re

    entries = llm_real.entries()

    assert len(entries) >= 3
    for name, entry in entries.items():
        assert entry["url"].startswith("https://github.com/"), name
        assert entry["licence"] in llm_real.LICENCES, name
        assert re.fullmatch(r"CVE-\d{4}-\d{4,}", entry["advisory"]), name
        assert entry["category"] in RULES, name
        assert entry["files"] and all(not f.startswith("/") for f in entry["files"]), name
        for kind in ("commit", "fixed"):
            if kind in entry:
                assert re.fullmatch(r"[0-9a-f]{40}", entry[kind]), (name, kind)


def _origin(tmp_path) -> tuple[str, str, str]:
    """A local repository standing in for GitHub: two commits of one file."""
    import subprocess

    origin = tmp_path / "origin"
    origin.mkdir()

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=origin, check=True, capture_output=True,
                              text=True).stdout.strip()

    git("init", "-q")
    git("config", "uploadpack.allowFilter", "true")
    git("config", "uploadpack.allowAnySHA1InWant", "true")
    (origin / "chain.py").write_text("def run(llm):\n    return eval(llm.predict('x'))\n")
    git("add", "."), git("-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                         "commit", "-qm", "vulnerable")
    vulnerable = git("rev-parse", "HEAD")
    (origin / "chain.py").write_text("def run(llm):\n    return int(llm.predict('x'))\n")
    git("add", "."), git("-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                         "commit", "-qm", "fixed")
    return origin.as_uri(), vulnerable, git("rev-parse", "HEAD")


def test_a_real_case_is_fetched_at_its_commits_into_the_build_cache(tmp_path):
    url, vulnerable, fixed = _origin(tmp_path)
    entries = {"demo": {"url": url, "licence": "MIT", "advisory": "CVE-2026-0001",
                        "category": "code-execution", "commit": vulnerable, "fixed": fixed,
                        "files": ["chain.py"]}}

    cache = llm_real.fetch(tmp_path / "cache", entries)

    assert "eval(" in (cache / "demo" / "vulnerable" / "chain.py").read_text()
    assert "int(" in (cache / "demo" / "fixed" / "chain.py").read_text()
    assert llm_real.fetch(tmp_path / "cache", entries) == cache   # at its pin: no refetch


def test_the_real_cases_join_the_track_and_name_their_kind(tmp_path):
    url, vulnerable, fixed = _origin(tmp_path)
    entries = {"demo": {"url": url, "licence": "MIT", "advisory": "CVE-2026-0001",
                        "category": "code-execution", "commit": vulnerable, "fixed": fixed,
                        "files": ["chain.py"]}}
    cache = llm_real.fetch(tmp_path / "cache", entries)

    cases = twins.llm_real_cases(tmp_path / "t", cache, entries)

    assert [(c.id, c.vulnerable, c.category, c.path) for c in cases] == [
        ("llm-real-demo", True, "code-execution", "real/demo/vulnerable"),
        ("llm-real-demo-fixed", False, "code-execution", "real/demo/fixed")]
    assert (tmp_path / "t" / "real" / "demo" / "vulnerable" / "chain.py").is_file()
    assert not list((tmp_path / "t").rglob(".valvur*"))


# ------------------------------------------------------------- the ninth track

def _eval():
    import importlib.util

    spec = importlib.util.spec_from_file_location("valvur_eval", REPO / "scripts" / "eval.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["valvur_eval"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_the_track_comes_ninth_so_tracks_one_to_eight_keep_their_numbers():
    tracks = _eval().TRACKS

    assert tracks[7:] == ["real-code-precision", "llm-output"]


def test_it_is_scored_per_sink_and_reports_generated_and_real_cases_apart(tmp_path):
    """A scan that catches every direct flow and nothing else: the helper flows and
    the real advisories are missed, and the two kinds say so separately."""
    import json

    url, vulnerable, fixed = _origin(tmp_path)
    entries = {"demo": {"url": url, "licence": "MIT", "advisory": "CVE-2026-0001",
                        "category": "code-execution", "commit": vulnerable, "fixed": fixed,
                        "files": ["chain.py"]}}
    real = llm_real.fetch(tmp_path / "real", entries)
    harness = _eval()

    def scan(root: Path) -> None:
        cases = json.loads((root.parent / "llm-output.cases.json").read_text())
        findings = [{"path": c["path"] if c["path"].endswith((".py", ".js"))
                     else c["path"] + "/chain.py", "rule": c["rules"][0], "sources": ["opengrep"],
                     "suppressed": None, "status": "new"}
                    for c in cases if c["vulnerable"] and c["id"].startswith("llm-gen-")
                    and "-helper" not in c["id"]]
        folder = root / ".security-scan"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "findings.json").write_text(json.dumps({"findings": findings}))
        (folder / "run.json").write_text(json.dumps({"status": "findings", "complete": True}))

    result = harness.run(["llm-output"], tmp_path / "work", scan=scan, image="valvur:dev",
                         image_id=lambda image: "sha256:abc",
                         llm_real=lambda: (real, entries))
    track = result["tracks"]["llm-output"]

    assert set(track["categories"]) == {"code-execution", "shell", "query", "dom"}
    assert track["generated"]["vulnerable"] == 34 and track["generated"]["caught"] == 30
    assert (track["real"]["vulnerable"], track["real"]["caught"]) == (1, 0)
    assert track["generated"]["score"] > track["score"] > track["real"]["score"]
