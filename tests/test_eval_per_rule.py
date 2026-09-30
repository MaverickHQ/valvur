"""R13.2: each candidate rule measured before any ships (D29).

`scripts/eval.py --per-rule DIR` runs the rules in DIR, through the image's Opengrep,
over track 1 (the OWASP Benchmark), track 2 (the JavaScript twins) and the corpus,
each read the way a scan reads it. Per rule: its true positives, false positives and
matches on cases of another weakness, and its time. A rule meets D29's bar with one
true positive and precision of at least 0.5. A corpus match counts against a rule
unless a label says a maintainer would act on it: those projects are mature code.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVAL = REPO / "scripts" / "eval"


def _module():
    sys.path.insert(0, str(EVAL))
    try:
        spec = importlib.util.spec_from_file_location("per_rule", EVAL / "per_rule.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["per_rule"] = module
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(EVAL))
    return module


def _case(path: str, vulnerable: bool, cwe: int):
    return _module().Case(path, "t", "c", path, vulnerable, cwes=(cwe,))


def _report(*matches: tuple[str, str], times: dict[str, float] | None = None) -> dict:
    return {"results": [{"check_id": f"rules.{rule}", "path": f"/src/{path}"}
                        for rule, path in matches],
            "time": {"targets": [{"path": "/src/x", "match_times": [
                [f"rules.{rule}", seconds] for rule, seconds in (times or {}).items()]}]}}


def test_a_match_counts_by_its_cases_label_and_weakness():
    per_rule = _module()
    cases = [_case("a.py", True, 502), _case("b.py", False, 502), _case("c.py", True, 22)]
    report = _report(("pickle", "a.py"), ("pickle", "b.py"), ("pickle", "c.py"),
                     ("pickle", "helpers/util.py"))

    counts = per_rule.tally(report, cases, {"pickle": {502}})

    assert counts["pickle"] == per_rule.Counts(tp=1, fp=1, outside=2, new=1)


def test_a_child_weakness_answers_its_parent():
    per_rule = _module()
    cases = [_case("w.py", True, 330), _case("e.py", True, 94)]
    report = _report(("random", "w.py"), ("eval", "e.py"))

    counts = per_rule.tally(report, cases, {"random": {338}, "eval": {95}})

    assert counts["random"].tp == 1 and counts["eval"].tp == 1


def test_a_corpus_match_counts_against_a_rule_unless_labelled_tp():
    per_rule = _module()
    report = _report(("random", "lib/jitter.py"), ("shell", "tools/run.py"))
    labels = {("requests", "shell", "tools/run.py"): "tp"}

    counts = per_rule.tally_corpus("requests", report, labels)

    assert counts["random"] == per_rule.Counts(fp=1)
    assert counts["shell"] == per_rule.Counts(tp=1, new=1)


def test_each_rules_time_is_summed_over_every_file():
    per_rule = _module()
    report = _report(times={"pickle": 0.25, "random": 0.5})
    report["time"]["targets"].append({"path": "/src/y", "match_times": [["rules.pickle", 0.75]]})

    assert per_rule.times(report) == {"pickle": 1.0, "random": 0.5}


def test_the_bar_is_one_new_true_positive_and_precision_of_a_half():
    per_rule = _module()

    assert per_rule.Counts(tp=1, fp=1, new=1).ships
    assert not per_rule.Counts(tp=0, fp=0).ships
    assert not per_rule.Counts(tp=2, fp=3, new=2).ships
    assert per_rule.Counts(tp=5, fp=0, outside=40, new=5).ships  # another weakness's cases
    # D29 as amended by R13.6: every true positive at a line valvur's own rules
    # already report is a second finding for one flaw, never merged.
    assert not per_rule.Counts(tp=7, fp=7, new=0).ships


def test_a_match_at_a_line_valvurs_own_rules_report_is_not_new():
    per_rule = _module()
    cases = [_case("a.py", True, 78), _case("b.py", True, 78)]
    report = {"results": [{"check_id": "rules.shell", "path": "/src/a.py", "start": {"line": 3}},
                          {"check_id": "rules.shell", "path": "/src/b.py", "start": {"line": 9}}]}

    counts = per_rule.tally(report, cases, {"shell": {78}}, own={("a.py", 3)})

    assert counts["shell"] == per_rule.Counts(tp=2, new=1)


def test_a_target_is_read_as_a_scan_reads_it(tmp_path):
    per_rule = _module()
    target = tmp_path / "project"
    (target / "tests").mkdir(parents=True)
    (target / "tests" / "t.py").write_text("x = 1\n")
    (target / ".git").mkdir()

    copy = per_rule.readable(target, tmp_path / "copy")

    assert (copy / "tests" / "t.py").is_file() and not (copy / ".git").exists()
    assert "turns Opengrep's default ignore list off" in (copy / ".semgrepignore").read_text()


def test_per_rule_measures_the_tracks_and_the_corpus_and_writes_a_table(tmp_path):
    spec = importlib.util.spec_from_file_location("valvur_eval", REPO / "scripts" / "eval.py")
    evaluation = importlib.util.module_from_spec(spec)
    sys.modules["valvur_eval"] = evaluation
    spec.loader.exec_module(evaluation)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "pickle.yaml").write_text(
        "rules:\n  - id: pickle\n    metadata:\n      cwe: \"CWE-502\"\n")
    benchmark = tmp_path / "bench"
    (benchmark / "testcode").mkdir(parents=True)
    (benchmark / "expectedresults-0.1.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,deserialization,true,502\n"
        "BenchmarkTest00002,deserialization,false,502\n")
    project = tmp_path / "corpus" / "requests"
    project.mkdir(parents=True)
    seen: list[str] = []

    def run(rules_dir, target, image):
        if rules_dir.name == "own-rules":         # valvur's own report nothing here
            return {"results": [], "time": {"targets": []}}
        seen.append(target.name)
        found = {"sast-python": ["testcode/BenchmarkTest00001.py"], "sast-js": [],
                 "corpus-requests": ["src/util.py"]}[target.name]
        return {"results": [{"check_id": "rules.pickle", "path": f"/src/{p}"} for p in found],
                "time": {"targets": []}}

    report = evaluation.per_rule(rules, tmp_path / "work", benchmark=benchmark,
                                 corpus=[{"name": "requests"}], checkouts=tmp_path / "corpus",
                                 run=run, verify=lambda root: None)

    assert seen == ["sast-python", "sast-js", "corpus-requests"]
    row = report["rules"]["pickle"]
    assert (row["tp"], row["fp"], row["ships"]) == (1, 1, True)
    assert "| pickle | 502 | 1 | 1 | 1 | 0 | 0.5 | yes |" in evaluation.per_rule_table(report)


def test_opengrep_runs_in_the_target_where_it_finds_the_ignore_file(tmp_path, monkeypatch):
    """Opengrep reads `.semgrepignore` from its working directory, not from the target:
    run from the image's default, it skipped every `tests/` tree, and R13.2's first
    measurement missed seven of the corpus's matches in `requests` alone."""
    import subprocess

    per_rule = _module()
    ran: list[list[str]] = []

    def run(command, **kwargs):
        ran.append(command)
        return subprocess.CompletedProcess(command, 0, '{"results": []}', "")

    monkeypatch.setattr(per_rule.subprocess, "run", run)

    per_rule.opengrep(tmp_path / "rules", tmp_path / "target", "valvur:dev")

    [command] = ran
    assert command[command.index("-w") + 1] == "/src"
