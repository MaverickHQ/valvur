"""R29.3 (D65b): each shipped rule's precision, from the Score's own scans.

`scripts/eval.py` already scans track 1 (the OWASP Benchmark for Python), track 2 (the
JavaScript twins) and the corpus. Each rule's true and false positives are read from
those same Results Folders, so a rule is judged by what valvur reports, path classes
and all, not by a raw Opengrep run the user never sees. The container is faked by a
scan function that writes a Results Folder, as `test_eval_run.py` does.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval.py"


def _harness():
    spec = importlib.util.spec_from_file_location("valvur_eval", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["valvur_eval"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _results(root: Path, findings: list[dict]) -> None:
    folder = root / ".security-scan"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "findings.json").write_text(json.dumps({"findings": findings}))
    (folder / "run.json").write_text(json.dumps({"status": "findings", "complete": True}))


def _finding(rule: str, path: str, line: int = 1, **extra) -> dict:
    return {"rule": rule, "path": path, "line": line, "sources": ["opengrep"],
            "suppressed": None, "status": "new", **extra}


def _benchmark(tmp_path: Path) -> Path:
    benchmark = tmp_path / "BenchmarkPython"
    benchmark.mkdir()
    (benchmark / "expectedresults-0.1.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,pathtraver,false,22\n"
        "BenchmarkTest00100,sqli,true,89\n"
        "BenchmarkTest00003,weakrand,true,330\n")
    return benchmark


def _measure(tmp_path: Path, by_track: dict[str, list[dict]], labels: str = "") -> dict:
    harness = _harness()
    checkouts = tmp_path / "checkouts"
    (checkouts / "flask").mkdir(parents=True)
    label_file = tmp_path / "labels.toml"
    label_file.write_text(labels)

    def scan(root: Path) -> None:
        name = "corpus" if root.parent == checkouts else root.name
        _results(root, by_track.get(name, []))

    result = harness.run(
        ["sast-python", "sast-js", "real-code-precision"], tmp_path / "work", scan=scan,
        image="valvur:dev", image_id=lambda image: "sha256:abc",
        benchmark=_benchmark(tmp_path), verify=lambda checkout: None,
        corpus=[{"name": "flask"}], checkouts=checkouts, labels=label_file)
    return result["rules"]


def test_each_shipped_rule_is_measured_over_tracks_one_and_two_and_the_corpus(tmp_path):
    rules = _measure(tmp_path, {
        "BenchmarkPython": [
            _finding("valvur.python.path-traversal", "testcode/BenchmarkTest00001.py"),
            _finding("valvur.python.path-traversal", "testcode/BenchmarkTest00002.py"),
            # On a case of another weakness: that case says nothing about this rule.
            _finding("valvur.python.path-traversal", "testcode/BenchmarkTest00100.py"),
            # A vendored rule's true positive is new only at a line valvur's own rules
            # do not report (D29 as amended by R13.6).
            _finding("python_random_rule-random", "testcode/BenchmarkTest00003.py", 5),
            _finding("python_random_rule-random", "testcode/BenchmarkTest00003.py", 7),
            _finding("valvur.python.weak-hash", "testcode/BenchmarkTest00003.py", 7)],
        "sast-js": [_finding("valvur.javascript.sql-injection", "src/t89_1.js")],
        "corpus": [_finding("valvur.python.path-traversal", "app.py", fingerprint="f1")],
    }, labels='[[label]]\nrepo = "flask"\nfingerprint = "f1"\nrule = "r"\n'
              'verdict = "fp"\nreason = "a constant path"\n')

    traversal = rules["valvur.python.path-traversal"]
    assert traversal["places"]["sast-python"] == {"tp": 1, "fp": 1, "outside": 1, "new": 0,
                                                   "unjudged": 0}
    assert traversal["places"]["corpus"]["fp"] == 1
    assert (traversal["tp"], traversal["fp"], traversal["precision"]) == (1, 2, 0.333)
    assert (rules["python_random_rule-random"]["tp"], rules["python_random_rule-random"]["new"]) \
        == (2, 1)
    assert rules["valvur.javascript.sql-injection"]["places"]["sast-js"]["tp"] == 1
    # Every shipped rule has a row, matched or not, the vendored ones too.
    assert rules["valvur.llm.output-to-shell"]["tp"] == 0
    assert any(row["vendored"] for row in rules.values())
