"""R9.4: the OWASP Benchmark for Python as the Score's first track (ADR-0026, D21).

It is GPL-3.0, so it is fetched at a pinned commit into the build cache and never
vendored; its expected results become cases; a finding reaches a case by its file
and a category by its CWE; the track is scored as the OWASP scorecard scores.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EVAL = REPO / "scripts" / "eval"


def _owasp():
    sys.path.insert(0, str(EVAL))
    try:
        spec = importlib.util.spec_from_file_location("owasp", EVAL / "owasp.py")
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        sys.modules["owasp"] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module
    finally:
        sys.path.remove(str(EVAL))


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_a_checkout_at_any_other_commit_is_refused(tmp_path):
    owasp = _owasp()
    repo = tmp_path / "benchmark"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("not the pinned tree\n")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "commit", "-q", "-m", "x")

    with pytest.raises(owasp.PinMismatch, match="f1291485808b"):
        owasp.verify(repo)


def test_nothing_of_the_benchmark_is_tracked_here():
    tracked = _git(REPO, "ls-files").splitlines()

    assert not [p for p in tracked if "BenchmarkTest" in p or "expectedresults" in p]


SAMPLE = """# test name, category, real vulnerability, cwe, Benchmark version: 0.1, 2026-01-9
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00004,pathtraver,false,22
BenchmarkTest00100,sqli,true,89
"""


def test_the_expected_results_become_cases(tmp_path):
    owasp = _owasp()
    (tmp_path / "expectedresults-0.1.csv").write_text(SAMPLE)

    cases = owasp.cases(tmp_path)

    assert [(c.id, c.category, c.path, c.vulnerable, c.cwes) for c in cases] == [
        ("BenchmarkTest00001", "pathtraver", "testcode/BenchmarkTest00001.py", True, (22,)),
        ("BenchmarkTest00004", "pathtraver", "testcode/BenchmarkTest00004.py", False, (22,)),
        ("BenchmarkTest00100", "sqli", "testcode/BenchmarkTest00100.py", True, (89,)),
    ]


CHECKOUT = Path.home() / ".cache" / "valvur-build" / "eval" / "BenchmarkPython"


@pytest.mark.skipif(not (CHECKOUT / "expectedresults-0.1.csv").is_file(),
                    reason="the benchmark is not checked out in the build cache")
def test_the_pinned_benchmark_holds_its_published_counts():
    owasp = _owasp()
    owasp.verify(CHECKOUT)

    cases = owasp.cases(CHECKOUT)

    assert (len(cases), sum(c.vulnerable for c in cases)) == (1230, 452)
    assert len({c.category for c in cases}) == 14
