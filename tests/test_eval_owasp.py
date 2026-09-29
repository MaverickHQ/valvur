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
