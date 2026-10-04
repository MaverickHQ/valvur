"""R27.4: fuzzing (D63c).

Scorecard's Fuzzing check scored 0. ClusterFuzzLite builds, with atheris, a fuzzer
for each parser of untrusted text: the install commands the hook reads, the
lockfile readers, the project's `.security-scan.toml` and the readers of
`findings.json`. They live in `fuzz/`, outside `tests/`, because the image's
`.dockerignore` keeps `tests/` out of the build context ClusterFuzzLite builds in.
Each runs its seeds here without atheris, so a fuzzer that rots fails the unit suite.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FUZZ = REPO / "fuzz"
#: Each target D63c names, and the module its fuzzer must import.
TARGETS = {"fuzz_installs": "installs", "fuzz_lockfiles": "valvur.ecosystems.locked",
           "fuzz_project_config": "suppressions", "fuzz_findings": "gate"}


def _fuzzers() -> list[Path]:
    return sorted(FUZZ.glob("fuzz_*.py"))


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_clusterfuzzlite_builds_every_fuzzer_and_every_target_has_one():
    build = (REPO / ".clusterfuzzlite" / "build.sh").read_text()

    assert (REPO / ".clusterfuzzlite" / "project.yaml").read_text().strip() == \
        "language: python"
    assert "for fuzzer in fuzz/fuzz_*.py" in build and "compile_python_fuzzer" in build
    assert "pip3 install --no-deps ." in build
    assert {p.stem for p in _fuzzers()} == set(TARGETS)
    for path in _fuzzers():
        assert TARGETS[path.stem] in path.read_text(), path.name
        assert "atheris" not in path.read_text().split("def main", 1)[0], \
            f"{path.name} imports atheris outside main(); the unit suite runs without it"


@pytest.mark.parametrize("path", _fuzzers(), ids=lambda p: p.stem)
def test_every_fuzzer_runs_its_seeds_without_atheris(path):
    module = _load(path)

    assert module.SEEDS, f"{path.name} has no seeds"
    for seed in module.SEEDS:
        module.test_one_input(seed)
