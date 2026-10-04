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


def _workflow() -> str:
    return (REPO / ".github" / "workflows" / "fuzz.yml").read_text()


def _seconds(job: str) -> int:
    import re

    return int(re.search(r"fuzz-seconds: (\d+)", job)[1])


def test_the_fuzzers_run_briefly_on_each_pull_request_and_longer_nightly():
    import re

    text = _workflow()
    head, jobs = text.split("\njobs:\n", 1)
    pr = jobs.split("\n  nightly:\n", 1)[0]
    nightly = jobs.split("\n  nightly:\n", 1)[1].split("\n  tracked:\n", 1)[0]

    assert "pull_request:" in head and "pull_request_target" not in text
    assert re.search(r"^\s+- cron: ", head, re.M)
    assert "if: github.event_name == 'pull_request'" in pr and "mode: code-change" in pr
    assert "if: github.event_name != 'pull_request'" in nightly and "mode: batch" in nightly
    assert _seconds(pr) <= 600 < 1800 <= _seconds(nightly)
    for job in (pr, nightly):
        assert "uses: google/clusterfuzzlite/actions/build_fuzzers@" in job
        assert "uses: google/clusterfuzzlite/actions/run_fuzzers@" in job


def test_the_workflow_holds_the_minimum_permissions():
    import re

    text = _workflow()

    assert re.search(r"^permissions:\n  contents: read\n", text, re.M)
    grants = set(re.findall(r"^\s+(\w[\w-]*): write", text, re.M))
    assert grants == {"issues"}, f"a fuzz run writes nothing but a failure's issue: {grants}"


def test_atheris_is_a_development_dependency_alone():
    """The shim stays standard-library (F10.6). atheris is the `fuzz` extra, apart
    from `dev`, so `verify.sh`'s install on a Mac or Python 3.13 never builds it."""
    import re
    import tomllib

    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]

    assert project["dependencies"] == []
    extras = project["optional-dependencies"]
    assert [d for d in extras["fuzz"] if d.startswith("atheris")], extras
    assert not [d for name, deps in extras.items() if name != "fuzz"
                for d in deps if d.startswith("atheris")]
    for path in (REPO / "src").rglob("*.py"):
        assert not re.search(r"^\s*(import|from) atheris", path.read_text(), re.M), path
