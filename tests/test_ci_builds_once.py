"""R24.4: CI builds once (D55c, d).

A pull request built the image five times in `ci.yml` (R24.1): once in each e2e
job, once for the self-scan, and twice to compare. Each architecture builds it
once now, the jobs that need it load that build, and only the reproducibility
comparison's second build is made again. The version is read in one place and the
issue a failure gets is filed by one action, and the checks `main`'s branch
protection requires keep their names, since protection is the owner's to change.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"


def _jobs(text: str) -> dict[str, str]:
    """Each job's block of a workflow, by its key: the project has no YAML parser
    among its dependencies, and its workflows keep one shape."""
    body = text.split("\njobs:\n", 1)[1]
    keys = list(re.finditer(r"^  ([a-z][\w-]*):$", body, re.M))
    return {k[1]: body[k.end():keys[i + 1].start() if i + 1 < len(keys) else len(body)]
            for i, k in enumerate(keys)}


CI = _jobs((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))


def _required() -> set[str]:
    """The checks `main`'s protection requires, read from it on 2026-10-03 (R24.1) and
    kept where the release reads them back (R26.3)."""
    spec = importlib.util.spec_from_file_location("ci_verdict",
                                                  REPO / "scripts" / "ci_verdict.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return set(module.REQUIRED)


REQUIRED = _required()


def _legs(job: str) -> list[dict[str, str]]:
    """One dict of matrix values per leg the job runs: `include` entries, or the
    product of list axes such as `python: ["3.11", "3.13"]`."""
    matrix = job.split("      matrix:\n", 1)
    if len(matrix) == 1:
        return [{}]
    block = matrix[1].split("\n    steps:", 1)[0].split("\n    runs-on:", 1)[0]
    legs: list[dict[str, str]] = []
    for line in block.splitlines():
        entry = re.match(r"^ {10}- (\w+): (.+)$", line)
        more = re.match(r"^ {12}(\w+): (.+)$", line)
        axis = re.match(r"^ {8}(\w+): \[(.+)\]$", line)
        if entry:
            legs.append({entry[1]: entry[2].strip('"')})
        elif more and legs:
            legs[-1][more[1]] = more[2].strip('"')
        elif axis:
            values = [v.strip().strip('"') for v in axis[2].split(",")]
            legs = [{**leg, axis[1]: v} for leg in (legs or [{}]) for v in values]
    return legs or [{}]


def _names(job: str) -> set[str]:
    name = re.search(r"^    name: (.+)$", job, re.M)[1]
    found = set()
    for leg in _legs(job):
        label = name
        for key, value in leg.items():
            label = label.replace(f"${{{{ matrix.{key} }}}}", value)
        found.add(label)
    return found


def _builds(job: str) -> int:
    return job.count("docker buildx bake") * len(_legs(job))


def test_a_pull_request_builds_the_image_at_most_three_times():
    builds = {name: _builds(job) for name, job in CI.items() if _builds(job)}
    assert builds == {"image": 2, "reproducible": 1}, builds


def test_the_jobs_that_need_the_image_load_the_commits_build():
    for name in ("e2e", "selfscan", "reproducible"):
        job = CI[name]
        assert "\n    needs: image\n" in job, name
        # A job skipped because its build failed would count as a passed check.
        assert "\n    if: ${{ !cancelled() }}\n" in job, name
        assert "if: needs.image.result != 'success'" in job, name
        assert "uses: actions/download-artifact@" in job and "docker load" in job, name


def test_one_action_reads_the_version_and_one_files_the_issue():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"=\$\(grep -m1 '\^version' pyproject\.toml", text), path.name
        for step in text.split("\n      - ")[1:]:
            if re.search(r"^\s*if: failure\(\)", step, re.M) and "gh issue" not in step \
                    and "file-issue" not in step:
                continue
            if re.search(r"^\s*if: failure\(\)", step, re.M):
                assert "uses: ./.github/actions/file-issue" in step, path.name
    assert (REPO / ".github" / "actions" / "version" / "action.yml").is_file()


def test_the_required_checks_keep_their_names():
    names = set()
    for job in CI.values():
        names |= _names(job)
    assert REQUIRED <= names, sorted(REQUIRED - names)
