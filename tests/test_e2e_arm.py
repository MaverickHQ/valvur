"""R16.1: the arm64 e2e leg (D38).

The image is published for amd64 and arm64, and the Mac every phase is measured on
is arm64, but CI's e2e job ran on x86 alone. It gains an arm leg (`ubuntu-26.04-arm`
since R19), Docker only: podman and the parity guard stay the x86 leg's. The x86 leg keeps its name,
since `main`'s protection requires a check by that name.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CI = (REPO / ".github" / "workflows" / "ci.yml").read_text()


def _job(name: str) -> str:
    start = CI.index(f"\n  {name}:\n")
    following = re.search(r"\n  [a-z][\w-]*:\n", CI[start + 1:])
    return CI[start:start + 1 + following.start()] if following else CI[start:]


def _step(job: str, name: str) -> str:
    start = job.index(f"- name: {name}")
    following = job.find("\n      - ", start + 1)
    return job[start:following if following != -1 else len(job)]


def test_the_e2e_job_runs_on_x86_and_on_arm():
    job = _job("e2e")

    assert "runs-on: ${{ matrix.runner }}" in job
    assert re.search(r"runner: ubuntu-26\.04\n", job)
    assert re.search(r"runner: ubuntu-26\.04-arm\n", job)
    assert "fail-fast: false" in job          # one leg failing never hides the other


def test_the_x86_leg_keeps_the_name_mains_protection_requires():
    job = _job("e2e")

    assert "name: ${{ matrix.name }}" in job
    assert re.search(r"name: end-to-end \(real container\)\n", job)
    assert re.search(r"name: end-to-end \(real container, arm64\)\n", job)


def test_podman_and_its_parity_guard_are_the_x86_legs_alone():
    job = _job("e2e")

    for step in ("Make the image visible to podman", "Runtime parity actually ran"):
        assert "if: matrix.podman" in _step(job, step), step
