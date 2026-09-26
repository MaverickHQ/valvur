"""A reproducible image (28.4.5, B3).

No `SOURCE_DATE_EPOCH`, no `rewrite-timestamp`: the same tree yielded a different
digest per build, so trust rested on the OIDC identity and the tree hash rather
than on anyone's ability to rebuild and compare. Now every build gets the
commit's timestamp for every file in every layer, the base layers included, and
every caller passes it. What that buys is measured in the STATUS note: two
builds of one tree, the second without cache, layer by layer.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BAKE = REPO / "docker-bake.hcl"
WORKFLOWS = REPO / ".github" / "workflows"


def _bake_target(name: str) -> str:
    text = BAKE.read_text(encoding="utf-8")
    start = text.index(f'target "{name}"')
    end = text.find("\ntarget ", start + 1)
    return text[start:end if end > 0 else None]


def test_the_bake_file_dates_every_layer_from_one_timestamp():
    text = BAKE.read_text(encoding="utf-8")
    assert re.search(r'variable "SOURCE_DATE_EPOCH"', text), "no SOURCE_DATE_EPOCH variable"
    dev = _bake_target("dev")
    assert re.search(r"SOURCE_DATE_EPOCH\s*=\s*SOURCE_DATE_EPOCH", dev), \
        "the dev target does not pass SOURCE_DATE_EPOCH as a build argument"
    assert "rewrite-timestamp=true" in dev, "the dev target's output keeps the base layers' mtimes"
    release = _bake_target("release")
    assert "rewrite-timestamp=true" in release, "the release output keeps the base layers' mtimes"
    assert 'inherits = ["dev"]' in release, "the release target no longer takes dev's arguments"


def test_every_workflow_build_passes_the_commits_timestamp():
    """Four call sites in three workflows. `git log -1 --format=%ct` is the
    commit's time, the same on every machine that checks the commit out — the
    property the variable exists for."""
    calls = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"docker buildx bake", text):
            window = text[max(0, match.start() - 400):match.start()]
            calls.append((path.name, "SOURCE_DATE_EPOCH" in window
                          and "git log -1 --format=%ct" in window))
    assert len(calls) >= 4, calls
    assert all(passed for _, passed in calls), \
        f"a build without the commit's timestamp: {[n for n, ok in calls if not ok]}"


def test_the_contributor_command_passes_it_too():
    text = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")
    command = next(line for line in text.splitlines() if "docker buildx bake" in line)
    assert "SOURCE_DATE_EPOCH=" in command, command


def test_ci_builds_twice_without_cache_and_compares():
    """The test the task asks for, where it can run: a job that builds the tree
    twice with no cache and fails unless the two images are one."""
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("\n  reproducible:", 1)
    assert len(job) == 2, "ci.yml has no reproducible job"
    body = job[1].split("\n  selfscan:", 1)[0]
    assert body.count("docker buildx bake dev --no-cache") == 1
    assert "for tag in first second" in body
    assert 'test "$first" = "$second"' in body


def test_the_bytecode_is_compiled_in_hash_mode_with_a_fixed_seed():
    """Measured on the way (28.4.5): with the timestamp fixed, all 5,533 `.pyc`
    files still differed between two builds — pip had written timestamp-mode
    bytecode and `compileall` without `-f` left it; then the marshalled
    constants' order followed the process's hash seed."""
    dockerfile = "\n".join(line for line in (REPO / "Dockerfile").read_text().splitlines()
                            if not line.lstrip().startswith("#"))
    compiles = [line for line in dockerfile.splitlines() if "compileall" in line]
    assert len(compiles) == 2, compiles
    for line in compiles:
        assert "PYTHONHASHSEED=0" in line and "-f" in line and "unchecked-hash" in line, line
        assert "-j" not in line.split("compileall", 1)[1].split("--")[0], "parallel workers reseed"
    assert "--no-compile" in dockerfile, "pip still writes timestamp-mode bytecode"
