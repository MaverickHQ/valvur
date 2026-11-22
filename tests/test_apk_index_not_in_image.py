"""Alpine's repository index is not kept in the image.

apk-tools 3, on Alpine 3.24, writes each repository's index to `/var/cache/apk` even under
`--no-cache`: 1.6.1's image holds `APKINDEX.3cace40b.tar.gz` and `APKINDEX.5773bea6.tar.gz`,
3 MB dated the minute it was built. Alpine republishes an index whenever any package in the
repository moves, so two builds of one tree are one image only while it publishes nothing
between them. On 2026-11-21 it published at 15:11 UTC, a bootloader's packages, between the
two builds of `main` at f0e7150, and they differed (run 44916424890: sha256:7956f9db… and
sha256:1dc90306…). Each step that calls apk removes what apk cached, in the same layer.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CACHE = "/var/cache/apk"
EMPTIED = f"rm -f {CACHE}/*"


def _run_steps() -> list[str]:
    """Each `RUN` of the Dockerfile as one line, comments left out."""
    lines = [line for line in (REPO / "Dockerfile").read_text().splitlines()
             if not line.lstrip().startswith("#")]
    steps, step = [], None
    for line in lines:
        if step is None and line.startswith("RUN "):
            step = ""
        if step is not None:
            step += line.removesuffix("\\")
            if not line.endswith("\\"):
                steps.append(step)
                step = None
    return steps


def test_every_step_that_calls_apk_empties_its_cache_after_the_last_call():
    steps = [step for step in _run_steps() if re.search(r"\bapk (?:add|del)\b", step)]

    assert len(steps) == 1, steps  # the raise; Checkov's step calls apk no more (R44.10)
    for step in steps:
        last = max(m.start() for m in re.finditer(r"\bapk (?:add|del)\b", step))
        assert EMPTIED in step, step
        assert step.rindex(EMPTIED) > last, "apk runs again after the cache is emptied"


def _image() -> str:
    from valvur.engine_host import IMAGE

    return IMAGE


@pytest.mark.e2e
def test_the_image_holds_no_copy_of_alpines_index():
    said = subprocess.run(
        ["docker", "run", "--rm", _image(), "python3", "-c",
         f"import json, os; print(json.dumps(sorted(os.listdir('{CACHE}'))))"],
        capture_output=True, text=True, check=True).stdout

    assert json.loads(said) == []
