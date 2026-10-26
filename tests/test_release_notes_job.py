"""TASKLIST-1.6.0 E2: the release run keeps each leg's image verdict, and says what it does not fix.

`artifact` judges the staged image on each architecture (R43.4, N2.7); it now keeps that
verdict as `image-gate-<arch>`, even when it blocks. `notes` renders both with
`scripts/release_notes_image.py` before the brake, so a rehearsal proves it, and
`promote` only downloads the section first and copies it into the GitHub release's notes.
Rendering inside `promote` was rejected: a rehearsal is cancelled at the brake, so a
broken step there would first fail in the real release, after PyPI.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RELEASE = REPO / ".github" / "workflows" / "release.yml"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
GATE_STEP = "The staged image, scanned as it ships (R43.4, N2.7)"


def _job(name: str) -> str:
    text = RELEASE.read_text()
    start = re.search(rf"^  {re.escape(name)}:\n", text, re.M)
    assert start, f"no job {name}"
    end = re.search(r"^  [a-z][a-z-]*:\n", text[start.end():], re.M)
    return text[start.start(): start.end() + (end.start() if end else len(text))]


def _steps(job: str) -> list[str]:
    """The job's steps, each from its `- ` to the next."""
    body = job[job.index("    steps:\n"):]
    return ["      - " + step for step in re.split(r"^      - ", body, flags=re.M)[1:]]


def test_artifact_writes_each_architecture_s_verdict():
    steps = _steps(_job("artifact"))
    gate = next(step for step in steps if f"name: {GATE_STEP}\n" in step)

    assert ('python3 scripts/image_gate.py "$RUNNER_TEMP/image-scan.json" '
            '--out "$RUNNER_TEMP/image-gate.json"') in gate


def test_artifact_uploads_the_verdict_and_the_scan_even_when_the_gate_blocks():
    steps = _steps(_job("artifact"))
    index = next(i for i, step in enumerate(steps) if f"name: {GATE_STEP}\n" in step)
    upload = steps[index + 1]

    assert upload.startswith(f"      - uses: {UPLOAD} ")
    assert "        if: always()\n" in upload
    assert "          name: image-gate-${{ matrix.arch }}\n" in upload
    assert "${{ runner.temp }}/image-scan.json" in upload
    assert "${{ runner.temp }}/image-gate.json" in upload
