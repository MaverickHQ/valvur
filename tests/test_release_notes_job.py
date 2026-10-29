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
# The action, not its SHA: the pin has one home, the workflow, which Dependabot moves and
# `test_every_action_in_every_workflow_is_pinned_to_a_sha` holds to a SHA. A second copy
# here kept #255 red.
UPLOAD = re.compile(r"      - uses: actions/upload-artifact@[0-9a-f]{40} ")
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

    assert UPLOAD.match(upload), upload
    assert "        if: always()\n" in upload
    assert "          name: image-gate-${{ matrix.arch }}\n" in upload
    assert "${{ runner.temp }}/image-scan.json" in upload
    assert "${{ runner.temp }}/image-gate.json" in upload


def test_notes_follows_both_legs_and_holds_only_read():
    notes = _job("notes")

    assert re.search(r"^    needs: \[verify, artifact\]\n", notes, re.M)
    grant = re.search(r"^    permissions:\n((?:      .*\n)+)", notes, re.M)
    assert grant, "no job-level permissions"
    assert [line.split("#")[0].strip() for line in grant[1].splitlines()] == ["contents: read"]
    assert "environment:" not in notes, "the brake is promote's"
    uses = re.findall(r"uses: (\S+)", notes)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use) for use in uses), uses


def test_notes_renders_both_verdicts_and_keeps_the_section():
    notes = _job("notes")

    assert "python3 scripts/release_notes_image.py" in notes
    assert "gates/image-gate-amd64/image-gate.json" in notes
    assert "gates/image-gate-arm64/image-gate.json" in notes
    assert "          name: notes-image\n" in notes
    assert "          path: notes-image.md\n" in notes


def test_no_run_in_notes_interpolates_an_expression():
    runs = re.findall(r"run: \|\n((?:\s{10,}.*\n|\n)+)", _job("notes")) + \
        re.findall(r"run: (\S.*)\n", _job("notes"))

    assert runs and not any("${{" in run for run in runs)


def test_promote_waits_for_notes_and_downloads_it_first():
    promote = _job("promote")
    needs = re.search(r"^    needs: \[(.*)\]\n", promote, re.M)

    assert needs and "notes" in [name.strip() for name in needs[1].split(",")]
    steps = _steps(promote)
    assert "actions/checkout@" in steps[0]
    assert "download-artifact@" in steps[1] and "          name: notes-image\n" in steps[1]


def test_the_github_release_carries_the_section_before_the_changelog_link():
    create = next(step for step in _steps(_job("promote"))
                  if "name: Create the GitHub release\n" in step)

    section = create.index("cat notes-image.md")
    assert section < create.index('echo "See [CHANGELOG.md]')
    assert create.index("Image digest:") < section
