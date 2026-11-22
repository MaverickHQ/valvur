"""R48.6: no test, script or workflow compares against a moving target (Requirement 15.2).

The Dockerfile pins each base by digest, with its tag beside it, and the workflows pin each
action by commit. Anything that names the same image or action by a tag alone gets whatever
the tag holds that day: the licence check diffed the image against the base's tag as Docker
Hub served it, not against the base the image was built from. So a reference by tag to an
image the Dockerfile pins, or to an action a workflow pins, is refused. So is `:latest` of
valvur's own image, which is by definition the one that moves, unless the file is on the
list below with its reason.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
WHERE = ("tests", "scripts", ".github")
#: The fixtures are scanned, not run; and this file names what it refuses.
SKIPPED = ("tests/fixtures/", "tests/test_no_moving_target.py")
OURS = "ghcr.io/maverickhq/valvur:latest"
_PIN = re.compile(r"^FROM (\S+?:[^\s@]+)@sha256:[0-9a-f]{64}", re.M)
_USES = re.compile(r"\buses:\s*([\w.-]+/[\w.-]+)[\w./-]*@([\w./-]+)")
_COMMIT = re.compile(r"[0-9a-f]{40}")

#: (file, what it names) to why it may: each a tag read on purpose.
EXCEPTIONS: dict[tuple[str, str], str] = {
    (".github/workflows/acceptance.yml", OURS):
        "the nightly judges the image users pull today, which is this tag",
    (".github/workflows/watchdog.yml", OURS):
        "the watchdog reads each Scanner's Go from the image users pull today",
    ("tests/test_image_gate_workflows.py", OURS):
        "asserts that the nightly reads this tag, and nothing is pulled",
    ("tests/test_watchdog_scanners.py", OURS):
        "asserts that the watchdog reads this tag, and nothing is pulled",
    (".github/workflows/release.yml", "python:3.12-alpine3.24"):
        "the owner's file: the argument is dropped in the owner's sitting, as CI dropped it",
}


def _files(root: Path):
    for top in WHERE:
        for path in sorted((root / top).rglob("*")):
            name = path.relative_to(root).as_posix()
            if not path.is_file() or name.startswith(SKIPPED):
                continue
            try:
                yield name, path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue


def moving(root: Path, exceptions: dict[tuple[str, str], str], ours: str = OURS) -> list[str]:
    """Each line under `tests/`, `scripts/` and `.github/` that names by a tag alone an
    image the Dockerfile pins by digest or an action a workflow pins by commit, or that
    names `ours`."""
    pinned = set(_PIN.findall((root / "Dockerfile").read_text(encoding="utf-8")))
    images = re.compile("|".join([*(rf"{re.escape(name)}(?![@\w.-])" for name in sorted(pinned)),
                                  rf"{re.escape(ours)}(?![\w.-])"]))
    files = list(_files(root))
    # An action runs from `.github/` alone: elsewhere a `uses:` is a fixture's text.
    used = {name: [_USES.findall(line) if name.startswith(".github/") else []
                   for line in lines] for name, lines in files}
    by_commit = {action for lines in used.values() for line in lines
                 for action, ref in line if _COMMIT.fullmatch(ref)}
    found = []
    for name, lines in files:
        for number, line in enumerate(lines, start=1):
            named = {*images.findall(line),
                     *(f"{action}@{ref}" for action, ref in used[name][number - 1]
                       if action in by_commit and not _COMMIT.fullmatch(ref))}
            found += [f"{name}:{number}: names {one} by a tag that moves"
                      for one in sorted(named) if (name, one) not in exceptions]
    return found


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM base:1.2-alpine@sha256:" + "a" * 64 + " AS build\nFROM scratch\n")
    for top in WHERE:
        (tmp_path / top).mkdir()
    return tmp_path


def test_a_pinned_image_named_by_its_tag_alone_is_reported_with_its_line(tree):
    (tree / "scripts" / "check.py").write_text('ok = 1\nBASE = "base:1.2-alpine"\n')
    (tree / "tests" / "test_x.py").write_text('PIN = "base:1.2-alpine@sha256:' + "a" * 64 + '"\n'
                                              'OTHER = "base:1.2-alpine3"\nUNPINNED = "x:1"\n')

    assert moving(tree, {}) == ["scripts/check.py:2: names base:1.2-alpine by a tag that moves"]


def test_an_action_pinned_by_commit_in_one_place_and_by_tag_in_another_is_reported(tree):
    (tree / ".github" / "ci.yml").write_text(
        "      - uses: actions/checkout@" + "3" * 40 + " # v7\n"
        "      - uses: ./.github/actions/file-issue\n"
        "      - uses: other/never-pinned@v1\n")
    (tree / ".github" / "release.yml").write_text("      - uses: actions/checkout@v7\n")
    (tree / "tests" / "test_y.py").write_text('FIXTURE = "- uses: actions/checkout@v4"\n')

    assert moving(tree, {}) == [
        ".github/release.yml:1: names actions/checkout@v7 by a tag that moves"]


def test_latest_of_our_own_image_is_reported(tree):
    (tree / ".github" / "ci.yml").write_text(
        "run: docker pull ghcr.io/owner/tool:latest\nrun: docker pull ghcr.io/owner/other:latest\n"
        "run: docker pull ghcr.io/owner/tool:latest-arm64\n")

    assert moving(tree, {}, ours="ghcr.io/owner/tool:latest") == [
        ".github/ci.yml:1: names ghcr.io/owner/tool:latest by a tag that moves"]


def test_a_file_on_the_list_is_not_reported(tree):
    (tree / "scripts" / "check.py").write_text('BASE = "base:1.2-alpine"\n')

    assert moving(tree, {("scripts/check.py", "base:1.2-alpine"): "read on purpose"}) == []


def test_on_this_repository_nothing_moves_but_what_the_list_names():
    assert moving(REPO, EXCEPTIONS) == []


def test_every_exception_has_a_reason_and_is_still_needed():
    for (name, named), reason in EXCEPTIONS.items():
        assert len(reason.split()) >= 4, f"{name} {named}: say why"
    found = moving(REPO, {})
    unused = [key for key in EXCEPTIONS
              if not any(line.startswith(f"{key[0]}:") and f" names {key[1]} by " in line
                         for line in found)]
    assert unused == []


def test_the_licence_check_reads_the_base_the_image_was_built_from():
    from check_image_licences import DOCKERFILE, base_of

    final = [line.split()[1] for line in DOCKERFILE.read_text().splitlines()
             if line.startswith("FROM ")][-1]
    assert base_of(DOCKERFILE.read_text()) == final and "@sha256:" in final
    with pytest.raises(ValueError, match="not pinned by digest"):
        base_of("FROM base:1.2-alpine\n")
