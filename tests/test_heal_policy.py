"""R44.4: a heal merges itself only inside its envelope (Requirement 8).

`scripts/heal_policy.py lock` judges a heal's pull request from the base branch: what it
changed and who committed it, on stdin, and its two files, in a directory, as data. It runs
the recipe on the base's lock with the commit's own pins and asks for the same bytes.
Resolution is real and hermetic (`heal_support.tree`).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from heal_support import HEAL, LOCK
from heal_support import tree as heal_tree

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="the recipe runs uv")

POLICY = HEAL.parent / "heal_policy.py"
OLD = {"uploaded": "2026-01-01T00:00:00Z"}
CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n"
PROJECTS = {"checkov": {"1.0": {**OLD, "requires": ["alpha", "beta"]},
                        "1.1": {**OLD, "requires": ["alpha", "beta"]}},
            "alpha": {"1.0": OLD, "1.1": {**OLD, "requires": ["gamma"]}},
            "beta": {"1.0": OLD, "1.1": OLD, "2.0": OLD},
            "gamma": {"1.0": OLD}}
HAVE = {"checkov": "1.0", "alpha": "1.0", "beta": "1.0"}


def _commit(message: str, *, author: str = "valvur-heal[bot]", committer: str = "web-flow",
            verified: bool = True) -> dict:
    return {"sha": "0" * 40, "author": {"login": author}, "committer": {"login": committer},
            "commit": {"message": message, "verification": {"verified": verified}}}


def _heal(tmp_path: Path, monkeypatch, pins: dict[str, str]) -> tuple[Path, Path, str]:
    """The base tree, and a heal of it as `heal.py apply` makes one: its two files in a
    directory, and its commit's message."""
    tree = heal_tree(tmp_path, monkeypatch, HAVE, PROJECTS, top=("checkov",))
    (tree / "CHANGELOG.md").write_text(CHANGELOG)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "schema": 1, "made": "2026-10-21T06:41:00Z", "lock": LOCK, "escalations": [],
        "findings": [{"rule": "CVE-2026-0001", "fingerprint": "fp", "package": name,
                      "version": HAVE[name], "fixed_version": version, "severity": "high",
                      "advisory_published": "2026-10-19T16:47:35Z"} for name, version in
                     pins.items()],
        "pins": [{"package": name, "from": HAVE[name], "to": version, "why": "fix",
                  "rule": "cooldown", "uploaded": "2026-10-01T00:00:00Z"}
                 for name, version in pins.items()]}))
    head = tmp_path / "head"
    made = subprocess.run([sys.executable, str(HEAL), "apply", "--plan", str(plan), "--tree",
                           str(tree), "--out", str(head), "--run", "https://example.invalid/1"],
                          capture_output=True, text=True, check=False)
    assert made.returncode == 0, made.stderr
    return tree, head, made.stdout


def _judge(tree: Path, head: Path, view: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(POLICY), "lock", "--base", str(tree),
                           "--head", str(head)], input=json.dumps(view),
                          capture_output=True, text=True, check=False)


def _view(message: str, *paths: str, **commit) -> dict:
    return {"files": [{"path": path} for path in paths or (LOCK, "CHANGELOG.md")],
            "commits": [_commit(message, **commit)]}


def test_a_heal_exactly_as_the_recipe_makes_it_is_eligible(tmp_path, monkeypatch):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})

    run = _judge(tree, head, _view(message))

    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.startswith("eligible")


def test_a_third_file_leaves_it_for_the_owner(tmp_path, monkeypatch):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})

    run = _judge(tree, head, _view(message, LOCK, "CHANGELOG.md", "scripts/heal_policy.py"))

    assert run.returncode == 1
    assert "scripts/heal_policy.py" in run.stdout


@pytest.mark.parametrize("commit, names", [
    ({"author": "someone-else"}, "someone-else"),
    ({"author": "valvur-heal"}, "valvur-heal"),
    ({"committer": "valvur-heal[bot]"}, "GitHub"),
    ({"verified": False}, "signature"),
])
def test_a_commit_the_app_did_not_make_through_github_leaves_it_for_the_owner(
        tmp_path, monkeypatch, commit, names):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})

    run = _judge(tree, head, _view(message, **commit))

    assert run.returncode == 1
    assert names in run.stdout


def test_a_commit_with_no_heal_pin_leaves_it_for_the_owner(tmp_path, monkeypatch):
    tree, head, _message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})

    run = _judge(tree, head, _view("fix: beta 1.1 in the Checkov lock, by hand\n"))

    assert run.returncode == 1
    assert "Heal-Pin" in run.stdout


def test_a_second_commit_is_held_to_the_same(tmp_path, monkeypatch):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    view = _view(message)
    view["commits"].append(_commit(message, author="a-collaborator"))

    run = _judge(tree, head, view)

    assert run.returncode == 1
    assert "a-collaborator" in run.stdout


def _drop_a_hash(lock: str) -> str:
    lines = lock.splitlines(keepends=True)
    index = next(i for i, line in enumerate(lines) if "--hash=sha256:" in line)
    return "".join(lines[:index] + lines[index + 1:])


@pytest.mark.parametrize("edit", [
    pytest.param(lambda lock: lock.replace("alpha==1.0", "alpha==1.0.1"), id="a-version-by-hand"),
    pytest.param(_drop_a_hash, id="a-hash-dropped"),
    pytest.param(lambda lock: lock + "    # a comment\n", id="a-line-added"),
    pytest.param(lambda lock: lock.replace("beta==1.1", "beta==1.0"), id="the-pin-not-applied"),
])
def test_a_lock_one_byte_from_the_recipes_leaves_it_for_the_owner(tmp_path, monkeypatch, edit):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    lock = head / LOCK
    lock.write_text(edit(lock.read_text()))

    run = _judge(tree, head, _view(message))

    assert run.returncode == 1
    assert "not what the recipe writes" in run.stdout


def _by_the_recipe(tmp_path: Path, monkeypatch, pins: dict[str, str]) -> tuple[Path, Path, str]:
    """A pull request whose lock the recipe did write, for pins a heal would never plan."""
    sys.path.insert(0, str(HEAL.parent))
    import heal

    tree, head, _message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    written = heal.relock(tree, (tree / LOCK).read_text(), pins)
    assert written is not None
    (head / LOCK).write_text(written)
    trailers = "".join(f"Heal-Pin: {name}=={version}\n" for name, version in pins.items())
    return tree, head, "fix: a move the envelope does not hold\n\n" + trailers


@pytest.mark.parametrize("pins, names", [
    ({"alpha": "1.1"}, "gamma"),
    ({"beta": "2.0"}, "major"),
    ({"checkov": "1.1"}, "Checkov"),
])
def test_a_move_outside_the_envelope_leaves_it_for_the_owner(tmp_path, monkeypatch, pins, names):
    tree, head, message = _by_the_recipe(tmp_path, monkeypatch, pins)

    run = _judge(tree, head, _view(message))

    assert run.returncode == 1
    assert names in run.stdout


def test_an_overridden_package_does_not_move(tmp_path, monkeypatch):
    """An override is a decision the owner wrote down, with its reason. A heal that moves
    the package it names is the owner's to read, even when the override allows the move
    and the recipe wrote the lock."""
    sys.path.insert(0, str(HEAL.parent))
    import heal

    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    (tree / "requirements-checkov.overrides").write_text("# why\nbeta>=1.0\n")
    written = heal.relock(tree, (tree / LOCK).read_text(), {"beta": "1.1"})
    assert written is not None
    (head / LOCK).write_text(written)

    run = _judge(tree, head, _view(message))

    assert run.returncode == 1
    assert "override" in run.stdout and "beta" in run.stdout


@pytest.mark.parametrize("edit, names", [
    pytest.param(lambda text: text.replace("The first.\n", ""), "removes", id="a-line-removed"),
    pytest.param(lambda text: text + "\nA line under 1.0.0.\n", "outside", id="added-below"),
    pytest.param(lambda text: text.replace("# Changelog\n", "# Changelog\n\nA new opening.\n"),
                 "outside", id="added-above"),
    pytest.param(lambda text: text.replace("## [Unreleased]\n", "## [Unreleased]\n\n## [9.9.9]\n"),
                 "outside", id="a-new-version-heading"),
])
def test_a_changelog_that_does_more_than_add_under_unreleased_leaves_it_for_the_owner(
        tmp_path, monkeypatch, edit, names):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    changelog = head / "CHANGELOG.md"
    changelog.write_text(edit(changelog.read_text()))

    run = _judge(tree, head, _view(message))

    assert run.returncode == 1
    assert "CHANGELOG" in run.stdout and names in run.stdout


def test_a_heal_that_leaves_the_changelog_alone_is_judged_on_its_lock(tmp_path, monkeypatch):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    (head / "CHANGELOG.md").unlink()

    run = _judge(tree, head, _view(message, LOCK))

    assert run.returncode == 0, run.stdout


@pytest.mark.parametrize("stdin", ["not json", "[]", "{}", '{"files": [], "commits": []}'])
def test_input_it_cannot_read_is_exit_two(tmp_path, monkeypatch, stdin):
    tree, head, _message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})

    run = subprocess.run([sys.executable, str(POLICY), "lock", "--base", str(tree),
                          "--head", str(head)], input=stdin, capture_output=True, text=True,
                         check=False)

    assert run.returncode == 2
    assert run.stdout.startswith("cannot judge")


def test_a_pull_request_whose_lock_is_missing_is_exit_two(tmp_path, monkeypatch):
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    (head / LOCK).unlink()

    assert _judge(tree, head, _view(message)).returncode == 2


def test_nothing_beside_the_two_files_is_read_or_run(tmp_path, monkeypatch):
    """The pull request's directory is data. A recipe, a `sitecustomize`, a uv
    configuration and requirements planted in it change nothing and run nothing."""
    tree, head, message = _heal(tmp_path, monkeypatch, {"beta": "1.1"})
    marker = tmp_path / "ran"
    (head / "scripts").mkdir()
    trap = head / "scripts" / "lock-checkov.sh"
    trap.write_text(f"#!/bin/sh\ntouch {marker}\n")
    (head / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').close()\n")
    (head / "heal.py").write_text(f"open({str(marker)!r}, 'w').close()\n")
    (head / "uv.toml").write_text("[pip]\nno-index = false\n")
    (head / "requirements-checkov.in").write_text("checkov\nsomething-else\n")
    (head / "requirements-checkov.overrides").write_text("beta==2.0\n")

    run = _judge(tree, head, _view(message))

    assert run.returncode == 0, run.stdout
    assert not marker.exists()
    subprocess.run(["sh", str(trap)], check=True)
    assert marker.exists(), "the trap works when it is run"
