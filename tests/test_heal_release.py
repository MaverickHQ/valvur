"""R45.2: when the heal may prepare a release by itself (Requirement 9, D81g).

`scripts/heal_release.py check` reads the commits since the latest tag and what they
changed. A security patch is a patch: every commit is patch-class, and the only release
machinery that moved is the Checkov lock. Anything else is the owner's release to cut, and
is escalated as `release-needs-owner`. Each case is a repository made in `tmp_path`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HEAL_RELEASE = REPO / "scripts" / "heal_release.py"
HEAL = ("fix: beta 1.1 in the Checkov lock, by the heal\n\nHeal-Pin: beta==1.1\n"
        "Heal-Advisory: CVE-2026-0001 beta published 2026-10-19T16:47:35Z\n"
        "Heal-Run: https://example.invalid/1\n")


LOCKED = {"requirements-checkov.txt": "alpha==2.0 \\\n    --hash=sha256:00\n"
                                      "beta==1.1 \\\n    --hash=sha256:00\n"}


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for key, value in (("user.name", "t"), ("user.email", "t@example.invalid"),
                       ("commit.gpgsign", "false"), ("tag.gpgsign", "false"),
                       ("core.hooksPath", "/dev/null")):
        _git(root, "config", key, value)
    (root / "requirements-checkov.txt").write_text("alpha==2.0 \\\n    --hash=sha256:00\n"
                                                   "beta==1.0 \\\n    --hash=sha256:00\n")
    (root / "pyproject.toml").write_text('[project]\nname = "valvur"\nversion = "1.0.0"\n')
    (root / "Dockerfile").write_text("FROM scratch\n")
    (root / "app.py").write_text("print(1)\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "chore: release 1.0.0")
    _git(root, "tag", "v1.0.0")
    return root


def _commit(root: Path, message: str, **files: str) -> None:
    for name, text in (files or {"app.py": f"# {message}\n"}).items():
        path = root / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)


def _check(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(HEAL_RELEASE), "check", "--since", "v1.0.0",
                           "--root", str(root), *args], capture_output=True, text=True,
                          check=False)


def test_heal_dependabot_and_patch_class_commits_since_the_tag_are_eligible(repo):
    _commit(repo, HEAL, **LOCKED)
    _commit(repo, "chore: bump the dev-dependencies group with 3 updates (#299)")
    _commit(repo, "fix(r44.10): the image no longer records the day it was built")
    _commit(repo, "docs: a sentence")
    _commit(repo, "test(r1): one more")
    _commit(repo, "ci: a pinned action")
    _commit(repo, "refactor(r1): no behaviour moved")

    run = _check(repo)

    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.startswith("eligible: 7 commits since v1.0.0")


@pytest.mark.parametrize("message, names", [
    ("feat: a new command", "feat"),
    ("feat(r50.2): scan --ref", "feat"),
    ("fix!: the reply's schema moves", "!"),
    ("fix(api)!: the reply's schema moves", "!"),
    ("fix: a field renamed\n\nBREAKING CHANGE: the reply's schema moves", "BREAKING CHANGE"),
    ("Update README", "not a Conventional Commit"),
    ("revert: the last fix", "revert"),
])
def test_a_commit_that_is_not_patch_class_is_release_needs_owner(repo, message, names):
    _commit(repo, HEAL, **LOCKED)
    _commit(repo, message)

    run = _check(repo)

    assert run.returncode == 1
    assert run.stdout.startswith("release-needs-owner: ") and names in run.stdout


@pytest.mark.parametrize("path", ["Dockerfile", "docker-bake.hcl", "hatch_build.py",
                                  ".github__workflows__release.yml",
                                  "requirements-zizmor.txt"])
def test_any_other_release_machinery_changed_is_release_needs_owner(repo, path):
    _commit(repo, HEAL, **LOCKED)
    _commit(repo, "fix: a change to how the release is built", **{path: "changed\n"})

    run = _check(repo)

    assert run.returncode == 1
    assert path.replace("__", "/") in run.stdout


def test_no_commit_since_the_tag_is_nothing_to_release(repo):
    run = _check(repo)

    assert run.returncode == 1 and "no commit since v1.0.0" in run.stdout


def test_a_tag_that_does_not_exist_is_exit_two(repo):
    run = subprocess.run([sys.executable, str(HEAL_RELEASE), "check", "--since", "v9.9.9",
                          "--root", str(repo)], capture_output=True, text=True, check=False)

    assert run.returncode == 2


def test_a_release_with_no_heal_commit_in_it_is_the_owners(repo):
    _commit(repo, "docs: a sentence")
    _commit(repo, "fix: something by hand")

    run = _check(repo)

    assert run.returncode == 1 and "no heal commit since v1.0.0" in run.stdout


IMAGE = ("fix: tzdata 2026b-r0 and Go 1.27.6 in the image, by the heal\n\n"
         "Heal-Go: golang:1.27.6-alpine3.24@sha256:" + "c" * 64 + "\n"
         "Heal-Raise: ALPINE_RAISE tzdata=2026b-r0\n"
         "Heal-Raise: TRIVY_RAISE golang.org/x/net@v0.62.0\n"
         "Heal-Advisory: CVE-2026-0003 tzdata\nHeal-Advisory: CVE-2026-97054 go\n"
         "Heal-Run: https://example.invalid/2\n")


def _opening(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(HEAL_RELEASE), "opening", "--since", "v1.0.0",
                           "--root", str(root)], capture_output=True, text=True, check=False)


def test_the_opening_is_one_template_filled_from_the_heal_commits(repo):
    _commit(repo, HEAL, **LOCKED)
    _commit(repo, "docs: a sentence")

    run = _opening(repo)

    assert run.returncode == 0, run.stderr
    assert " ".join(run.stdout.split()) == (
        "A security patch, released by the heal (ADR-0032): beta 1.0 to 1.1 in the Checkov "
        "lock, past CVE-2026-0001.")
    assert run.stdout.endswith(".\n")


def test_the_opening_names_the_images_changes_too_and_wraps_as_the_changelog_does(repo):
    _commit(repo, HEAL, **LOCKED)
    _commit(repo, IMAGE)

    said = _opening(repo).stdout

    assert " ".join(said.split()) == (
        "A security patch, released by the heal (ADR-0032): beta 1.0 to 1.1 in the Checkov "
        "lock; Go 1.27.6, tzdata 2026b-r0 and golang.org/x/net v0.62.0 in Trivy, in the "
        "image; past CVE-2026-0001, CVE-2026-0003 and CVE-2026-97054.")
    assert all(len(line) <= 96 for line in said.splitlines())
    assert _opening(repo).stdout == said


def _release(root: Path, version: str) -> None:
    _commit(root, f"chore: release {version}",
            **{"pyproject.toml": f'[project]\nname = "valvur"\nversion = "{version}"\n'})
    _git(root, "tag", f"v{version}")


def _verify(root: Path, tag: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(HEAL_RELEASE), "verify", "--tag", tag,
                           "--root", str(root)], capture_output=True, text=True, check=False)


def test_verify_is_check_up_to_the_tag_and_the_patch_plus_one_rule(repo):
    _commit(repo, HEAL, **LOCKED)
    _release(repo, "1.0.1")
    _commit(repo, "feat: after the tag, and none of its business")

    run = _verify(repo, "v1.0.1")

    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.startswith("eligible: v1.0.1 is v1.0.0's patch plus one")


@pytest.mark.parametrize("version, names", [("1.1.0", "patch plus one"),
                                            ("1.0.2", "patch plus one"),
                                            ("2.0.0", "patch plus one")])
def test_a_version_that_is_not_the_patch_plus_one_is_refused(repo, version, names):
    _commit(repo, HEAL, **LOCKED)
    _release(repo, version)

    run = _verify(repo, f"v{version}")

    assert run.returncode == 1 and names in run.stdout


def test_verify_refuses_history_that_check_refuses_and_a_tag_that_lies(repo):
    _commit(repo, HEAL, **LOCKED)
    _commit(repo, "feat: a new command")
    _release(repo, "1.0.1")
    feature = _verify(repo, "v1.0.1")
    again = {name: text.replace("1.1", "1.2") for name, text in LOCKED.items()}
    _commit(repo, HEAL.replace("1.1", "1.2"), **again)
    _git(repo, "tag", "v1.0.2")
    lying = _verify(repo, "v1.0.2")

    assert feature.returncode == 1 and "feat" in feature.stdout
    assert lying.returncode == 1 and "declares 1.0.1" in lying.stdout
