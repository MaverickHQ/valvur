"""R42.5, extended (D81s, D81d): the watchdog watches what Dependabot cannot (N3.10).

Dependabot follows a Scanner pinned as an image or in a requirements file. Opengrep is
neither: the image takes its release from a URL in an `ARG`, which no ecosystem reads, so
its releases arrive unseen. And no ecosystem notices a Scanner that has stopped: Gitleaks
8.30.1, released 2026-03-12, still runs a binary built with go1.24.13, which Go stopped
supporting when go1.26 was released. So the watchdog reads each Scanner's releases
upstream, and the Go each binary was built with, and keeps an issue for each. GitHub is
faked on loopback, and so is go.dev's list of supported releases.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest
from fake_github import FakeGitHub

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "watchdog.py"
NOW = "2026-10-25T07:00:00Z"


def _script():
    spec = importlib.util.spec_from_file_location("watchdog", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["watchdog"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _release(tag: str, published: str, **extra) -> dict:
    return {"tag_name": tag, "published_at": published, "draft": False, "prerelease": False,
            "html_url": f"https://github.com/opengrep/opengrep/releases/tag/{tag}", **extra}


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """The files the image's pins are read from, with Opengrep pinned at 1.29.0."""
    root = tmp_path / "tree"
    root.mkdir()
    for name in ("Dockerfile", "requirements-checkov.txt", "requirements-zizmor.txt"):
        shutil.copy(REPO / name, root / name)
    _pin_opengrep(root, "1.29.0")
    (root / "workflows").mkdir()
    return root


def _pin_opengrep(root: Path, version: str) -> None:
    dockerfile = root / "Dockerfile"
    dockerfile.write_text(re.sub(r"(?m)^(ARG OPENGREP_URL=\S+/download/v)[\d.]+$",
                                 rf"\g<1>{version}", dockerfile.read_text()))


def _watch(github: FakeGitHub, root: Path, *extra: str) -> int:
    return _script().main(["--repo", github.repo, "--api", github.url, "--now", NOW,
                           "--workflows", str(root / "workflows"), "--scanners",
                           "--root", str(root), *extra])


def test_an_opengrep_release_past_the_cooldown_files_one_issue_naming_it(tree):
    with FakeGitHub() as github:
        github.releases["opengrep/opengrep"] = [
            _release("v1.32.0", "2026-10-22T10:54:06Z"),      # three days old: cooling down
            _release("v1.31.0", "2026-10-15T11:35:42Z"),
            _release("v1.30.0", "2026-09-07T10:19:45Z"),
        ]

        assert _watch(github, tree, "--dry-run") == 0
        assert github.writes == []
        assert _watch(github, tree) == 0
        assert _watch(github, tree) == 0                       # the next day: no second issue

    opengrep = [i for i in github.issues if i["title"] == "watchdog: Opengrep 1.31.0"]
    assert len(opengrep) == 1 and opengrep[0]["state"] == "open"
    assert "1.29.0" in opengrep[0]["body"] and "1.31.0" in opengrep[0]["body"]
    assert "v1.31.0" in opengrep[0]["body"]                     # its release, linked
    assert not any("1.32.0" in i["title"] for i in github.issues)


def test_a_later_run_closes_it_once_the_pin_moves(tree):
    with FakeGitHub() as github:
        github.releases["opengrep/opengrep"] = [_release("v1.31.0", "2026-10-15T11:35:42Z")]
        assert _watch(github, tree) == 0
        [issue] = github.issues

        _pin_opengrep(tree, "1.31.0")
        assert _watch(github, tree) == 0

    assert issue["state"] == "closed"
    assert issue["comments"] == ["The image pins Opengrep 1.31.0 now."]
    assert len(github.issues) == 1
