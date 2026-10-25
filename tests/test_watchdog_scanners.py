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


#: Each Scanner's newest release upstream, as of 2026-10-25 (R47.1).
LATEST = {"gitleaks/gitleaks": ("v8.30.1", "2026-03-12T15:40:37Z"),
          "aquasecurity/trivy": ("v0.76.1", "2026-10-21T10:20:32Z"),
          "google/osv-scanner": ("v2.7.0", "2026-10-12T00:52:31Z"),
          "anchore/syft": ("v1.55.0", "2026-10-19T18:54:42Z"),
          "opengrep/opengrep": ("v1.29.0", "2026-08-20T10:00:00Z"),
          "zizmorcore/zizmor": ("v1.31.1", "2026-10-15T22:59:33Z"),
          "bridgecrewio/checkov": ("3.3.30", "2026-10-20T13:00:16Z")}
#: The Go each binary in the image was built with, before Gitleaks was built from source.
TOOLCHAINS = {"gitleaks": "go1.24.13", "trivy": "go1.27.1", "osv-scanner": "go1.27.0",
              "syft": "go1.26.8", "opengrep": None}


def _live(github: FakeGitHub, tree: Path, toolchains: dict) -> list[str]:
    for upstream, (tag, published) in LATEST.items():
        github.releases[upstream] = [_release(tag, published)]
    path = tree / "toolchains.json"
    path.write_text(__import__("json").dumps(toolchains))
    assert _watch(github, tree, "--toolchains", str(path), "--go-releases",
                  f"{github.url}/go") == 0
    return [i["title"] for i in github.issues if i["state"] == "open"]


def test_a_scanner_with_no_release_in_180_days_or_an_unsupported_go_keeps_one_issue(tree):
    with FakeGitHub() as github:
        assert _live(github, tree, TOOLCHAINS) == ["watchdog: Gitleaks liveness"]
        assert _live(github, tree, TOOLCHAINS) == ["watchdog: Gitleaks liveness"]

        [issue] = github.issues
        assert "no release in 226 days" in issue["body"]
        assert "go1.24.13" in issue["body"] and "go1.26 and go1.27" in issue["body"]

        # Built from source with a current Go: the release's age alone still holds it open.
        rebuilt = {**TOOLCHAINS, "gitleaks": "go1.27.3"}
        assert _live(github, tree, rebuilt) == ["watchdog: Gitleaks liveness"]
        assert "go1.24.13" not in issue["comments"][-1]

        github.releases["gitleaks/gitleaks"] = [_release("v8.31.0", "2026-10-01T00:00:00Z")]
        LATEST_NOW = dict(LATEST, **{"gitleaks/gitleaks": ("v8.31.0", "2026-10-01T00:00:00Z")})
        for upstream, (tag, published) in LATEST_NOW.items():
            github.releases[upstream] = [_release(tag, published)]
        path = tree / "toolchains.json"
        assert _watch(github, tree, "--toolchains", str(path), "--go-releases",
                      f"{github.url}/go") == 0

    assert issue["state"] == "closed"
