"""R43.2 (D81c): `6-self` scans the latest release, not a commit pinned by hand (N4.5).

`SELF_PIN` was moved by hand twice in three weeks, and the second time too late: the
nightly failed on 2026-10-20 and 2026-10-21 on advisories a release had not shipped yet
(#234). The repository is now the newest `v[0-9]*` tag reachable from HEAD, found as
`refresh.yml` finds it, and the report names the tag and its commit.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "acceptance" / "generate.py"


def _generate():
    spec = importlib.util.spec_from_file_location("acceptance_generate", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_generate"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _git(cwd: Path, *args: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "PATH": "/usr/bin:/bin:/usr/local/bin"}
    return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                           *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


def _release(repo: Path, version: str, text: str) -> str:
    (repo / "VERSION").write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"chore: release {version}")
    _git(repo, "tag", "-a", f"v{version}", "-m", version)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    return root


def test_the_newest_release_tag_is_archived_not_what_came_after(repo, tmp_path):
    _release(repo, "1.0.0", "one\n")
    second = _release(repo, "1.1.0", "two\n")
    (repo / "VERSION").write_text("unreleased\n")
    _git(repo, "commit", "-qam", "feat: after the release")
    _git(repo, "tag", "nightly-1")

    root = tmp_path / "6-self"
    root.mkdir()
    _generate().self_at_release(root, repo=repo)

    assert (root / "VERSION").read_text() == "two\n"
    run = tomllib.loads((root / "expected.toml").read_text())["run"]
    assert (run["tag"], run["commit"]) == ("v1.1.0", second)
    assert run["complete"] is True


def test_with_no_release_tag_reachable_generation_fails_and_says_why(repo, tmp_path):
    (repo / "VERSION").write_text("nothing released\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "feat: first")
    _git(repo, "tag", "nightly-1")

    with pytest.raises(RuntimeError, match=r"no tag matching v\[0-9\]\*"):
        _generate().self_at_release(tmp_path / "6-self", repo=repo)


def test_no_commit_is_hard_coded_for_6_self():
    """A forty-hex literal on `6-self`'s path is a pin moved by hand again."""
    import inspect

    generate = _generate()
    source = inspect.getsource(generate.self_at_release)

    assert not hasattr(generate, "SELF_PIN")
    assert not re.search(r"\b[0-9a-f]{40}\b", source)
    assert generate.BUILDERS["6-self"] is generate.self_at_release


def test_the_report_names_the_release_6_self_scanned(tmp_path):
    spec = importlib.util.spec_from_file_location("acceptance", REPO / "scripts" / "acceptance.py")
    acceptance = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance"] = acceptance
    spec.loader.exec_module(acceptance)  # type: ignore[union-attr]
    result = acceptance.RepoResult("6-self", acceptance.Verdict(), 1.0, 0,
                                   released=("v1.5.3", "91af75b" + "0" * 33))

    table = acceptance.render_markdown([result], {"platform": "test", "swap_gb": 0})
    report = acceptance.to_json([result], {"platform": "test"})

    assert "6-self scanned v1.5.3 (91af75b)" in table
    assert report["repositories"][0]["release"] == {"tag": "v1.5.3",
                                                    "commit": "91af75b" + "0" * 33}
