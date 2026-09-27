"""R3.7: secrets in history (D3; F2.1, P2; ADR-0021).

The host writes each commit's added lines into a file in valvur's scratch
directory, on all refs, bounded at 5,000 commits or 200 MB, and keeps where each
commit's lines for each path begin, so a Gitleaks hit maps back to both. Only
added lines: a removed line was added by an earlier commit, which is scanned.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from valvur import history

KEY = "AKIAV7Q2XR4TVBN6WLKJ"


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=env).stdout.strip()


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "commit.gpgsign", "false")
    return root


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _line_of(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines(), start=1) if needle in line)


def test_a_removed_secret_is_in_the_history_with_its_commit_and_path(repo, tmp_path):
    added = _commit(repo, {"config.py": f"KEY = '{KEY}'\n"}, "add a key")
    _commit(repo, {"config.py": "KEY = ''\n"}, "remove it")
    written = history.write(repo, tmp_path / "history.txt")
    assert written is not None
    text = written.path.read_text()
    assert text.count(KEY) == 1                       # added once; the removal is not a line
    assert written.locate(_line_of(text, KEY)) == (added, "config.py")
    assert written.commits == 2
    assert written.bounded is None
    assert written.bytes == len(written.path.read_bytes())


def test_every_ref_is_read_not_only_the_branch_checked_out(repo, tmp_path):
    _commit(repo, {"app.py": "x = 1\n"}, "first")
    _git(repo, "checkout", "-q", "-b", "side")
    side = _commit(repo, {"deploy/keys.py": f"KEY = '{KEY}'\n"}, "a key on a side branch")
    _git(repo, "checkout", "-q", "main")
    written = history.write(repo, tmp_path / "history.txt")
    assert written is not None
    text = written.path.read_text()
    assert written.locate(_line_of(text, KEY)) == (side, "deploy/keys.py")


def test_each_path_in_a_commit_maps_to_itself(repo, tmp_path):
    sha = _commit(repo, {"a b/ü.py": "first = 1\n", "z.py": f"KEY = '{KEY}'\n"}, "two files")
    written = history.write(repo, tmp_path / "history.txt")
    assert written is not None
    text = written.path.read_text()
    assert written.locate(_line_of(text, "first = 1")) == (sha, "a b/ü.py")
    assert written.locate(_line_of(text, KEY)) == (sha, "z.py")


def test_past_the_commit_bound_the_newest_are_read_and_the_bound_is_named(repo, tmp_path):
    for i in range(3):
        _commit(repo, {f"f{i}.py": f"n = {i}\n"}, f"commit {i}")
    written = history.write(repo, tmp_path / "history.txt", max_commits=2)
    assert written is not None
    assert written.commits == 2
    assert written.bounded == "the 2-commit bound"
    assert "n = 0" not in written.path.read_text()     # the oldest was not read


def test_past_the_byte_bound_writing_stops_and_the_bound_is_named(repo, tmp_path):
    for i in range(5):
        _commit(repo, {f"f{i}.py": "x" * 1000 + "\n"}, f"commit {i}")
    written = history.write(repo, tmp_path / "history.txt", max_bytes=2500)
    assert written is not None
    assert written.bounded == "the 2,500-byte bound"
    assert written.bytes <= 2500
    assert written.commits < 5


def test_a_directory_that_is_not_a_repository_has_no_history(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert history.write(plain, tmp_path / "history.txt") is None


def test_the_bounds_are_the_decisions(repo):
    assert history.MAX_COMMITS == 5000
    assert history.MAX_BYTES == 200 * 2**20
