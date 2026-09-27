"""R3.2: the File Set (ADR-0021), on real temporary git repositories.

The git view — tracked files and untracked files git does not ignore — plus the
ignored files an agent obeys or a secret hides in, minus the project's excludes.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from valvur import fileset


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                    *args], cwd=root, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
                        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin",
                        "HOME": str(root)})


def _repo(tmp_path: Path, files: dict[str, str], *, gitignore: str = "") -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    if gitignore:
        (root / ".gitignore").write_text(gitignore)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def test_the_git_view_is_tracked_and_untracked_not_ignored_files_never_git(tmp_path):
    root = _repo(tmp_path, {"src/app.py": "x = 1\n", "data/big.json": "{}\n"},
                 gitignore="data/\n")
    (root / "new.py").write_text("y = 2\n")                 # untracked, not ignored
    built = fileset.build(root)
    assert built.scope == "git"
    assert built.files == [".gitignore", "new.py", "src/app.py"]
