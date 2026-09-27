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


def test_ignored_agent_configuration_and_env_files_are_read_and_the_rest_named(tmp_path):
    root = _repo(tmp_path, {"app.py": "x = 1\n"},
                 gitignore=".env*\n.mcp.json\n.claude/\n.kiro/\ndata/\n")
    for name in (".env", ".env.local", ".mcp.json", ".claude/settings.local.json",
                 ".kiro/settings/mcp.json", "data/rows.json"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
    built = fileset.build(root)
    assert built.files == [".claude/settings.local.json", ".env", ".env.local",
                           ".gitignore", ".kiro/settings/mcp.json", ".mcp.json", "app.py"]
    assert ("data/", "ignored by git") in built.skipped


def test_a_large_ignored_directory_costs_a_bounded_search(tmp_path, monkeypatch):
    monkeypatch.setattr(fileset, "IGNORED_SEARCH_LIMIT", 10)
    root = _repo(tmp_path, {"app.py": "x = 1\n"}, gitignore="data/\nconfig/\n")
    for i in range(50):
        (root / "data").mkdir(exist_ok=True)
        (root / "data" / f"{i:02}.json").write_text("{}\n")
    (root / "config").mkdir()
    (root / "config" / ".env").write_text("TOKEN=x\n")
    built = fileset.build(root)
    assert "config/.env" in built.files
    assert any(path == "data/" and "as far as 10 files" in why for path, why in built.skipped)
