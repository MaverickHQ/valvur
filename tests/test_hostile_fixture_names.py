"""R48.7: the hostile fixtures are stored under names no agent loads (Requirement 15.3).

`tests/fixtures/broken-repo/` plants an `AGENTS.md`, a `CLAUDE.md`, an `.mcp.json` and a
`.claude/settings.json` for valvur to find: instructions written to mislead an agent, and a
server and hooks for one to start. An agent working in this repository loads files by
those names as its own. So each is stored as `<name>.fixture`, as the planted manifests are
(R27.2), and `scripts/fixtures.py` gives it its real name only in the copy a test scans.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from fixture_copy import copy_fixture

REPO = Path(__file__).resolve().parent.parent
#: What an agent client loads from a directory it works in, by name.
LOADED = re.compile(r"(^|/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.mcp\.json|\.cursorrules|"
                    r"\.windsurfrules|copilot-instructions\.md|"
                    r"(\.claude|\.cursor|\.kiro|\.codex|\.windsurf)/.*)$")
_STORED = re.compile(r"fixtures/broken-repo|FIXTURES? / \"broken-repo\"|\bBROKEN\b")
_THROUGH = re.compile(r"copy_fixture\(|fixtures\.copy\(|fixtures\.py broken-repo|^BROKEN = ")
#: A file that names the stored tree and reads nothing an agent would load from it.
NOT_READERS = {
    "tests/test_hostile_fixture_names.py": "the guard itself, which lists the stored names",
    "tests/test_fixture_manifests.py": "lists the stored names, which are its subject",
    "tests/test_noise.py": "a path as text, given to a function that opens nothing",
}


def readers(root: Path, not_readers: dict[str, str]) -> list[str]:
    """Each line under `tests/`, `scripts/` and `.github/` that reaches the stored
    `broken-repo` other than by handing it to the copier."""
    found = []
    for path in sorted([*root.glob("tests/*.py"), *root.glob("scripts/**/*.py"),
                        *root.glob(".github/**/*.yml")]):
        name = path.relative_to(root).as_posix()
        if name in not_readers:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = line.split("#", 1)[0] if path.suffix == ".py" else line
            if _STORED.search(code) and not _THROUGH.search(code.strip()):
                found.append(f"{name}:{number}: reads the stored broken-repo itself")
    return found


def test_a_copy_gives_a_stored_file_and_a_stored_directory_their_real_names(tmp_path):
    stored = tmp_path / "stored"
    (stored / ".claude.fixture" / "hooks.fixture").mkdir(parents=True)
    (stored / ".claude.fixture" / "settings.json").write_text("{}")
    (stored / ".claude.fixture" / "hooks.fixture" / "run.sh.fixture").write_text("true\n")
    (stored / ".mcp.json.fixture").write_text("{}")

    copied = copy_fixture(stored, tmp_path / "copy")

    assert sorted(p.relative_to(copied).as_posix() for p in copied.rglob("*")) == [
        ".claude", ".claude/hooks", ".claude/hooks/run.sh", ".claude/settings.json", ".mcp.json"]
    assert (stored / ".claude.fixture" / "settings.json").is_file(), "the stored tree is left"


def test_nothing_under_the_fixtures_is_stored_under_a_name_an_agent_loads():
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files", "tests/fixtures"],
                             capture_output=True, text=True, check=True).stdout.splitlines()

    assert [path for path in tracked if LOADED.search(path)] == []


def test_the_copy_a_test_scans_has_the_real_names(tmp_path):
    copied = copy_fixture("broken-repo", tmp_path / "ws")

    for name in ("AGENTS.md", "CLAUDE.md", ".mcp.json", ".claude/settings.json"):
        assert (copied / name).is_file(), name
    assert not [p for p in copied.rglob("*.fixture")]


def test_a_made_reader_of_the_stored_tree_is_reported(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(
        'ws = copy_fixture(FIXTURES / "broken-repo", tmp_path)\n'
        'text = (FIXTURES / "broken-repo" / "main.tf").read_text()\n'
        '# tests/fixtures/broken-repo is only named here\n')

    assert readers(tmp_path, {}) == ["tests/test_x.py:2: reads the stored broken-repo itself"]


def test_nothing_reads_the_stored_tree_but_through_the_copier():
    assert readers(REPO, NOT_READERS) == []
    for name, reason in NOT_READERS.items():
        assert (REPO / name).is_file() and len(reason.split()) >= 4, name
