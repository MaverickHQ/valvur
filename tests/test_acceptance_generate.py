"""R2.1: the acceptance repositories are built from nothing, the same every time.

Repositories 5 and 6 are archives of pinned commits and are exercised by the
harness, not here: 5 needs a clone, and 6 is this repository.
"""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "acceptance" / "generate.py"
LOCAL = ("1", "2", "3", "4", "7", "8")


def _module():
    spec = importlib.util.spec_from_file_location("acceptance_generate", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_generate"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _fingerprint(root: Path) -> list[tuple[str, str]]:
    files = sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)
    return [(p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())
            for p in files]


def _head(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()


def test_two_builds_are_the_same_trees_with_the_same_commits(tmp_path):
    generate = _module()
    first, second = tmp_path / "a", tmp_path / "b"
    for number in LOCAL:
        generate.build(first, number, data_files=20)
        generate.build(second, number, data_files=20)
    for name in sorted(p.name for p in first.iterdir()):
        assert _fingerprint(first / name) == _fingerprint(second / name), name
        assert _head(first / name) == _head(second / name), name


def test_no_planted_credential_is_a_literal_in_this_repository():
    generate = _module()
    source = SCRIPT.read_text()
    key = "AKIA" + "QX3ZR5TW7YB2MN4P"
    assert key not in source
    tracked = subprocess.run(["git", "-C", str(REPO), "grep", "-lF", key],
                             capture_output=True, text=True, check=False).stdout
    assert tracked == "", tracked
    assert generate.MALICIOUS[2].startswith("MAL-")


def test_every_repository_says_what_it_expects(tmp_path):
    generate = _module()
    for number in LOCAL:
        (root,) = generate.build(tmp_path, number, data_files=5).values()
        expected = tomllib.loads((root / "expected.toml").read_text())
        assert expected["run"]["complete"] is True, root.name
        for must in expected.get("must", []):
            assert must["rule"], root.name
