"""22.C.1 — the image records what it was built from, and the tree can check it.

Checks and rules ship inside the image (ADR-0013). Edit one, forget to rebuild, and
the unit suite passes while every real scan runs the old code — five times in four
days, the last of them during Block B, when the previous image crashed the new
shim's Check in-container and the F1.9 version check saw two identical versions.
The digest is computed by ONE module on both sides of the build, so the unit tests
here are about that module; the e2e test at the bottom is the guard itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from valvur import tree_hash

REPO = Path(__file__).resolve().parent.parent


def _tree(root: Path, files: dict[str, str]) -> dict[str, Path]:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return {"Dockerfile": root / "Dockerfile", "rules": root / "rules", "valvur": root / "pkg"}


BASE = {
    "Dockerfile": "FROM x\n", "rules/a.yaml": "a\n",
    "pkg/__init__.py": "", "pkg/check.py": "x = 1\n",
}


def test_the_digest_is_stable_across_locations(tmp_path):
    """The whole point: the same files at different paths — `src/valvur/` here,
    site-packages in the image — must hash identically, because the label is what
    is hashed, not the path."""
    here = _tree(tmp_path / "a", BASE)
    there = _tree(tmp_path / "somewhere" / "else" / "deep", BASE)

    assert tree_hash.digest(here) == tree_hash.digest(there)


@pytest.mark.parametrize("change", [
    {"pkg/check.py": "x = 2\n"},                 # a content change in a Check
    {"rules/a.yaml": "b\n"},                     # a rule
    {"Dockerfile": "FROM y\n"},                  # the Dockerfile
    {"pkg/new_check.py": "y = 1\n"},             # an added file
    {"rules/b.yaml": "c\n"},
])
def test_every_input_moves_the_digest(tmp_path, change):
    before = tree_hash.digest(_tree(tmp_path / "before", BASE))
    after = tree_hash.digest(_tree(tmp_path / "after", {**BASE, **change}))

    assert before != after, change


def test_a_removed_file_moves_the_digest(tmp_path):
    parts = _tree(tmp_path, BASE)
    before = tree_hash.digest(parts)
    (tmp_path / "rules" / "a.yaml").unlink()

    assert tree_hash.digest(parts) != before


def test_a_rename_moves_the_digest(tmp_path):
    """Same bytes under another name is a different input: a Check that moved is a
    Check the image does not have at the path the shim will ask for."""
    parts = _tree(tmp_path, BASE)
    before = tree_hash.digest(parts)
    (tmp_path / "pkg" / "check.py").rename(tmp_path / "pkg" / "kcehc.py")

    assert tree_hash.digest(parts) != before


def test_byte_code_caches_and_editor_droppings_are_not_inputs(tmp_path):
    """The image strips `__pycache__` after install and the host has it everywhere,
    so it must count on neither side — or the two would never agree."""
    parts = _tree(tmp_path, BASE)
    before = tree_hash.digest(parts)
    (tmp_path / "pkg" / "__pycache__").mkdir()
    (tmp_path / "pkg" / "__pycache__" / "check.cpython-312.pyc").write_bytes(b"\x00")
    (tmp_path / "pkg" / "stale.pyc").write_bytes(b"\x00")
    (tmp_path / "rules" / ".DS_Store").write_bytes(b"\x00")

    assert tree_hash.digest(parts) == before


def test_a_missing_input_is_an_error_not_an_empty_contribution(tmp_path):
    """A digest computed over `rules/` that does not exist would match an image
    with no rules — silently. Missing is loud."""
    parts = _tree(tmp_path, BASE)
    parts["rules"] = tmp_path / "no-such-dir"

    with pytest.raises(FileNotFoundError):
        tree_hash.digest(parts)


def test_the_tree_parts_are_exactly_what_the_dockerfile_copies():
    """If the Dockerfile starts copying something new, this must widen with it —
    the guard is only as good as the set of inputs it watches."""
    dockerfile = (REPO / "Dockerfile").read_text()
    copied = {
        line.split()[1]
        for line in dockerfile.splitlines()
        if line.startswith("COPY ") and "--from=" not in line
    }
    parts = tree_hash.tree_parts(REPO)

    # The Checkov lock joined in 23.4.1: a changed hash is a changed image.
    assert copied == {"Dockerfile", "rules", "src/valvur", "requirements-checkov.txt"}
    assert {p.relative_to(REPO).as_posix() for p in parts.values()} == copied


def test_the_cli_answers_for_a_tree(capsys):
    assert tree_hash.main(["--tree", str(REPO)]) == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 64 and out == tree_hash.digest(tree_hash.tree_parts(REPO))
    assert tree_hash.main(["--bogus"]) == 2


# ----------------------------------------------------------------- the guard

@pytest.mark.e2e
def test_the_image_under_test_was_built_from_this_tree():
    """The guard, where the trap bites: every e2e test below this line runs
    against VALVUR_IMAGE, and a stale one makes all of them lie. Fails with the
    rebuild command rather than letting a real scan run yesterday's Checks."""
    import os
    import subprocess

    from valvur.runner import IMAGE, detect_runtime

    runtime = detect_runtime()
    probe = subprocess.run(
        [runtime, "run", "--rm", "--entrypoint", "cat", IMAGE, tree_hash.IMAGE_DIGEST_FILE],
        capture_output=True, text=True, timeout=120, check=False,
    )
    built_from = probe.stdout.strip()
    expected = tree_hash.digest(tree_hash.tree_parts(REPO))

    assert probe.returncode == 0 and built_from, (
        f"{IMAGE} carries no build digest; it predates the guard. Rebuild it."
    )
    assert built_from == expected, (
        f"{IMAGE} was built from a different tree (image {built_from[:12]}, tree "
        f"{expected[:12]}). Rebuild it before trusting anything below:\n"
        f"  VALVUR_VERSION=... docker buildx bake   # → valvur:dev; VALVUR_IMAGE is "
        f"{os.environ.get('VALVUR_IMAGE', 'valvur:dev')}"
    )
