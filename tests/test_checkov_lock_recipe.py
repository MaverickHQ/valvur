"""R42.4: the Checkov lock is what its recipe writes (N3.7).

`scripts/lock-checkov.sh` passes extra arguments through after its own, so the heal
re-locks with the recipe itself, and resolves with `--no-build`, so no package's code
runs to resolve it. Resolution is real and hermetic: small wheels built in `tmp_path`,
read through `--no-index --find-links`.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RECIPE = REPO / "scripts" / "lock-checkov.sh"

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="the recipe runs uv")


def _wheel(directory: Path, name: str, version: str, requires: tuple[str, ...] = ()) -> None:
    """A minimal, valid pure-Python wheel."""
    dist = f"{name}-{version}.dist-info"
    files = {
        f"{name}/__init__.py": "",
        f"{dist}/METADATA": "Metadata-Version: 2.1\n"
                            f"Name: {name}\nVersion: {version}\n"
                            + "".join(f"Requires-Dist: {r}\n" for r in requires),
        f"{dist}/WHEEL": "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
                         "Tag: py3-none-any\n",
    }
    record = []
    for path, text in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest())
        record.append(f"{path},sha256={digest.decode().rstrip('=')},{len(text)}")
    record.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = "\n".join(record) + "\n"
    with zipfile.ZipFile(directory / f"{name}-{version}-py3-none-any.whl", "w") as wheel:
        for path, text in files.items():
            wheel.writestr(path, text)


def _tree(tmp_path: Path, requirement: str) -> tuple[Path, Path]:
    """A copy of the recipe in a tree of its own, and a directory of wheels."""
    tree, wheels = tmp_path / "tree", tmp_path / "wheels"
    (tree / "scripts").mkdir(parents=True)
    wheels.mkdir()
    shutil.copy(RECIPE, tree / "scripts" / RECIPE.name)
    (tree / "requirements-checkov.in").write_text(requirement + "\n")
    (tree / "requirements-checkov.overrides").write_text("")
    return tree, wheels


def _recipe(tree: Path, wheels: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(tree / "scripts" / RECIPE.name), "--no-index",
                           "--find-links", str(wheels), *extra],
                          capture_output=True, text=True, check=False)


def test_extra_arguments_reach_uv_after_the_recipe_s_own(tmp_path):
    tree, wheels = _tree(tmp_path, "alpha")
    _wheel(wheels, "alpha", "1.0", ("beta>=1",))
    for version in ("1.0", "1.1"):
        _wheel(wheels, "beta", version)
    pins = tmp_path / "pins.txt"
    pins.write_text("beta==1.0\n")

    run = _recipe(tree, wheels, "--constraint", str(pins))

    assert run.returncode == 0, run.stderr
    lock = (tree / "requirements-checkov.txt").read_text()
    assert "alpha==1.0" in lock and "beta==1.0" in lock and "--hash=sha256:" in lock


def test_the_existing_lock_is_kept_unless_an_upgrade_is_asked_for(tmp_path):
    tree, wheels = _tree(tmp_path, "alpha")
    _wheel(wheels, "alpha", "1.0", ("beta>=1",))
    _wheel(wheels, "beta", "1.0")
    assert _recipe(tree, wheels).returncode == 0
    _wheel(wheels, "beta", "1.1")

    assert _recipe(tree, wheels).returncode == 0
    assert "beta==1.0" in (tree / "requirements-checkov.txt").read_text()
    assert _recipe(tree, wheels, "--upgrade-package", "beta").returncode == 0
    assert "beta==1.1" in (tree / "requirements-checkov.txt").read_text()


def test_a_package_that_needs_a_build_to_resolve_is_refused_and_named(tmp_path):
    tree, wheels = _tree(tmp_path, "gamma")
    sdist = wheels / "gamma-1.0.tar.gz"
    subprocess.run(["tar", "-czf", str(sdist), "-C", str(tmp_path), "tree/scripts"],
                   check=True)

    run = _recipe(tree, wheels)

    assert run.returncode != 0
    assert "gamma" in run.stderr and "building from source is disabled" in run.stderr
