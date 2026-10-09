"""R40.2 (D79): the README PyPI shows, written by the build.

PyPI renders the README as the project's description and resolves nothing relative: on
`1.5.0`'s page the demo did not load and 22 of 52 links led nowhere. `hatch_build.py`'s
metadata hook hands PyPI a copy whose links point at the repository at the release's
tag. Tested through a built wheel, the artifact PyPI receives, since hatchling belongs
to the build and not to this environment.
"""

from __future__ import annotations

import email
import re
import subprocess
import tomllib
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
#: Where the build points PyPI's links: the repository, and its raw files for images.
INTO_REPO = re.compile(r"https://(?:github\.com/MaverickHQ/valvur/(?:blob|tree)|"
                       r"raw\.githubusercontent\.com/MaverickHQ/valvur)/([^/]+)/([^)#\s\"]*)")
_FENCE = re.compile(r"^```.*?^```", re.M | re.S)


@pytest.fixture(scope="module")
def description(tmp_path_factory) -> str:
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(out)], cwd=REPO, check=True,
                   capture_output=True, text=True, timeout=300)
    [wheel] = out.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        [name] = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        metadata = email.message_from_bytes(archive.read(name))
    assert metadata["Description-Content-Type"] == "text/markdown"
    return metadata.get_payload()


def _targets(text: str) -> list[str]:
    """Every Markdown link or image target, and every HTML `src` or `srcset`."""
    text = _FENCE.sub("", text)
    return [m.group(1) or m.group(2) for m in
            re.finditer(r"\]\(([^)\s]+)\)|\b(?:src|srcset)=\"([^\"]+)\"", text)]


def test_pypi_s_copy_has_no_relative_link_or_image(description):
    relative = [t for t in _targets(description)
                if not re.match(r"[a-z][a-z0-9+.-]*:|#", t)]

    assert relative == []


def test_every_link_into_the_repository_names_a_file_at_the_release_s_tag(description):
    declared = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    found = [INTO_REPO.match(t) for t in _targets(description)]
    into = [m for m in found if m]

    assert into, "no link into the repository at all"
    assert {m.group(1) for m in into} == {f"v{declared}"}
    missing = [m.group(2) for m in into if not (REPO / m.group(2)).exists()]
    assert missing == []


def test_the_picture_becomes_its_light_image(description):
    """PyPI's page is light and its renderer keeps no `<picture>`."""
    assert "<picture>" not in description and "<source" not in description
    assert re.search(r'<img src="https://raw\.githubusercontent\.com/MaverickHQ/valvur/'
                     r'[^/]+/docs/logo-light\.svg"', description)


def test_github_s_readme_keeps_its_relative_links():
    """The tree's README is GitHub's, whose links the link test holds relative."""
    readme = (REPO / "README.md").read_text(encoding="utf-8")

    assert "](docs/HOW-IT-WORKS.md)" in readme and "<picture>" in readme
