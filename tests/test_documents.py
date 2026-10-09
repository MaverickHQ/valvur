"""R39.3 (D78c): the documents beside the README, indexed, linked and current.

`docs/README.md` is the index a reader lands on from the README, so a document it does
not list is one nobody finds. `SUPPORT.md`, `ROADMAP.md` and `CITATION.cff` are the files
GitHub and citation tools look for. Every relative link in every document resolves,
anchors included: when R39.2 moved the README's detail into guides, three links into
its old sections broke in documents nobody re-read.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from user_docs import broken_links

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"


def _documents() -> list[Path]:
    """Every live document. `docs/history/` is closed records, kept as they were written,
    as `check_traceability.py` skips it too."""
    history = DOCS / "history"
    return sorted(p for p in [*REPO.glob("*.md"), *DOCS.rglob("*.md"),
                              *(REPO / ".kiro" / "specs" / "valvur").glob("*.md")]
                  if history not in p.parents)


def test_the_index_lists_every_document_and_folder():
    index = (DOCS / "README.md").read_text(encoding="utf-8")
    listed = set(re.findall(r"\]\(([^)#\s]+)\)", index))
    wanted = {p.name for p in DOCS.glob("*.md") if p.name != "README.md"}
    wanted |= {f"{p.name}/" for p in DOCS.iterdir() if p.is_dir()}

    assert sorted(wanted - listed) == []


def test_support_roadmap_and_citation_are_where_github_looks():
    for name in ("SUPPORT.md", "ROADMAP.md", "CITATION.cff"):
        assert (REPO / name).is_file(), name


def test_the_citation_names_the_version_this_tree_declares():
    declared = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    citation = (REPO / "CITATION.cff").read_text(encoding="utf-8")

    assert re.search(r"^cff-version: 1\.2\.0$", citation, re.M)
    assert re.search(rf'^version: "{re.escape(declared)}"$', citation, re.M)


def test_every_relative_link_in_every_document_resolves():
    broken = {str(p.relative_to(REPO)): broken_links(p) for p in _documents()}

    assert {name: links for name, links in broken.items() if links} == {}


def test_a_release_moves_the_citation_with_the_version():
    """`prepare_release.py` writes the version and the date into `CITATION.cff` with the
    rest, so a citation never names a version older than the release it ships in."""
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("prepare_release",
                                                  REPO / "scripts" / "prepare_release.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["prepare_release"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    citation = module.planned(REPO, "9.9.9", "2030-01-02")[Path("CITATION.cff")]

    assert re.search(r'^version: "9\.9\.9"$', citation, re.M)
    assert re.search(r"^date-released: 2030-01-02$", citation, re.M)
