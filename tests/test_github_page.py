"""R39.4 (D78d): the repository's GitHub page, as `docs/LISTING.md` records it.

The About description, the website and the topics are written once, in the listing
document, and applied from there with the owner's yes: changing the page publishes. A
test holds GitHub's limits, so a later edit cannot record a page GitHub would refuse.
"""

from __future__ import annotations

import re
from pathlib import Path

LISTING = Path(__file__).resolve().parent.parent / "docs" / "LISTING.md"


def page() -> dict:
    """The page's fields, from the listing document's `## The GitHub page` section."""
    text = LISTING.read_text(encoding="utf-8")
    assert "\n## The GitHub page\n" in text, "docs/LISTING.md has no GitHub page section"
    section = text.split("\n## The GitHub page\n", 1)[1].split("\n## ", 1)[0]
    description = re.search(r"^- \*\*Description:\*\* (.+)$", section, re.M)
    website = re.search(r"^- \*\*Website:\*\* (\S+)$", section, re.M)
    topics = re.search(r"^- \*\*Topics:\*\* (.+)$", section, re.M)
    assert description and website and topics, "a field is missing"
    return {"description": description.group(1).strip(),
            "homepage": website.group(1),
            "topics": [t.strip("` ") for t in topics.group(1).split(",")]}


def test_the_description_fits_the_about_box():
    description = page()["description"]

    assert 0 < len(description) <= 350
    assert "offline" in description.lower() and "AI-generated code" in description


def test_the_website_is_https():
    assert page()["homepage"].startswith("https://")


def test_the_topics_are_twenty_at_most_in_github_s_syntax():
    topics = page()["topics"]

    assert 0 < len(topics) <= 20 and len(set(topics)) == len(topics)
    for topic in topics:
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,49}", topic), topic


def _png_size(path: Path) -> tuple[int, int]:
    """Width and height from a PNG's IHDR chunk."""
    import struct

    head = path.read_bytes()[:24]
    assert head[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} is not a PNG"
    return struct.unpack(">II", head[16:24])


def test_the_social_preview_is_rendered_from_its_svg_at_github_s_size():
    """GitHub shows a social preview at 1280 by 640 and refuses one over 1 MB. The PNG
    is rendered from the SVG in the tree by `scripts/social_preview.py`, so the card can
    be changed by a commit and rendered again."""
    docs = LISTING.parent
    svg = (docs / "social-preview.svg").read_text(encoding="utf-8")
    png = docs / "social-preview.png"

    assert 'width="1280" height="640"' in svg
    assert _png_size(png) == (1280, 640)
    assert png.stat().st_size <= 1_000_000
