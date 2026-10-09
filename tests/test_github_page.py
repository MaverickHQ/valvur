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
