"""R44.10: the README claims no more about rebuilding the image than was measured.

The self-healing spec's Requirement 22.3. Measured on 2026-11-22: `v1.6.2`'s tree, rebuilt a
day after its release, differed from the published image in two files, Alpine's index and
`/etc/shadow`. Both are fixed since, and no release has yet been rebuilt to its digest. Until
one has, the README says nothing of reproducible builds.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLAIM = re.compile(r"reproducib|bit[- ]for[- ]bit|byte[- ]for[- ]byte", re.I)


def claims(text: str) -> list[str]:
    return [line for line in text.splitlines() if CLAIM.search(line)]


def test_a_claim_would_be_seen():
    assert claims("The image is reproducible.\nAnd more.") == ["The image is reproducible."]
    assert claims("Two builds are bit-for-bit one image.")


def test_the_readme_makes_no_claim_of_a_reproducible_image():
    assert claims((REPO / "README.md").read_text(encoding="utf-8")) == []
