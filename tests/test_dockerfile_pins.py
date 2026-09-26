"""29.4.1 — every base image names its tag beside its digest.

Its own file rather than the supply-chain constraint suite: that suite is the
release gate's, held to the forty-eight tests 28.4.4 split.
"""

from __future__ import annotations

import re
from pathlib import Path


def test_every_pinned_base_image_names_its_tag_beside_the_digest():
    """29.4.1. A digest alone told Dependabot nothing about which tag to follow, so
    it followed `latest`: on 2026-09-26 it proposed a Debian `python` (the build
    failed at `apk`) and a newer `syft` than the adapter reports. `image:tag@sha256:…`
    pins the bytes AND names the line to track, so a bump is a refresh of the tag
    we mean — and the version comments the lines used to carry are the lines."""

    for number, line in enumerate(Path("Dockerfile").read_text().splitlines(), start=1):
        match = re.match(r"^FROM\s+(\S+)", line)
        if not match or "@sha256:" not in match.group(1):
            continue
        reference = match.group(1)
        shape = r"[^:@\s]+(?::\d+)?/?[^:@\s]*:[^@\s]+@sha256:[0-9a-f]{64}"
        assert re.fullmatch(shape, reference), \
            f"Dockerfile:{number} pins a digest with no tag beside it: {reference}"
