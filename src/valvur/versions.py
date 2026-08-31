"""Version ordering, shared by the OSV adapter and the remediation grouper.

Both need to answer "which of these fixes is the right one to recommend", and they
must answer it identically or the proposal contradicts the finding it cites.
"""

from __future__ import annotations

import re


def version_key(value: str) -> tuple[int, ...]:
    """Tolerant ordering across ecosystems: numeric segments compare numerically, so
    1.1.16 sorts above 1.1.9 where a string compare would not."""
    return tuple(
        int(m.group(1)) if (m := re.match(r"(\d+)", part)) else 0
        for part in re.split(r"[._-]", value.split("+")[0])
    )


def release_line(value: str) -> int:
    """The major line an installed version sits on. Fixes do not cross it: telling
    someone on 5.0.7 to "upgrade to 1.1.18" is a downgrade, and a pnpm tree really
    does carry three lines of the same package at once."""
    key = version_key(value)
    return key[0] if key else 0
