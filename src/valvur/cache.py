"""Host-side cache for vulnerability data (ADR-0012) and the package-name index
(ADR-0018).

Lives outside the image so advisory freshness and image version stay independent —
they change at completely different rates.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

STALE_AFTER_DAYS = 30

#: When a clean result stops being trustworthy. Trivy rebuilds its database every
#: 24 hours — `NextUpdate` is always `UpdatedAt + 24h` — so seven days is seven
#: missed rebuilds, not a number chosen because it sounded careful. Being a few
#: hours past due is normal and says nothing; a week of missed advisories is the
#: difference between "we looked and found nothing" and "we did not look recently
#: enough to know".
DB_STALE_AFTER_DAYS = 7

#: When the package-name index stops being evidence (ADR-0018). Thirty days is
#: roughly 16,000 PyPI and 48,000 npm names of drift, and matches the KEV threshold
#: already reported beside it. The failure direction is the opposite of the
#: database's: an old index is MISSING names, so it overstates — a package newer than
#: the index is reported nonexistent — rather than letting a hallucination through.
#: The threshold keeps the answer's age visible; it is not a cliff.
NAME_INDEX_STALE_AFTER_DAYS = 30


def root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.environ.get("VALVUR_CACHE")
    return Path(base or (Path.home() / ".cache")) / "valvur"


def trivy_db() -> Path:
    return root() / "trivy"


def name_index() -> Path:
    """Where the package-name index lives: one sorted plain-text file per ecosystem
    and a `metadata.json` saying when each was built (ADR-0018). Mounted read-only
    into every container at `/cache/names`."""
    return root() / "names"


def name_index_present() -> bool:
    return (name_index() / "metadata.json").is_file()


def name_index_age_days() -> float | None:
    """Age of the OLDEST ecosystem in the index, or None when there is no index.

    The oldest, because the verdict is one verdict: a fresh PyPI list beside a
    six-week-old npm list is a six-week-old answer for any project with a
    `package.json`. Built time, not download time, for the same reason as the
    database (F6.11): a mirror can hand over old data this morning.
    """
    import json

    marker = name_index() / "metadata.json"
    if not marker.is_file():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        ecosystems = data.get("ecosystems") or {}
        if not isinstance(ecosystems, dict) or not ecosystems:
            return None
        ages = [stamp_age_days(entry.get("built_at")) for entry in ecosystems.values()]
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return None
    if any(age is None for age in ages):
        return None
    return max(ages)  # type: ignore[type-var]


def stamp_age_days(stamp: object) -> float | None:
    from datetime import UTC, datetime

    try:
        built = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if built.tzinfo is None:
        built = built.replace(tzinfo=UTC)
    return (datetime.now(UTC) - built).total_seconds() / 86400


def db_present() -> bool:
    return (trivy_db() / "db" / "trivy.db").is_file()


def db_age_days() -> float | None:
    """How old the DATA is, not how long ago it was downloaded (F6.11).

    Those differ, and the difference matters most to the users who need it most.
    An air-gapped mirror (F10.5) can hand over a six-month-old database this
    morning: the file's mtime would read as fresh while every advisory in it is
    half a year out of date. Trivy stamps the build time in `UpdatedAt`, so that is
    what we ask. mtime is the fallback for a database that carries no metadata.
    """
    marker = trivy_db() / "db" / "metadata.json"
    if not marker.is_file():
        return None
    stamped = _metadata_time(marker, "UpdatedAt")
    if stamped is not None:
        return stamped
    return (time.time() - marker.stat().st_mtime) / 86400


def db_overdue_days() -> float | None:
    """Days past the moment Trivy itself said the database should be replaced.

    Trivy's own opinion beats ours: `NextUpdate` is what the tool that built the
    data considers its shelf life.
    """
    marker = trivy_db() / "db" / "metadata.json"
    if not marker.is_file():
        return None
    return _metadata_time(marker, "NextUpdate")


def _metadata_time(marker: Path, field: str) -> float | None:
    """Days elapsed since a timestamp in Trivy's metadata, or None if unreadable.

    Unreadable is not zero. A corrupt or unexpected metadata file must not produce a
    confident "0 days old" — that is the failure this whole phase exists to remove.
    """
    import json
    from datetime import UTC, datetime

    try:
        raw = json.loads(marker.read_text(encoding="utf-8")).get(field)
        stamped = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return (datetime.now(UTC) - stamped).total_seconds() / 86400
