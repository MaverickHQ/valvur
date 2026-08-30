"""Host-side cache for vulnerability data (ADR-0012).

Lives outside the image so advisory freshness and image version stay independent —
they change at completely different rates.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

STALE_AFTER_DAYS = 30


def root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.environ.get("VALVUR_CACHE")
    return Path(base or (Path.home() / ".cache")) / "valvur"


def trivy_db() -> Path:
    return root() / "trivy"


def db_present() -> bool:
    return (trivy_db() / "db" / "trivy.db").is_file()


def db_age_days() -> float | None:
    marker = trivy_db() / "db" / "metadata.json"
    if not marker.is_file():
        return None
    return (time.time() - marker.stat().st_mtime) / 86400
