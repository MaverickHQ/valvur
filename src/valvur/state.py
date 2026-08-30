"""Previous-run state, so a rescan can report what actually changed.

Local only. Results are never committed (ADR-0011), so this history does not travel
with the repository — a fresh clone has no past and reports everything as `new`. That
is correct and honest: we do not know what a machine has seen before.
"""

from __future__ import annotations

import json
from pathlib import Path

from .fingerprint import FP_VERSION

STATE_FILE = "state.json"
SCHEMA = 1


def load(results_dir: Path) -> tuple[set[str], set[str]]:
    """Return (fingerprints present last run, fingerprints ever marked fixed)."""
    path = results_dir / STATE_FILE
    if not path.is_file():
        return set(), set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set(), set()
    # A fingerprint algorithm change invalidates all history; start clean rather
    # than silently comparing incomparable identities.
    if data.get("fp_version") != FP_VERSION:
        return set(), set()
    return set(data.get("present", [])), set(data.get("fixed", []))


def save(results_dir: Path, present: set[str], fixed: set[str]) -> None:
    (results_dir / STATE_FILE).write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "fp_version": FP_VERSION,
                "present": sorted(present),
                "fixed": sorted(fixed),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def status_for(fingerprint: str, previous: set[str], previously_fixed: set[str]) -> str:
    if fingerprint in previous:
        return "persisting"
    if fingerprint in previously_fixed:
        return "regressed"
    return "new"
