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


#: Set when history was discarded because the Fingerprint algorithm changed.
#: Read once by the caller, which reports it (task 17.4). Discarding was always
#: correct; doing it silently was not — every Finding reappears as `new`, every
#: previous `fixed` vanishes, and committed Suppressions stop matching. A developer
#: sees what looks like a catastrophic regression with nothing to say otherwise.
_reset: list[tuple[object, int]] = []


def take_reset() -> tuple[object, int] | None:
    """The Fingerprint version change that discarded history, if there was one."""
    return _reset.pop() if _reset else None


def load(results_dir: Path) -> tuple[dict[str, str], set[str]]:
    """Return ({fingerprint: title} present last run, fingerprints ever fixed).

    Titles are kept so a rescan can say *what* you fixed rather than only that
    something was — "you fixed the AWS key in config.py" beats "fixed: 1".
    """
    path = results_dir / STATE_FILE
    if not path.is_file():
        return {}, set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}, set()
    # A fingerprint algorithm change invalidates all history; start clean rather
    # than silently comparing incomparable identities.
    if data.get("fp_version") != FP_VERSION:
        _reset.append((data.get("fp_version"), FP_VERSION))
        return {}, set()
    present = data.get("present", {})
    if isinstance(present, list):  # pre-3.4.4 state; titles unknown
        present = dict.fromkeys(present, "")
    return present, set(data.get("fixed", []))


def save(results_dir: Path, present: dict[str, str], fixed: set[str]) -> None:
    (results_dir / STATE_FILE).write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "fp_version": FP_VERSION,
                "present": dict(sorted(present.items())),
                "fixed": sorted(fixed),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def status_for(fingerprint: str, previous: dict[str, str], previously_fixed: set[str]) -> str:
    if fingerprint in previous:
        return "persisting"
    if fingerprint in previously_fixed:
        return "regressed"
    return "new"
