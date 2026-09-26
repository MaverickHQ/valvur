"""Previous-run state, so a rescan can report what actually changed.

Local only. Results are never committed (ADR-0011), so this history does not travel
with the repository — a fresh clone has no past and reports everything as `new`. That
is correct and honest: we do not know what a machine has seen before.
"""

from __future__ import annotations

import json
from pathlib import Path

from .findings import Status
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


def render(present: dict[str, str], fixed: set[str], *, generation: str = "") -> str:
    """The state document. Written by `results.write` in the same generation as
    the artifacts it describes (26.0.3), so a state.json from one run beside a
    findings.json from another is detectable rather than silent."""
    return json.dumps(
        {
            "schema": SCHEMA,
            "fp_version": FP_VERSION,
            "generation": generation,
            "present": dict(sorted(present.items())),
            "fixed": sorted(fixed),
        },
        indent=2,
    ) + "\n"


def save(results_dir: Path, present: dict[str, str], fixed: set[str], *,
         generation: str = "") -> None:
    """Write the state document on its own — whole, then renamed into place."""
    import os

    target = results_dir / STATE_FILE
    staged = target.with_name(target.name + ".tmp")
    staged.write_text(render(present, fixed, generation=generation), encoding="utf-8")
    os.replace(staged, target)


def status_for(fingerprint: str, previous: dict[str, str], previously_fixed: set[str]) -> Status:
    # F5.6: new / persisting / fixed / regressed, against the previous run's state.
    if fingerprint in previous:
        return Status.PERSISTING
    if fingerprint in previously_fixed:
        return Status.REGRESSED
    return Status.NEW
