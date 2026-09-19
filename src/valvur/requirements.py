"""`requirements*.txt`, read for one question: is each line a version or a range?

Found by Block A's corpus dispatch (task 25.3, 2026-09-18): a 39-line requirements
file with no pins read as *checked* on `offline` — Trivy reads pinned lines only, and
correctly reported nothing for a range — while on `full` OSV-Scanner evaluated every
range at its lower bound and reported 110 advisories against versions nobody
installs. Both defects turn on the same fact about a line, so it is decided once,
here, and read by the coverage note and the pipeline stage that act on it.

A *pinned* line names one version: `==1.2.3`, or `===` arbitrary equality. Everything
else with a name is a *range* — `>=`, `~=`, `<`, `!=`, a wildcard `==1.*`, or no
specifier at all, which is every version there is. Options, comments, editable and
direct references (`-e .`, `name @ git+…`, a URL) are none of these: they are not
registry dependencies, and the pinning rule already covers the mutable ones.
"""

from __future__ import annotations

import re
from pathlib import Path

REQUIREMENTS_GLOB = "requirements*.txt"

_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_PIN = re.compile(r"^={2,3}\s*[^\s,;*]+$")


def normalise(name: str) -> str:
    """PEP 503: the one spelling a name has, whichever the file used."""
    return re.sub(r"[-_.]+", "-", name).lower()


def classify(line: str) -> tuple[str, bool] | None:
    """`(normalised name, pinned)` for a dependency line; `None` for a line that is
    not one."""
    # pip-compile writes `pkg==1.0 \` with the hashes on continuation lines: the
    # backslash is not part of the specifier. Found by valvur's own self-scan the
    # first time this ran against the hash-locked Checkov requirements — 95 of 97
    # pins read as ranges, OSV's one Finding there was dropped, and the suppression
    # on it lapsed.
    stripped = line.split("#", 1)[0].strip().rstrip("\\").strip()
    if not stripped or stripped.startswith("-") or "@" in stripped or "://" in stripped:
        return None
    if stripped.startswith((".", "/")):
        return None
    match = _LINE.match(stripped)
    if not match:
        return None
    name, rest = match.group(1), match.group(2)
    specifiers = rest.split(";", 1)[0].strip()
    # `==1.2,<2` pins; `==1.*` does not — the wildcard is a range wearing `==`.
    pinned = any(_PIN.match(part.strip()) for part in specifiers.split(","))
    return normalise(name), pinned


def read(path: Path) -> dict[str, bool]:
    """Every registry dependency the file names, and whether it is pinned. A name
    listed twice takes the last line, as pip does."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    out: dict[str, bool] = {}
    for line in lines:
        entry = classify(line)
        if entry:
            out[entry[0]] = entry[1]
    return out


def pins(path: Path) -> tuple[int, int]:
    """`(pinned, unpinned)` line counts."""
    values = list(read(path).values())
    return sum(values), len(values) - sum(values)


def is_requirements_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name.startswith("requirements") and name.endswith(".txt")
