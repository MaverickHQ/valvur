"""Project licence hygiene (F4.1-F4.3).

A missing or contradictory licence blocks a production release and is invisible to
every Scanner we orchestrate. Dependency licence policy is separate and host-side —
it reads the SBOM the fleet has already produced (see licence_policy.py).
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Check

CANDIDATES = ("LICENSE", "LICENCE", "COPYING", "LICENSE.md", "LICENCE.md", "LICENSE.txt")

# Distinctive phrases, not whole texts. Enough to identify the family and catch a
# contradiction; full SPDX matching is ScanCode's job and is deferred to `deep`.
SIGNATURES = (
    ("AGPL-3.0", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I)),
    ("GPL-3.0", re.compile(r"GNU GENERAL PUBLIC LICENSE\s*\n?\s*Version 3", re.I)),
    ("GPL-2.0", re.compile(r"GNU GENERAL PUBLIC LICENSE\s*\n?\s*Version 2", re.I)),
    ("LGPL-2.1", re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE", re.I)),
    ("Apache-2.0", re.compile(r"Apache License\s*\n?\s*Version 2\.0", re.I)),
    ("MPL-2.0", re.compile(r"Mozilla Public License Version 2\.0", re.I)),
    ("BSD-3-Clause", re.compile(r"Redistributions of source code must retain", re.I)),
    ("MIT", re.compile(r"Permission is hereby granted, free of charge", re.I)),
)

DECLARED = (
    ("pyproject.toml", re.compile(r'^\s*license\s*=\s*[{\s]*(?:text\s*=\s*)?"([^"]+)"', re.M)),
    ("package.json", re.compile(r'"license"\s*:\s*"([^"]+)"')),
    ("Cargo.toml", re.compile(r'^\s*license\s*=\s*"([^"]+)"', re.M)),
)


class LicenceFileCheck(Check):
    """Severities are stated, not defaulted (task 19.C.1, corpus defect C5).

    Every Finding from this Check and from `ai_artifact` arrived as `unknown`, which
    reached the `SUMMARY.md` counts table as a literal `| unknown | 1 |` row on every
    corpus project. Ranking was unaffected — `ranking.py` weights by rule, not severity
    — but `findings.json`, SARIF and every IDE reading it saw `unknown`.

    `low` for a missing or unidentified licence: it is a release blocker, not a
    vulnerability. `medium` for a mismatch, because two files disagreeing about the
    licence is a statement someone will rely on being true.
    """

    name = "licence-file"

    def run(self, workspace: Path, exclude: tuple[str, ...] = ()) -> list[dict]:
        licence_path = next(
            (workspace / c for c in CANDIDATES if (workspace / c).is_file()), None
        )
        if licence_path is None:
            return [{
                "rule": "valvur.licence.missing",
                "severity": "low",
                "path": ".",
                "line": 0,
                "title": "No licence file found",
                "evidence": f"looked for: {', '.join(CANDIDATES)}",
                "identity": ("licence", "<project>", "missing"),
            }]

        text = licence_path.read_text(encoding="utf-8", errors="replace")
        identified = next((spdx for spdx, rx in SIGNATURES if rx.search(text)), None)
        if identified is None:
            identified = _from_title(text)
        rel = licence_path.name

        if identified is None:
            return [{
                "rule": "valvur.licence.unidentified",
                "severity": "low",
                "path": rel,
                "line": 0,
                "title": "Licence file present but its licence could not be identified",
                "evidence": "no known licence signature matched",
                "identity": ("licence", "<project>", "unidentified"),
            }]

        declared = _declared(workspace)
        if declared and declared[1].upper() != identified.upper():
            return [{
                "rule": "valvur.licence.mismatch",
                "severity": "medium",
                "path": declared[0],
                "line": 0,
                "title": (
                    f"{rel} is {identified} but {declared[0]} declares "
                    f"{declared[1]}"
                ),
                "evidence": f"file={identified} metadata={declared[1]}",
                "identity": ("licence", "<project>", "mismatch", identified, declared[1]),
            }]
        return []


# A file whose first lines name the licence is a declaration, even without the full
# text. Requiring the body would flag every short LICENSE as unidentifiable.
TITLES = (
    ("AGPL-3.0", re.compile(r"\bAGPL[- ]?3", re.I)),
    ("GPL-3.0", re.compile(r"\bGPL[- ]?3", re.I)),
    ("LGPL-2.1", re.compile(r"\bLGPL[- ]?2", re.I)),
    ("Apache-2.0", re.compile(r"\bApache[- ]?2", re.I)),
    ("BSD-3-Clause", re.compile(r"\bBSD[- ]?3", re.I)),
    ("MPL-2.0", re.compile(r"\bMPL[- ]?2|Mozilla Public", re.I)),
    ("ISC", re.compile(r"\bISC\b", re.I)),
    ("MIT", re.compile(r"\bMIT\b", re.I)),
)


def _from_title(text: str) -> str | None:
    head = "\n".join(text.splitlines()[:3])
    return next((spdx for spdx, rx in TITLES if rx.search(head)), None)


def _declared(workspace: Path) -> tuple[str, str] | None:
    for name, pattern in DECLARED:
        path = workspace / name
        if not path.is_file():
            continue
        match = pattern.search(path.read_text(encoding="utf-8", errors="replace"))
        if match:
            return name, match.group(1)
    return None
