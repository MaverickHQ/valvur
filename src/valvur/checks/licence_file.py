"""Does the project have a licence at all? (F4.2)

The simplest real Check, and the one that proves the in-container path end to end.
A missing licence blocks a production release and is invisible to every Scanner we
orchestrate.
"""

from __future__ import annotations

from pathlib import Path

CANDIDATES = ("LICENSE", "LICENCE", "COPYING", "LICENSE.md", "LICENCE.md", "LICENSE.txt")


class LicenceFileCheck:
    name = "licence-file"

    def run(self, workspace: Path) -> list[dict]:
        for candidate in CANDIDATES:
            if (workspace / candidate).is_file():
                return []
        return [
            {
                "rule": "valvur.licence.missing",
                "path": ".",
                "line": 0,
                "title": "No licence file found",
                "evidence": f"looked for: {', '.join(CANDIDATES)}",
                "identity": ("licence", "<project>", "missing"),
            }
        ]
