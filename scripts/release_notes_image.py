"""What the image does not fix, for the GitHub release's notes (R43.4, N2.7, TASKLIST E2).

    python3 scripts/release_notes_image.py \\
      gates/image-gate-amd64/image-gate.json gates/image-gate-arm64/image-gate.json

Each argument is a verdict `scripts/image_gate.py --out` wrote, in a directory whose name
ends in its architecture (`image-gate-amd64`). The section lists, once per finding across
the architectures, every vulnerability in the image with no fix yet, and every one the
owner accepted in `.github/image-accepted.yaml`, with its expiry. The release run's
`notes` job renders it before the brake, and `promote` copies it into the notes. 1.5.4's
list was written by hand, and it missed the base image's pip. Exit 0 when it printed, 2
naming the file when a verdict is missing or is not one. Standard library only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HEADING = "## What this image does not fix"
INTRO = ("Found by the image's own Trivy over its root filesystem, in the release run (R43.4). A\n"
         "vulnerability with a fix in reach blocks the release, unless the owner accepted it in\n"
         "`.github/image-accepted.yaml` with an expiry.")
NOTHING = "Nothing: every vulnerability Trivy found in the image has a fix in it."
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _arch(path: Path) -> str:
    name = path.parent.name
    return name.removeprefix("image-gate-") if name.startswith("image-gate-") else "unknown"


def render(verdicts: list[tuple[str, dict]]) -> str:
    rows: dict[tuple[str, str, str], dict] = {}
    for arch, verdict in verdicts:
        listed = [(vuln, "no fix yet") for vuln in verdict["unfixed"]] + \
                 [(vuln, f"accepted until {vuln['expires']}") for vuln in verdict["accepted"]]
        for vuln, status in listed:
            key = (vuln["id"], vuln["package"], vuln["installed"])
            row = rows.setdefault(key, {**vuln, "arches": [], "status": status})
            if arch not in row["arches"]:
                row["arches"].append(arch)
    if not rows:
        return f"{HEADING}\n\n{NOTHING}\n"
    lines = [HEADING, "", INTRO, "",
             "| advisory | package | installed | severity | architectures | status |",
             "|---|---|---|---|---|---|"]
    order = sorted(rows.values(), key=lambda row: (
        SEVERITIES.index(row["severity"]) if row["severity"] in SEVERITIES else len(SEVERITIES),
        row["id"]))
    for row in order:
        lines.append(f"| {row['id']} | {row['package']} | {row['installed']} | "
                     f"{row['severity']} | {', '.join(sorted(row['arches']))} | {row['status']} |")
    return "\n".join(lines) + "\n"


def _read(path: Path) -> dict:
    """A verdict: an object whose `unfixed` and `accepted` are lists."""
    verdict = json.loads(path.read_text())
    if not isinstance(verdict, dict) or not all(
            isinstance(verdict.get(key), list) for key in ("unfixed", "accepted")):
        raise ValueError("not a verdict: no list-valued `unfixed` and `accepted`")
    return verdict


def main(argv: list[str] | None = None) -> int:
    paths = [Path(arg) for arg in (sys.argv[1:] if argv is None else argv)]
    verdicts = []
    for path in paths:
        try:
            verdicts.append((_arch(path), _read(path)))
        except (OSError, ValueError) as error:
            print(f"release notes: cannot read {path}: {error}", file=sys.stderr)
            return 2
    print(render(verdicts), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
