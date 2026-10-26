"""What the image does not fix, for the GitHub release's notes (R43.4, N2.7, TASKLIST E2).

    python3 scripts/release_notes_image.py \\
      gates/image-gate-amd64/image-gate.json gates/image-gate-arm64/image-gate.json

Each argument is a verdict `scripts/image_gate.py --out` wrote, in a directory whose name
ends in its architecture (`image-gate-amd64`). The section lists, once per finding across
the architectures, every vulnerability in the image with no fix yet, and every one the
owner accepted in `.github/image-accepted.yaml`, with its expiry. The release run's
`notes` job renders it before the brake, and `promote` copies it into the notes. 1.5.4's
list was written by hand, and it missed the base image's pip. Standard library only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HEADING = "## What this image does not fix"
INTRO = ("Found by the image's own Trivy over its root filesystem, in the release run (R43.4). A\n"
         "vulnerability with a fix in reach blocks the release, unless the owner accepted it in\n"
         "`.github/image-accepted.yaml` with an expiry.")


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
    lines = [HEADING, "", INTRO, "",
             "| advisory | package | installed | severity | architectures | status |",
             "|---|---|---|---|---|---|"]
    for row in rows.values():
        lines.append(f"| {row['id']} | {row['package']} | {row['installed']} | "
                     f"{row['severity']} | {', '.join(sorted(row['arches']))} | {row['status']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    paths = [Path(arg) for arg in (sys.argv[1:] if argv is None else argv)]
    print(render([(_arch(path), json.loads(path.read_text())) for path in paths]), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
