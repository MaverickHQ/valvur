"""The image that ships, judged (R43.4, D81t, N2.7).

    docker run --rm --network none -v <database>:/db:ro --entrypoint trivy valvur:dev \\
      rootfs --cache-dir /db --cache-backend memory --skip-db-update \\
      --skip-java-db-update --offline-scan --format json --scanners vuln --quiet / \\
      > image-scan.json
    python3 scripts/image_gate.py image-scan.json --out image-gate.json

Every other gate reads the repository's lockfiles; this reads the built image, through
its own Trivy over its own root filesystem: its OS packages, its Python environments,
and its Go binaries' modules and standard library. The base tag `python:3.12-alpine3.22`
stopped moving on 2026-04-19, and nothing saw it until 2026-10-24.

- A vulnerability with a fixed version **blocks**, unless `.github/image-accepted.yaml`
  lists its id and package with an `expires` date still ahead.
- One with no fixed version is **reported**, and does not block.
- An accepted entry without an expiry, or past it, is **refused** by name, and accepts
  nothing.

The accepted file is the owner's, as a Suppression is: nothing automated writes it
(Requirement 16.3). It is a list under `accepted:`, each entry an `id`, a `package`, an
`expires` date and a `reason`, read line by line: no YAML parser is among the
dependencies. Exit 0 when nothing blocks, 1 when something does, 2 when the scan or the
accepted file cannot be read. `--out` writes the verdict as JSON, the heal's second
input (R44.6). Standard library only. This is the project checking its own image; it is
not a feature valvur offers its users.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, date, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ACCEPTED = REPO / ".github" / "image-accepted.yaml"

_ENTRY = re.compile(r"^  - (\w+):\s*(.*?)\s*$")
_FIELD = re.compile(r"^    (\w+):\s*(.*?)\s*$")


class Unreadable(ValueError):
    pass


def accepted_entries(text: str) -> list[dict[str, str]]:
    """The entries under `accepted:`, each a dict of its fields."""
    entries: list[dict[str, str]] = []
    inside = False
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.rstrip() == "accepted:":
            inside = True
            continue
        if not inside:
            raise Unreadable(f"line {number}: expected `accepted:` first")
        if (start := _ENTRY.match(line)) and start.group(1) == "id":
            entries.append({"id": start.group(2).strip("'\"")})
        elif (field := _FIELD.match(line)) and entries:
            entries[-1][field.group(1)] = field.group(2).strip("'\"")
        else:
            raise Unreadable(f"line {number}: not an entry's `id` or field: {line.strip()}")
    for entry in entries:
        if not entry.get("package"):
            raise Unreadable(f"{entry['id']}: no package")
    return entries


def vulnerabilities(report: object) -> list[dict[str, str]]:
    """Every vulnerability Trivy reported, with the target it was found in."""
    if not isinstance(report, dict) or not isinstance(report.get("Results") or [], list):
        raise Unreadable("not a Trivy JSON report")
    found = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            raise Unreadable("a result that is not an object")
        for vuln in result.get("Vulnerabilities") or []:
            found.append({"id": str(vuln["VulnerabilityID"]), "package": str(vuln["PkgName"]),
                          "installed": str(vuln.get("InstalledVersion", "")),
                          "fixed": str(vuln.get("FixedVersion") or ""),
                          "severity": str(vuln.get("Severity", "UNKNOWN")),
                          "target": str(result.get("Target", ""))})
    return found


def judge(found: list[dict[str, str]], entries: list[dict[str, str]], today: date) -> dict:
    """{blocking, accepted, unfixed, refused}, each a list."""
    valid, refused = {}, []
    for entry in entries:
        expires = entry.get("expires", "")
        try:
            ahead = date.fromisoformat(expires) >= today if expires else None
        except ValueError:
            ahead = None
        if ahead:
            valid[(entry["id"], entry["package"])] = entry
        else:
            refused.append({**entry, "why": "expired" if ahead is False else "no expiry"})
    verdict: dict[str, list] = {"blocking": [], "accepted": [], "unfixed": [],
                                "refused": refused}
    for vuln in found:
        if not vuln["fixed"]:
            verdict["unfixed"].append(vuln)
        elif (vuln["id"], vuln["package"]) in valid:
            verdict["accepted"].append({**vuln, "expires": valid[(vuln["id"],
                                                                   vuln["package"])]["expires"]})
        else:
            verdict["blocking"].append(vuln)
    return verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scan", type=Path, help="Trivy's JSON over the image's root filesystem")
    parser.add_argument("--accepted", type=Path, default=ACCEPTED)
    parser.add_argument("--today", help="YYYY-MM-DD; the UTC date by default")
    parser.add_argument("--out", type=Path, help="write the verdict here, as JSON")
    args = parser.parse_args(argv)
    today = date.fromisoformat(args.today) if args.today else datetime.now(UTC).date()
    try:
        found = vulnerabilities(json.loads(args.scan.read_text()))
        entries = (accepted_entries(args.accepted.read_text())
                   if args.accepted.is_file() else [])
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"image gate: cannot read the scan or the accepted file: {error}")
        return 2
    verdict = judge(found, entries, today)
    if args.out:
        args.out.write_text(json.dumps(verdict, indent=2) + "\n")
    for entry in verdict["refused"]:
        print(f"refused: {entry['id']} {entry['package']}: {entry['why']}, so it accepts nothing")
    for vuln in verdict["blocking"]:
        print(f"blocks: {vuln['id']} {vuln['package']} {vuln['installed']}, fixed in "
              f"{vuln['fixed']} ({vuln['severity']}, {vuln['target']})")
    for vuln in verdict["unfixed"]:
        print(f"no fix yet: {vuln['id']} {vuln['package']} {vuln['installed']} "
              f"({vuln['severity']}, {vuln['target']})")
    print(f"{len(verdict['blocking'])} blocking, {len(verdict['accepted'])} accepted, "
          f"{len(verdict['unfixed'])} with no fix, {len(verdict['refused'])} entries refused")
    return 1 if verdict["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
