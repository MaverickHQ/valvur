#!/usr/bin/env python3
"""The release's OpenVEX document, from the image gate's verdicts (R52.2, D82q, Req. 14.1).

    python3 scripts/image_vex.py --image ghcr.io/maverickhq/valvur --digest sha256:… \\
      --release 1.7.0 --out valvur-1.7.0.openvex.json \\
      gates/image-gate-amd64/image-gate.json gates/image-gate-arm64/image-gate.json

Each argument is a verdict `scripts/image_gate.py --out` wrote, in a directory whose name
ends in its architecture. The document's product is the image by digest, and it holds one
statement for each vulnerability the image's own Trivy found and the release shipped with:

- one with no fixed version is `under_investigation`;
- one the owner accepted in `.github/image-accepted.yaml` is `affected`, with the entry's
  reason and expiry as what is being done about it;
- an accepted one whose entry gives a `justification`, one of OpenVEX's five, is
  `not_affected`, with the entry's reason as the impact statement.

**It says only what valvur knows.** Nothing here decides that a vulnerability does not
affect the image: `not_affected` is the owner's statement, written by the owner in the
accepted file, and copied. A vulnerability with a fix in reach and no acceptance blocks the
release, so it is in no release's document.

OpenVEX requires at least one statement, so verdicts with nothing to say give no document:
nothing is written and the run says so. The same verdicts and the same `--timestamp` give
the same bytes. Exit 0 when the document was written or there was nothing to state, 2
naming the file when a verdict or the accepted file cannot be read, and then nothing is
written. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))

import image_gate

CONTEXT = "https://openvex.dev/ns/v0.2.0"
AUTHOR = "valvur's release workflow (github.com/MaverickHQ/valvur)"
TOOLING = "scripts/image_vex.py"
DOWNLOAD = "https://github.com/MaverickHQ/valvur/releases/download"
#: OpenVEX 0.2.0's justifications for `not_affected`, as its specification spells them.
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present",
                  "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary",
                  "inline_mitigations_already_exist")
#: Trivy's name for where it found a package, to the package URL's type.
_PURL_TYPE = {"python-pkg": "pypi", "gobinary": "golang", "node-pkg": "npm", "jar": "maven"}
_OS = ("alpine", "debian", "ubuntu", "wolfi", "chainguard")


class Unreadable(ValueError):
    pass


def _arch(path: Path) -> str:
    name = path.parent.name
    return name.rsplit("-", 1)[-1] if "-" in name else name


def _read(path: Path) -> dict:
    try:
        verdict = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Unreadable(f"{path}: {error}") from error
    if not isinstance(verdict, dict) or not all(
            isinstance(verdict.get(key), list) for key in ("accepted", "unfixed")):
        raise Unreadable(f"{path}: not a verdict of scripts/image_gate.py")
    return verdict


def image_purl(image: str, digest: str, arch: str = "") -> str:
    """The image by digest, as a package URL of type `oci`. OpenVEX does not say how an
    image is written; this is the package-URL specification's own form for one."""
    repository, name = image.rsplit("/", 1)
    return (f"pkg:oci/{name}@{quote(digest, safe='')}?repository_url={repository}/{name}"
            + (f"&arch={arch}" if arch else ""))


def package_purl(vuln: dict) -> str:
    kind, name = str(vuln.get("kind") or ""), quote(str(vuln["package"]), safe="/@")
    version = quote(str(vuln.get("installed") or ""), safe="")
    if kind in _OS:
        return f"pkg:apk/{kind}/{name}@{version}" if kind in ("alpine", "wolfi", "chainguard") \
            else f"pkg:deb/{kind}/{name}@{version}"
    return f"pkg:{_PURL_TYPE.get(kind, 'generic')}/{name}@{version}"


def statements(verdicts: list[tuple[str, dict]], accepted: list[dict[str, str]],
               image: str, digest: str) -> list[dict]:
    """One statement for each vulnerability and package, across the architectures."""
    said = {(entry["id"], entry["package"]): entry for entry in accepted}
    every = sorted({arch for arch, _ in verdicts})
    rows: dict[tuple[str, str, str], dict] = {}
    for arch, verdict in verdicts:
        for kind in ("unfixed", "accepted"):
            for vuln in verdict[kind]:
                key = (str(vuln["id"]), str(vuln["package"]), str(vuln.get("installed", "")))
                row = rows.setdefault(key, {"vuln": vuln, "kind": kind, "arches": set()})
                row["arches"].add(arch)
    made = []
    for (identifier, package, installed), row in sorted(rows.items()):
        vuln, arches = row["vuln"], sorted(row["arches"])
        # On every architecture the release has, the product is the image. On one alone,
        # it is the image for that architecture, and the statement says so.
        only = arches if arches != every else [""]
        where = f" Found in {vuln.get('target')}." if vuln.get("target") else ""
        on = f" On {', '.join(arches)} alone." if arches != every else ""
        statement: dict = {
            "vulnerability": {"name": identifier},
            "products": [{"@id": image_purl(image, digest, arch),
                          "identifiers": {"purl": image_purl(image, digest, arch)},
                          "subcomponents": [{"@id": package_purl(vuln)}]} for arch in only],
        }
        entry = said.get((identifier, package), {})
        if row["kind"] == "unfixed":
            statement["status"] = "under_investigation"
            statement["status_notes"] = (
                f"{package} {installed} has no fixed version yet, so the release ships with "
                f"it.{where}{on}")
        elif entry.get("justification"):
            if entry["justification"] not in JUSTIFICATIONS:
                raise Unreadable(f"{identifier} in {package}: `{entry['justification']}` is "
                                 "not one of OpenVEX's justifications")
            statement["status"] = "not_affected"
            statement["justification"] = entry["justification"]
            statement["impact_statement"] = (
                f"{entry.get('reason') or 'Stated by the maintainer.'} The maintainer's "
                f"statement, reviewed again by {vuln.get('expires')}.{on}")
        else:
            statement["status"] = "affected"
            statement["action_statement"] = (
                f"Accepted by the maintainer until {vuln.get('expires')}: "
                f"{entry.get('reason') or 'no reason recorded'} {package} {installed} is "
                f"fixed in {vuln.get('fixed')}.{where}{on}")
        made.append(statement)
    return made


def document(made: list[dict], *, release: str, timestamp: str) -> dict:
    return {"@context": CONTEXT,
            "@id": f"{DOWNLOAD}/v{release}/valvur-{release}.openvex.json",
            "author": AUTHOR, "timestamp": timestamp, "version": 1, "tooling": TOOLING,
            "statements": made}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("verdicts", nargs="+", type=Path)
    parser.add_argument("--image", required=True, help="the repository, without a tag")
    parser.add_argument("--digest", required=True, help="the index's, as sha256:…")
    parser.add_argument("--release", required=True, help="the version, as 1.7.0")
    parser.add_argument("--timestamp", help="ISO 8601; the clock by default")
    parser.add_argument("--accepted", type=Path, default=image_gate.ACCEPTED)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    timestamp = args.timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        verdicts = [(_arch(path), _read(path)) for path in args.verdicts]
        try:
            entries = image_gate.accepted_entries(args.accepted.read_text(encoding="utf-8"))
        except (OSError, image_gate.Unreadable) as error:
            raise Unreadable(f"{args.accepted}: {error}") from error
        made = statements(verdicts, entries, args.image, args.digest)
    except Unreadable as error:
        print(f"image vex: {error}", file=sys.stderr)
        return 2
    if not made:
        print("image vex: nothing to state, so no document: every vulnerability the image's "
              "Trivy found has a fix in the image")
        return 0
    args.out.write_text(json.dumps(document(made, release=args.release, timestamp=timestamp),
                                   indent=2) + "\n", encoding="utf-8")
    print(f"image vex: {len(made)} statement(s) in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
