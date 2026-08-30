#!/usr/bin/env python3
"""Verify F10.4: valvur adds no GPL/AGPL component of its own.

The check is a **diff against the base image**. Every Linux container carries GPL in
its userland — busybox, apk-tools, musl-utils — and no image can avoid that. What we
can control, and what ADR-0005 actually cares about, is what *we* install.

Uses syft, which we already ship. A hand-rolled pass over Python package metadata
reported "96 packages, all clean" while syft found 2,227 components and 12 GPL ones:
the Python layer was never where the risk was.

    python scripts/check_image_licences.py valvur:dev python:3.12-alpine3.22
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

SYFT = "anchore/syft:v1.51.1"
COPYLEFT = re.compile(r"\b(AGPL|GPL|SSPL|OSL|EUPL)\b", re.IGNORECASE)

# LGPL is permitted: we ship Opengrep (LGPL-2.1) as an unmodified binary invoked as a
# subprocess, which is aggregation rather than a derivative work (ADR-0004).
LGPL = re.compile(r"\bLGPL\b", re.IGNORECASE)


def sbom(image: str) -> dict:
    """Generate an SBOM for an image with syft.

    A partial executable path is correct here: the container runtime is whatever the
    operator has on PATH, and hard-coding an absolute path would break every machine
    whose Docker lives elsewhere. Argument-list form, never a shell.
    """
    result = subprocess.run(  # noqa: S603
        [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            SYFT, image, "-o", "cyclonedx-json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def licences(component: dict) -> set[str]:
    out = set()
    for entry in component.get("licenses", []) or []:
        licence = entry.get("license", {}) or {}
        value = licence.get("id") or licence.get("name") or entry.get("expression")
        if value:
            out.add(str(value))
    return out


def added_components(image: str, base: str) -> list[dict]:
    ours = sbom(image).get("components", [])
    base_keys = {(c.get("name"), c.get("version")) for c in sbom(base).get("components", [])}
    return [c for c in ours if (c.get("name"), c.get("version")) not in base_keys]


def offending(components: list[dict]) -> list[tuple[str, str]]:
    found = []
    for component in components:
        for licence in licences(component):
            if COPYLEFT.search(licence) and not LGPL.search(licence):
                found.append((component.get("name", "?"), licence))
    return found


def main(argv: list[str]) -> int:
    image = argv[0] if argv else "valvur:dev"
    base = argv[1] if len(argv) > 1 else "python:3.12-alpine3.22"

    added = added_components(image, base)
    problems = offending(added)

    print(f"components added by valvur over {base}: {len(added)}")
    if problems:
        print(f"\nFAIL — {len(problems)} GPL/AGPL component(s) deliberately added:")
        for name, licence in problems:
            print(f"  {name}: {licence}")
        print("\nSee ADR-0005. Base-image GPL is expected and disclosed in the SBOM;")
        print("components valvur installs are not.")
        return 1

    print("OK — no GPL or AGPL component is added by valvur.")
    print("Base-image GPL components are expected, unavoidable, and disclosed in the")
    print("published SBOM (F10.4 as corrected).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
