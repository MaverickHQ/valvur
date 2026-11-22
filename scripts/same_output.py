#!/usr/bin/env python3
"""Do two images give one output from every Scanner (R45.6, D81aa, Requirement 21.3).

    python3 scripts/same_output.py --released ghcr.io/maverickhq/valvur:latest --new valvur:dev

An image patch releases itself only when nothing a scan depends on has moved. This runs each
Scanner's golden recipe (`scanner_upgrade.RECIPES`) in the latest release's image and in the
new one, on this machine's one copy of the data, and compares the two outputs as a recapture
is judged (R47.3): after each run's identity is blanked, and Checkov's checks sorted.

It does not compare with a committed golden. Trivy's and OSV-Scanner's output on a fixture
changes whenever an advisory is published, so that comparison would fail on a day valvur did
not change. Two images on one day's data differ only if the images do.

Nothing is assumed equal: an image that cannot be run, and a Scanner that gives no output,
fail it. Gitleaks has no recipe (R47.1) and is not compared. Exit 0 when every Scanner gives
one output from both images, 1 otherwise, naming each.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scanner_upgrade

#: Every Scanner with a recipe.
TOOLS = tuple(sorted(scanner_upgrade.RECIPES))


def runtime_for(image: str) -> object:
    """The Scan Container of one image. The tests stand in for it."""
    from valvur.engine_host import ContainerRuntime  # deferred: the unit tests never run one

    return ContainerRuntime(image=image)


def _captured(tool: str, image: str) -> tuple[object | None, str]:
    """(the Scanner's comparable report from `image`, why there is none)."""
    try:
        report = scanner_upgrade.capture(tool, runtime_for(image))
    except Exception as error:  # whatever stopped the container, the two are not equal
        return None, f"{tool} could not be run in {image}: {error}"
    if not report.strip():
        return None, f"{tool} gave no output from {image}"
    try:
        return scanner_upgrade.comparable(tool, report), ""
    except ValueError as error:
        return None, f"{tool}'s output from {image} could not be read: {error}"


def differences(released: str, new: str, tools: tuple[str, ...] = TOOLS) -> list[str]:
    """Each Scanner whose output differs between the two images, or could not be had."""
    found = []
    for tool in tools:
        before, why = _captured(tool, released)
        after, why_new = _captured(tool, new) if before is not None else (None, "")
        if before is None or after is None:
            found.append(why or why_new)
        elif before != after:
            found.append(f"{tool}: its output on {scanner_upgrade.RECIPES[tool][0]} differs "
                         f"between {released} and {new}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--released", required=True, help="the latest release's image")
    parser.add_argument("--new", required=True, help="the image about to be released")
    parser.add_argument("--tool", action="append", choices=TOOLS,
                        help="compare this Scanner alone; every one with a recipe by default")
    args = parser.parse_args(argv)
    tools = tuple(args.tool) if args.tool else TOOLS
    found = differences(args.released, args.new, tools)
    for line in found:
        print(line)
    if not found:
        print(f"{len(tools)} Scanners give one output from both images: {', '.join(tools)}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
