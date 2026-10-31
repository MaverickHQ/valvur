"""Each Scanner's pinned version, and what moved since a release (R16.3, D34).

    uv run python scripts/scanner_pins.py --since v1.1.0 [--github-output FILE]

The image pins each Scanner in the Dockerfile, by the release it builds from source (D81w)
or Opengrep's release URL, or in a hash-locked requirements file. This is the one parser
of those pins: `test_scanner_pins.py` holds each adapter's version to it, and
`refresh.yml` asks it what moved on `main` since the latest release, reading the
release's files from its tag. Prints `{"since", "moved"}`; with `--github-output`,
appends `changed=true` or `changed=false` for the workflow.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

Reader = Callable[[str], str]

#: The Scanners built from their release's source (Gitleaks since 2026-10-25, the rest by
#: D81w): each one's `ARG` prefix, the image a release before then pinned instead, which
#: `--since` reads from its tag, and its Go module.
SOURCES = (("gitleaks", "GITLEAKS", "zricethezav/gitleaks", "github.com/zricethezav/gitleaks/v8"),
           ("trivy", "TRIVY", "aquasec/trivy", "github.com/aquasecurity/trivy"),
           ("osv-scanner", "OSV_SCANNER", "ghcr.io/google/osv-scanner",
            "github.com/google/osv-scanner/v2"),
           ("syft", "SYFT", "anchore/syft", "github.com/anchore/syft"))
#: The Scanners installed from a hash-locked requirements file.
LOCKS = (("checkov", "requirements-checkov.txt"), ("zizmor", "requirements-zizmor.txt"))


def in_tree(root: Path) -> Reader:
    return lambda name: (root / name).read_text()


def at_ref(root: Path, ref: str) -> Reader:
    """The files as `ref` holds them: a release's tag, say."""
    def read(name: str) -> str:
        return subprocess.run(["git", "-C", str(root), "show", f"{ref}:{name}"],  # noqa: S603
                              capture_output=True, text=True, check=True).stdout
    return read


def _need(match: re.Match[str] | None, missing: str) -> str:
    if match is None:
        raise ValueError(missing)
    return match.group(1)


def pins(read: Reader) -> dict[str, str]:
    """Each Scanner's version, as the image pins it."""
    dockerfile = read("Dockerfile")
    found: dict[str, str] = {}
    for stage, arg, image, _ in SOURCES:
        found[stage] = _need(re.search(rf"^ARG {arg}_VERSION=([\d.]+)$", dockerfile, re.M)
                             or re.search(rf"^FROM {re.escape(image)}:v?([\d.]+)@sha256:",
                                          dockerfile, re.M),
                             f"the Dockerfile no longer names {stage}'s release")
    found["opengrep"] = _need(re.search(r"^ARG OPENGREP_URL=\S+/download/v([\d.]+)$",
                                        dockerfile, re.M),
                              "the Dockerfile no longer names Opengrep's release")
    for tool, lock in LOCKS:
        found[tool] = _need(re.search(rf"^{tool}==([\d.]+) ", read(lock), re.M),
                            f"{lock} no longer pins {tool}")
    return found


def changed(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str | None]]:
    """Each Scanner whose pin differs, to [before, after]; None where it is absent."""
    return {tool: [before.get(tool), after.get(tool)]
            for tool in sorted(set(before) | set(after))
            if before.get(tool) != after.get(tool)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", required=True, metavar="REF",
                        help="the release to compare with, by its tag")
    parser.add_argument("--github-output", type=Path, metavar="FILE",
                        help="append changed=true|false here, for a workflow step")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    moved = changed(pins(at_ref(root, args.since)), pins(in_tree(root)))
    print(json.dumps({"since": args.since, "moved": moved}, indent=2))
    if args.github_output:
        with args.github_output.open("a") as out:
            out.write(f"changed={'true' if moved else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
