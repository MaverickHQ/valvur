"""A Scanner's upgrade, completed: every pin moved with its stage's (R47.2, D81v, N3.9).

    uv run python scripts/scanner_upgrade.py trivy 0.75.0 0.76.0 [--root DIR]

Dependabot moves a Scanner's stage (its `FROM`, Opengrep's release `ARG`s, or its
hash-locked requirements) and nothing else, so its pull requests stay red until the rest
move too (#229, #230, #238). This moves the rest, as R47.1 lists them: the adapter's
`VERSION`, the golden's pin in `tests/conftest.py`, `docs/PROTOCOL.md`'s table, and
Opengrep's signature check. It names the golden the new binary must be recaptured into,
and never writes one. Each pin must read the old version exactly once, or nothing is
written. Prints `{"scanner", "from", "to", "changed", "recapture"}`. Standard library
alone.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


#: Each Scanner's adapter module, under `src/valvur/adapters/`.
ADAPTERS = {"gitleaks": "gitleaks", "trivy": "trivy", "osv-scanner": "osv", "syft": "syft",
            "opengrep": "opengrep", "checkov": "checkov", "zizmor": "zizmor"}
#: Scanners whose output conftest builds, so they have no golden to recapture.
NO_GOLDEN = {"gitleaks"}


def _pins(tool: str, old: str, new: str) -> list[tuple[str, str, str]]:
    """Each pin as (file, what it reads today, what it reads after)."""
    q = re.escape
    pins = [
        (f"src/valvur/adapters/{ADAPTERS[tool]}.py",
         rf'^VERSION = "{q(old)}"$', f'VERSION = "{new}"'),
        ("tests/conftest.py", rf'(?<="{q(tool)}": )"{q(old)}"', f'"{new}"'),
        ("docs/PROTOCOL.md", rf"^(\| `{q(tool)}` \|[^\n]*\| ){q(old)}( \|)$", rf"\g<1>{new}\g<2>"),
    ]
    if tool == "opengrep":
        pins.append(("scripts/verify-opengrep.sh",
                     rf'^VERSION="\$\{{OPENGREP_VERSION:-v{q(old)}\}}"$',
                     f'VERSION="${{OPENGREP_VERSION:-v{new}}}"'))
    return pins


class LeftForOwner(Exception):
    """The upgrade is not one this script completes, with why."""


def update(root: Path, tool: str, old: str, new: str) -> list[str]:
    """Move every pin from `old` to `new`; the files changed. All or none."""
    if tool not in ADAPTERS:
        raise LeftForOwner(f"{tool!r} is not a Scanner this script knows: "
                           f"one of {', '.join(sorted(ADAPTERS))}")
    written: dict[str, str] = {}
    for name, pattern, replacement in _pins(tool, old, new):
        text = written.get(name) or (root / name).read_text(encoding="utf-8")
        after, count = re.subn(pattern, replacement, text, flags=re.M)
        if count != 1:
            raise LeftForOwner(f"{name} pins {tool} {old} {count} times, not once")
        written[name] = after
    for name, text in written.items():
        (root / name).write_text(text, encoding="utf-8")
    return sorted(written)


def golden(tool: str, version: str) -> list[str]:
    return [] if tool in NO_GOLDEN else [f"tests/fixtures/golden/{tool}-{version}.json"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scanner")
    parser.add_argument("old", help="the version every other pin reads today")
    parser.add_argument("new", help="the version the stage now pins")
    parser.add_argument("--root", type=Path, default=REPO, help="the tree (default: this one)")
    args = parser.parse_args(argv)
    try:
        changed = update(args.root, args.scanner, args.old, args.new)
    except LeftForOwner as why:
        print(f"left for the owner: {why}", file=sys.stderr)
        return 3
    print(json.dumps({"scanner": args.scanner, "from": args.old, "to": args.new,
                      "changed": changed, "recapture": golden(args.scanner, args.new)},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
