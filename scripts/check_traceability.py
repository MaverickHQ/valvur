#!/usr/bin/env python3
"""Requirements and code must stay in step — in both directions (task 17.2).

**Requirement → code** catches an ID nobody implemented. That is the easy direction
and the one a traceability check usually stops at.

**Code → requirement** is the direction that actually drifted. Five behaviours built
across Phases 13 to 16 had no requirement ID at all until task 17.0 added them, and
nothing would have noticed: an audit of citations only ever finds requirements the
code forgot, never code the requirements forgot. This approximates the second
direction by requiring every ADR — where decisions land before code does — to cite at
least one requirement.

Both checks are **ratchets against a recorded baseline**. Neither fails on the debt
that exists today; both fail the moment it grows. A check that fails on day one is a
check somebody disables in week two.

    python3 scripts/check_traceability.py          # verify
    python3 scripts/check_traceability.py --update # re-record the baseline
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "docs" / "traceability-baseline.toml"
SEARCHED = ("src", "tests", "scripts", ".github", "docs")
SUFFIXES = {".py", ".yml", ".yaml", ".md", ".sh", ".toml"}


def requirement_ids() -> set[str]:
    text = (REPO / ".kiro" / "specs" / "valvur" / "requirements.md").read_text()
    return set(re.findall(r"\b([FNP]\d+(?:\.\d+)?)\s+—", text))


def _cited_anywhere() -> str:
    parts = []
    for directory in SEARCHED:
        for path in (REPO / directory).rglob("*"):
            # Two files must not count as citations. The requirements document
            # names every ID by definition, and the baseline file lists precisely
            # the uncited ones — including it made every ID look cited the moment
            # the baseline was written, which the first run reported as 25
            # requirements resolving simultaneously.
            if path.name in {"requirements.md", BASELINE.name}:
                continue
            if path.is_file() and path.suffix in SUFFIXES:
                parts.append(path.read_text(errors="ignore"))
    return "\n".join(parts)


def uncited_requirements() -> set[str]:
    blob = _cited_anywhere()
    return {i for i in requirement_ids() if not re.search(rf"\b{re.escape(i)}\b", blob)}


def adrs_citing_nothing() -> set[str]:
    known = requirement_ids()
    orphans = set()
    for adr in sorted((REPO / "docs" / "adr").glob("*.md")):
        cited = set(re.findall(r"\b[FNP]\d+(?:\.\d+)?\b", adr.read_text())) & known
        if not cited:
            orphans.add(adr.stem)
    return orphans


def _load_baseline() -> tuple[set[str], set[str]]:
    if not BASELINE.is_file():
        return set(), set()
    data = tomllib.loads(BASELINE.read_text())
    return set(data.get("uncited_requirements", [])), set(data.get("adrs_citing_nothing", []))


def _write_baseline(uncited: set[str], orphans: set[str]) -> None:
    def key(i: str) -> tuple:
        return (i[0], *(int(n) for n in re.findall(r"\d+", i)))

    BASELINE.write_text(
        "# Traceability debt, recorded so it can only shrink (task 17.2).\n"
        "#\n"
        "# These are not acceptable, they are *known*. The check in\n"
        "# scripts/check_traceability.py fails when either list grows, and tells you\n"
        "# to shrink this file when it could. Re-record with:\n"
        "#\n"
        "#     python3 scripts/check_traceability.py --update\n"
        "\n"
        "# Requirement IDs cited in no source file, test, script, workflow or doc.\n"
        "uncited_requirements = [\n"
        + "".join(f'  "{i}",\n' for i in sorted(uncited, key=key))
        + "]\n\n"
        "# ADRs that cite no requirement, so the decision cannot be traced to what it\n"
        "# was deciding about.\n"
        "adrs_citing_nothing = [\n"
        + "".join(f'  "{a}",\n' for a in sorted(orphans))
        + "]\n"
    )


def main(argv: list[str]) -> int:
    uncited, orphans = uncited_requirements(), adrs_citing_nothing()

    if "--update" in argv:
        _write_baseline(uncited, orphans)
        print(f"baseline recorded: {len(uncited)} uncited, {len(orphans)} orphan ADRs")
        return 0

    known_uncited, known_orphans = _load_baseline()
    failed = False

    for label, now, before in (
        ("requirement cited nowhere", uncited, known_uncited),
        ("ADR citing no requirement", orphans, known_orphans),
    ):
        new = now - before
        for item in sorted(new):
            print(f"::error::new {label}: {item}")
            failed = True
        fixed = before - now
        if fixed:
            print(
                f"{len(fixed)} {label}(s) resolved: {', '.join(sorted(fixed))}. "
                "Re-record with `python3 scripts/check_traceability.py --update`."
            )

    if failed:
        print(
            "\nTraceability regressed. Either cite the requirement where the "
            "behaviour lives, or add the requirement the behaviour needs — "
            "whichever is actually true."
        )
        return 1

    print(f"traceability holds: {len(uncited)} uncited, {len(orphans)} orphan ADRs, "
          "neither grew")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
