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

**Every ID cited is defined** (R17.2, D43) is the third, and has no baseline because it
has no debt. N3.4 and N3.5 were cited by decisions, scripts, tests and a workflow for
the whole R9 to R16 build and defined nowhere; this check did not look. Requirement IDs
are never renumbered, so an ID that resolves nowhere is always a mistake, in the
archives as much as in the code.

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


#: Where a requirement ID can be cited (R17.2): every document, the code, the tests and
#: the workflows. `requirements.md` is among them, so an amendment naming a missing ID
#: is caught too.
CITING = (".kiro", "docs", "src", "scripts", "tests", ".github", "README.md",
          "CHANGELOG.md", "CONTRIBUTING.md", "CLAUDE.md", "SECURITY.md")
_CITED_ID = re.compile(r"\b([FN]\d+\.\d+)\b")


def requirement_ids(root: Path | None = None) -> set[str]:
    root = REPO if root is None else root
    text = (root / ".kiro" / "specs" / "valvur" / "requirements.md").read_text()
    return set(re.findall(r"\b([FNP]\d+(?:\.\d+)?)\s+—", text))


def _citing_files(root: Path):
    for name in CITING:
        path = root / name
        candidates = [path] if path.is_file() else sorted(path.rglob("*")) if path.is_dir() else []
        for candidate in candidates:
            if (candidate.is_file() and candidate.suffix in SUFFIXES
                    and candidate.name != BASELINE.name):
                yield candidate


def undefined_citations(root: Path | None = None) -> dict[str, str]:
    """Each requirement ID cited somewhere and defined nowhere, to where it is first
    cited, `path:line`."""
    root = REPO if root is None else root
    defined, found = requirement_ids(root), {}
    for path in _citing_files(root):
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            for match in _CITED_ID.finditer(line):
                if match[1] not in defined and match[1] not in found:
                    found[match[1]] = f"{path.relative_to(root).as_posix()}:{number}"
    return found


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

    for cited, where in sorted(undefined_citations().items()):
        print(f"::error::requirement cited but defined nowhere: {cited}, first at {where}")
        failed = True

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
            "whichever is actually true. An ID defined nowhere is a typo or a "
            "requirement never written: write it, or cite the one meant."
        )
        return 1

    print(f"traceability holds: {len(uncited)} uncited, {len(orphans)} orphan ADRs, "
          "neither grew; every cited ID is defined")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
