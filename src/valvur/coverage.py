"""Coverage contracts — what each Scanner and Check inspects, and what it does not.

**A Scanner that did not look is not a Scanner that found nothing.** valvur already
says so for a Scanner that did not *run* (`scanners_skipped`, `scanners_not_run`).
This module covers the harder case: a Scanner that ran, completed, and quietly did not
read half of what the reader assumed it did.

Two things made this a module rather than a comment:

**It has to work with no network.** Task 19.D.3 put coverage reporting inside the
Dependency Reality Check, which is registered `needs_network=True` and therefore
excluded from the default `offline` Profile. The gap is a static fact about which
files exist on disk — it needs no socket — so the one message that says *this scan
could not help you* was absent from the Profile almost everyone runs. Measured on a
local corpus, 2026-09-10: an npm project on `offline` reported no gap; the same
project on `full` reported three.

**A coverage gap is not a Profile omission.** They are different claims and both are
true at once. "The dependency-reality Check did not run on this Profile" is
Provenance. "Even on the fullest Profile, nothing here reads your `Cargo.toml`" is a
product limit, and stays true whichever Profile you choose. Reporting them through one
mechanism would make the permanent limit look like a flag you forgot to pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from . import ecosystems as _ecosystems
from . import fingerprint as _fp
from .findings import Finding, Severity

# The note rules are the verdict's (D52b): defined there, named here as ever.
from .verdict import (
    DOUBT_RULES,
    LICENCE_STATEMENT_RULES,
    NOTE_RULES,
    PRIVATE_RULE,
    RULE,
    VULNERABILITY_RULE,
)

__all__ = ["DOUBT_RULES", "LICENCE_STATEMENT_RULES", "NOTE_RULES", "PRIVATE_RULE", "RULE",
           "VULNERABILITY_RULE"]


@dataclass(frozen=True)
class Coverage:
    """What one adapter declares about its own reach.

    The default is empty rather than optimistic: an adapter that has not thought about
    its limits should not be recorded as having none.
    """

    inspects: tuple[str, ...] = ()
    """Inputs this adapter reads, in the reader's terms."""

    ignores: tuple[str, ...] = ()
    """Inputs it deliberately does not read, and why a reader might expect otherwise."""

    gaps: tuple[Finding, ...] = field(default=())
    """Gaps found in *this* Workspace — empty when the limits do not bite here."""

    def declared(self) -> bool:
        return bool(self.inspects or self.ignores)


def _representative(paths: list[str], order: tuple[str, ...]) -> str:
    """The path a reader should open first.

    Shallowest first, then the manifest's position in its ecosystem's declared order,
    then alphabetical. Previously this took whatever `rglob` yielded, which pointed a
    monorepo's npm gap at `infra/package.json` rather than the root `package.json`.

    The declared order matters as much as the depth: `Cargo.lock` and `Cargo.toml` sit
    at the same depth and "Cargo.lock" sorts first alphabetically, so a plain
    depth-then-name rule sent the reader to the generated file rather than the one they
    wrote. Every `sees` tuple lists its manifest before its lockfile.
    """
    def rank(path: str) -> tuple[int, int, str]:
        name = path.rsplit("/", 1)[-1]
        position = next(
            (i for i, pattern in enumerate(order) if fnmatch(name, pattern)), len(order)
        )
        return (path.count("/"), position, path)

    return min(paths, key=rank)


def _listed(workspace: Path, files: list[str] | None) -> list[str]:
    """The File Set (ADR-0021, R3.9), as the scan's context holds it when given: an
    installed `node_modules` is full of other people's manifests, and git ignores
    it, so it is not what was scanned."""
    from . import fileset
    from .refusal import Refusal

    if files is not None:
        return files
    try:
        return fileset.build(workspace).files
    except Refusal:
        return [p.relative_to(workspace).as_posix() for p in workspace.rglob("*")
                if p.is_file()]


def _present(
    workspace: Path, patterns: tuple[str, ...], exclude: tuple[str, ...],
    listed: list[str],
) -> list[str]:
    found: list[str] = []
    for pattern in patterns:
        for relative in listed:
            if not fnmatch(relative.rsplit("/", 1)[-1], pattern):
                continue
            # A configured exclusion says a path is not part of what this project
            # asked to be scanned, so its manifests are neither a gap nor a candidate
            # to represent one. Applied HERE rather than by filtering the Finding
            # afterwards: the representative path is the shallowest, so an excluded
            # `vendor/Cargo.toml` would otherwise be chosen to stand for a real
            # `crates/app/Cargo.toml` and take the whole gap down with it.
            if any(relative == e or relative.startswith(e.rstrip("/") + "/") for e in exclude):
                continue
            found.append(relative)
    return sorted(set(found))


def dependency_gaps(workspace: Path, exclude: tuple[str, ...] = (),
                    files: list[str] | None = None) -> list[Finding]:
    """One Finding per ecosystem whose dependencies nothing here verifies.

    Per **ecosystem**, never per file: a monorepo with forty `package.json` files has
    one gap, not forty. Keyed on the canonical ecosystem name from `ecosystems.py`, so
    `pnpm-lock.yaml` and `package.json` cannot become two.

    An ecosystem with at least one readable manifest present is not reported, even when
    unreadable ones sit beside it — `poetry.lock` next to a `pyproject.toml` is a
    resolved tree we skip on purpose, not a hole.
    """
    findings: list[Finding] = []
    listed = _listed(workspace, files)

    for key, manifests in sorted(_ecosystems.MANIFESTS.items()):
        seen = _present(workspace, manifests.sees, exclude, listed)
        if not seen:
            continue
        if _present(workspace, manifests.reads, exclude, listed):
            continue          # something readable covers this ecosystem

        shown = ", ".join(seen[:3])
        more = f" and {len(seen) - 3} more" if len(seen) > 3 else ""
        readable = (
            f"It reads {' and '.join(manifests.reads)} for this ecosystem, and none is "
            "present here."
            if manifests.reads else
            f"valvur has no existence check for {manifests.label} at all."
        )
        findings.append(Finding(
            rule=RULE,
            path=_representative(seen, manifests.sees),
            line=0,
            severity=Severity.LOW,
            title=f"{manifests.label} dependencies were not checked for existence",
            evidence=(
                f"Found {shown}{more}. {readable} No {manifests.label} dependency here "
                "was verified to exist, so this is missing coverage rather than a clean "
                "result. Hallucinated and typosquatted packages in this ecosystem would "
                "not have been reported."
            ),
            # Identity is the canonical ecosystem key, never the display label — the
            # label is what produced the pnpm/npm double-count (task 19.D.1, C4).
            fingerprint=_fp.derive("dependency_reality_gap", key),
            sources=("dependency-reality",),
        ))

    return findings


def vulnerability_gaps(workspace: Path, exclude: tuple[str, ...] = (),
                       files: list[str] | None = None) -> list[Finding]:
    """One Finding per ecosystem present whose dependencies Trivy could not check.

    The mirror of `dependency_gaps`, for the other question. Trivy needs a lockfile
    for npm, Ruby and Rust and a pinned requirements file for Python; a repository
    that commits only `package.json` has its thirty dependencies scanned by nothing,
    and Trivy reports no result rather than an error. `ecosystems.VULNERABILITY_
    MANIFESTS` records what was measured; this says when none of it is present.
    """
    findings: list[Finding] = []
    listed = _listed(workspace, files)
    for key, manifests in sorted(_ecosystems.MANIFESTS.items()):
        present = _present(workspace, manifests.reads + manifests.sees, exclude, listed)
        if not present:
            continue
        readable = _ecosystems.VULNERABILITY_MANIFESTS.get(key, ())
        found = _present(workspace, readable, exclude, listed)
        if found:
            # Present is not the same as a check for Python (25.3): a requirements
            # file of ranges is read by Trivy and reports nothing.
            if key != "pip":
                continue
            evidence = _unpinned_requirements(workspace, found)
            if evidence is None:
                continue
        else:
            shown = ", ".join(present[:3])
            evidence = (
                f"Found {shown}. Trivy reads {' or '.join(readable)} for this ecosystem "
                "and none is present, so it reported nothing — not zero vulnerabilities, "
                "no scan. Commit a lockfile (or a pinned requirements file) and rescan; "
                "until then this is missing coverage, not a clean result."
            )
        findings.append(Finding(
            rule=VULNERABILITY_RULE,
            path=_representative(present, manifests.reads + manifests.sees),
            line=0,
            severity=Severity.LOW,
            title=f"{manifests.label} dependencies were not checked for known vulnerabilities",
            evidence=evidence,
            # The same identity as the lockfile gap: one note per ecosystem, and a
            # suppression of it travels between the two causes.
            fingerprint=_fp.derive("trivy_gap", key),
            sources=("trivy",),
        ))
    return findings


def _unpinned_requirements(workspace: Path, found: list[str]) -> str | None:
    """The evidence for a Python gap that is not a missing file but an unpinned one
    (task 25.3), or None when the files present are a check.

    A lockfile is the resolved truth and settles it. Without one, a requirements
    file is a check only for its pinned lines: Trivy reads those and no others, so
    a file of ranges reads as checked while nothing was, and a mixed file is
    *partly* checked — the note says how much, per file.
    """
    from . import requirements as _requirements

    if any(not _requirements.is_requirements_file(rel) for rel in found):
        return None                                   # a lockfile is present
    unpinned: list[str] = []
    for rel in found:
        pinned, loose = _requirements.pins(workspace / rel)
        if loose:
            unpinned.append(f"{rel} ({loose} of {pinned + loose} lines are ranges)")
    if not unpinned:
        return None
    shown = "; ".join(unpinned[:3])
    more = f"; and {len(unpinned) - 3} more" if len(unpinned) > 3 else ""
    return (
        f"Unpinned: {shown}{more}. A range is not a version — Trivy checks pinned "
        "lines only and reported nothing for these, and on `full` OSV-Scanner's "
        "answers for them are evaluated at each range's lower bound and are not "
        "shown. Pin them (`==`) or commit a lockfile and rescan; until then this is "
        "missing coverage, not a clean result."
    )


def collect(adapters, workspace: Path, exclude: tuple[str, ...] = (),
            context=None) -> dict[str, dict]:
    """Every adapter's declared coverage, for Provenance (task 19.E.1).

    Called over the whole registry rather than the Profile's selection: a limit does
    not stop being true because a Profile skipped the Scanner that has it.
    """
    declared: dict[str, dict] = {}
    for adapter in adapters:
        coverage = adapter.coverage(workspace, exclude, context)
        if not coverage.declared():
            continue
        declared[adapter.name] = {
            "inspects": list(coverage.inspects),
            "ignores": list(coverage.ignores),
        }
    return declared
