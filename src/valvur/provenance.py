"""The record — per-Scanner outcomes, and `run.json`, which is what actually ran,
what failed, and why.

Without this a clean result is unfalsifiable: you cannot distinguish "no
vulnerabilities" from "every Scanner silently exited 1". For a tool whose output
gates a release, that distinction is the whole point (N3.1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import cache as _cache
from . import egress as _egress
from . import profiles as _profiles
from . import staleness as _staleness
from .fingerprint import FP_VERSION

if TYPE_CHECKING:
    from .api import ScanRun


@dataclass(frozen=True)
class ScannerRun:
    tool: str
    ok: bool
    version: str = ""
    reason: str = ""
    # A third state, distinct from both. A Scanner with nothing to analyse has not
    # failed, and the Scan Run is still complete — but it has not run either, and
    # letting that look identical to "ran and found nothing" is how a conditional
    # Scanner silently stops working.
    skipped: bool = False
    #: Wall-clock seconds this Scanner took, container start to report read (23.3.2).
    #: The fleet runs concurrently, so a scan takes about as long as its slowest —
    #: which is how a user finds the Checkov cost, and how 23.4.2 is measured.
    duration_s: float = 0.0
    #: The command line the runner launched after the image name, from the
    #: Invocation (28.3.6): what produced the raw output, beside its version and
    #: duration. Empty when nothing was launched.
    argv: tuple[str, ...] = ()

    @property
    def failed(self) -> bool:
        return not self.ok


def render(run: ScanRun) -> str:
    """`run.json`: what actually ran. Makes a clean result falsifiable (N3.1).

    Here since 28.1.1, beside the record's own type; it was `results._provenance`,
    a hundred and twenty lines of rendering inside the module whose job is the
    atomic write — the same split 27.3.3 made for `SUMMARY.md`. `results.write`
    calls this as it calls every other document's renderer.
    """

    return (
        json.dumps(
            {
                "schema": 1,
                "fp_version": FP_VERSION,
                # This Scan Run's id; the same value in findings.json, state.json
                # and results.sarif, and run.json is the last of them written, so
                # a sibling with a different one is from another run (26.0.3).
                "generation": run.generation,
                # F5.3 / task 17.4: history was discarded because identity changed.
                "identity_reset": list(run.identity_reset) if run.identity_reset else None,
                "status": run.status,
                # One line, one field, the same words on every surface (22.D.4).
                "status_reason": run.status_reason,
                # Which profile ran, and what it therefore did not look at. Without
                # this, run.json cannot tell you a class was out of scope.
                "profile": run.profile,
                # Scanners that had nothing to analyse. Distinct from a failure —
                # the run is still complete — and distinct from finding nothing.
                "scanners_skipped": {
                    s.tool: s.reason
                    for s in run.scanners if s.skipped
                },
                "scanners_not_run": list(
                    _profiles.not_run(run.profile)
                ),
                # What each Scanner and Check reads, and what it deliberately does
                # not (task 19.E.1). Distinct from the two fields above: those say a
                # Scanner did not run, this says what it does not look at even when
                # it does. A reader asking "was my Cargo.toml checked?" has nowhere
                # else to find out.
                "coverage": run.coverage,
                # An incomplete scan reporting "clean" would be a lie of omission.
                # This is the single field an agent should check first.
                "complete": not run.failures,
                # Reported, not silent: a user who vendored a vulnerable copy
                # deserves to know we skipped it.
                "excluded_vendored": run.vendored_dropped,
                # What this project chose not to scan, and how much it cost. An
                # exclusion the reader cannot see is indistinguishable from a
                # scanner that found nothing.
                # The scan budget in force and what it cut (23.3.7); None when none.
                "budget": ({"seconds": run.budget_s, "cut": list(run.budget_cut)}
                           if run.budget_s is not None else None),
                # The tree the shim and the image were built from (23.4.4). `match`
                # is None when either side is unrecorded — nothing to compare.
                "build": {"shim": run.shim_built_from, "image": run.image_built_from,
                          "match": run.build_match},
                "excluded_by_config": {
                    "paths": list(run.excluded_paths),
                    "findings_dropped": run.config_dropped,
                },
                # OSV-Scanner's answers against the lower bounds of unpinned ranges
                # (25.3): not the project's Findings, and not silently gone either.
                "excluded_unpinned": {
                    "advisories_dropped": run.unpinned_dropped,
                    "files": list(run.unpinned_files),
                },
                # Stated plainly, because we criticise competitors for being vague
                # about exactly this. Package NAMES (never source) are sent to public
                # registries by the dependency-reality Check, on `full` only.
                # F7.17. The vulnerability database, distinct from the enrichment
                # data below. This one determines whether findings exist at all, so a
                # clean result cannot be judged without it.
                "database": {
                    "age_days": _round_or_none(run.db_age_days),
                    "overdue_days": _round_or_none(run.db_overdue_days),
                    "stale": _staleness.db_is_stale(run),
                    "stale_after_days": _cache.DB_STALE_AFTER_DAYS,
                },
                # ADR-0018. The list of names that decides whether a dependency
                # EXISTS, as the database decides whether a CVE does. `present` is
                # false on a machine that has never run `valvur update`; then the
                # dependency-reality Check failed and `complete` above says so.
                "name_index": {
                    "present": run.name_index_age_days is not None,
                    "age_days": _round_or_none(run.name_index_age_days),
                    "stale": _staleness.index_is_stale(run),
                    "stale_after_days": _cache.NAME_INDEX_STALE_AFTER_DAYS,
                },
                "enrichment": {
                    "kev_source": run.kev_source,
                    "kev_age_days": round(run.kev_age_days or 0, 2),
                    "stale": (run.kev_age_days or 0) > 30,
                },
                # F6.10: what a network lookup transmitted, recorded exactly; the
                # opt-out is the default Profile, and `--offline` forces it.
                "network": {
                    "used": run.network_used,
                    "what_left_the_machine": _egress.disclosure(used=run.network_used),
                    # A first run's fetches (28.0.4): the image, the database, the
                    # index — each what/source/size_mb/seconds. `used` above is the
                    # Profile's own network; these are the sockets a first run
                    # opened before any Scanner ran, and this is where they are
                    # said. Empty, not absent, on a steady-state run.
                    "fetched": run.fetched,
                },
                # Broken out rather than a single total (task 19.C.1). One number
                # made an accepted risk, a live problem and a note about our own
                # missing coverage indistinguishable to every machine consumer.
                "findings": {
                    "active": len(run.active),
                    "suppressed": len(run.suppressed),
                    "not_covered": len(run.coverage_notes),
                    "total": len(run.findings),
                },
                "fixed": len(run.fixed),
                "scanners": [
                    {
                        "tool": s.tool,
                        "version": s.version,
                        "ok": s.ok,
                        "reason": s.reason,
                        "duration_s": round(s.duration_s, 1),
                        # The command line behind `raw/<tool>` (28.3.6).
                        "argv": list(s.argv),
                    }
                    for s in run.scanners
                ],
            },
            indent=2,
        )
        + "\n"
    )


def _round_or_none(value: float | None) -> float | None:
    """None is not zero. An unreadable database age must not read as "brand new" —
    that is precisely the confident-wrong-answer this phase removes."""
    return None if value is None else round(value, 2)
