"""Writes the Results Folder. Runs on the host, as the invoking user (ADR-0001)."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

from . import artifacts, rawoutput, remediation, summary
from . import egress as _egress
from .staleness import db_is_stale as _db_is_stale
from .staleness import index_is_stale as _index_is_stale
from .version import __version__ as _VERSION

if TYPE_CHECKING:
    # A ScanRun and nothing else (22.D.2). This module held 38 `getattr(run, …,
    # default)` calls defending against a duck-typed stub no test ever passed — the
    # tests all build a real ScanRun — so the defaults were dead code that could
    # silently paper over a renamed field. The type is what enforces it now; the
    # import is annotation-only because `api` imports this module.
    from .api import ScanRun

RESULTS_DIR = ".security-scan"


#: Artifacts a Scanner may or may not produce on a given run — today Syft's SBOM.
#: One this run did not produce is REMOVED, so a failed or skipped Syft cannot
#: leave the previous run's SBOM beside this run's findings (26.0.3); the same
#: rule `rawoutput.write` applies to `raw/*.json`. A test holds this equal to the
#: set of every adapter's `artifact`, so a new one cannot be forgotten.
OPTIONAL_ARTIFACTS = frozenset({"sbom.cdx.json"})

#: The suffix a document carries while it is being written, beside its final name.
STAGED = ".tmp"


def write(workspace: Path, run: ScanRun, scanner_artifacts=(), raw_outputs=(),
          state: str | None = None) -> Path:
    """The Results Folder, `.security-scan/` in the Workspace (F7.1): SUMMARY.md,
    REMEDIATION.md, findings.json, results.sarif, run.json, state.json, raw/, and
    sbom.cdx.json when Syft produced one (F7.4).

    **One generation, not seven writes (26.0.3).** Every document is rendered first,
    written whole to `<name>.tmp` beside its final name, and then renamed into
    place with `os.replace` in one loop — `run.json` last. So a single file is
    always either the previous document or this one, never a partial one; and a
    `run.json` naming this run's `generation` means every sibling renamed before
    it carries the same id. Before this, the seven `write_text` calls ran one at a
    time into the live folder, and an interruption between any two left new
    findings beside the previous run's SARIF with nothing in the folder able to
    say so. The stated limit: a multi-file swap is not atomic on POSIX without
    swapping the directory, and this directory holds the flock and the `raw-*`
    archives — so the window is the rename loop, microseconds, and detectable by
    the generation, against a window that was the whole scan and invisible.
    """
    import os

    folder = workspace / RESULTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    # The folder ignores itself. This is THE guarantee that results are never
    # committed (F7.2) — it survives someone tidying the project's root .gitignore,
    # and it travels with the folder if it is copied elsewhere. Written directly:
    # it is one byte of constant content and must exist before anything else does.
    (folder / ".gitignore").write_text("*\n", encoding="utf-8")
    # A previous write that was interrupted mid-loop left its staged documents;
    # they belong to no generation and go before this one begins.
    for leftover in folder.glob(f"*{STAGED}"):
        leftover.unlink()

    complete = not run.failures
    documents: list[tuple[str, str]] = [
        ("SUMMARY.md", summary.render(run)),
        ("findings.json", artifacts.findings_json(
            run.findings, status=run.status, status_reason=run.status_reason,
            complete=complete, generation=run.generation,
        )),
        ("results.sarif", artifacts.sarif(run.findings, version=_VERSION,
                                          generation=run.generation)),
        ("REMEDIATION.md", remediation.render(run.findings)),
        *scanner_artifacts,
        *([("state.json", state)] if state is not None else []),
        ("run.json", _provenance(run)),          # last: it vouches for the rest
    ]

    # raw/ first — it has its own stale-file rule and is not part of the swap; a
    # run.json that lands vouches for a raw/ that is already this run's.
    if raw_outputs:
        rawoutput.write(folder, list(raw_outputs))
    produced = {name for name, _ in documents}
    for name in OPTIONAL_ARTIFACTS - produced:
        with contextlib.suppress(FileNotFoundError):
            (folder / name).unlink()

    for name, content in documents:
        (folder / f"{name}{STAGED}").write_text(content, encoding="utf-8")
    for name, _ in documents:
        os.replace(folder / f"{name}{STAGED}", folder / name)
    return folder


def _provenance(run: ScanRun) -> str:
    """What actually ran. Makes a clean result falsifiable (N3.1)."""
    import json

    from . import cache as _cache
    from . import profiles as _profiles
    from .fingerprint import FP_VERSION

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
                    "stale": _db_is_stale(run),
                    "stale_after_days": _cache.DB_STALE_AFTER_DAYS,
                },
                # ADR-0018. The list of names that decides whether a dependency
                # EXISTS, as the database decides whether a CVE does. `present` is
                # false on a machine that has never run `valvur update`; then the
                # dependency-reality Check failed and `complete` above says so.
                "name_index": {
                    "present": run.name_index_age_days is not None,
                    "age_days": _round_or_none(run.name_index_age_days),
                    "stale": _index_is_stale(run),
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
