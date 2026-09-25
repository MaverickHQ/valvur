"""Writes the Results Folder. Runs on the host, as the invoking user (ADR-0001)."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

from . import artifacts, provenance, rawoutput, remediation, summary
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
            complete=complete, generation=run.generation, fetched=run.fetched,
        )),
        ("results.sarif", artifacts.sarif(run.findings, version=_VERSION,
                                          generation=run.generation)),
        ("REMEDIATION.md", remediation.render(run.findings)),
        *scanner_artifacts,
        *([("state.json", state)] if state is not None else []),
        ("run.json", provenance.render(run)),    # last: it vouches for the rest
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
