"""Writes the Results Folder. Runs on the host, as the invoking user (ADR-0001)."""

from __future__ import annotations

from pathlib import Path

RESULTS_DIR = ".security-scan"


def write(workspace: Path, run) -> Path:
    folder = workspace / RESULTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    # The folder ignores itself. This is THE guarantee that results are never
    # committed (F7.2) — it survives someone tidying the project's root .gitignore,
    # and it travels with the folder if it is copied elsewhere.
    (folder / ".gitignore").write_text("*\n", encoding="utf-8")
    (folder / "SUMMARY.md").write_text(_summary(run), encoding="utf-8")
    (folder / "run.json").write_text(_provenance(run), encoding="utf-8")
    return folder


def _provenance(run) -> str:
    """What actually ran. Makes a clean result falsifiable (N3.1)."""
    import json

    from .fingerprint import FP_VERSION

    return (
        json.dumps(
            {
                "schema": 1,
                "fp_version": FP_VERSION,
                "status": run.status,
                # An incomplete scan reporting "clean" would be a lie of omission.
                # This is the single field an agent should check first.
                "complete": not getattr(run, "failures", []),
                "findings": len(run.findings),
                "fixed": len(run.fixed),
                "scanners": [
                    {
                        "tool": s.tool,
                        "version": s.version,
                        "ok": s.ok,
                        "reason": s.reason,
                    }
                    for s in getattr(run, "scanners", [])
                ],
            },
            indent=2,
        )
        + "\n"
    )


def _summary(run) -> str:
    lines = [
        "# Security scan summary",
        "",
    ]

    # Failures come before findings. A reader who does not see them will trust a
    # partial scan as a complete one (F7.7).
    failures = getattr(run, "failures", [])
    if failures:
        lines += ["## ⚠ Scanners that did not complete", ""]
        lines += [f"- **{f.tool}** — {f.reason}" for f in failures]
        lines += ["", "**This scan is incomplete.** Findings below are partial.", ""]

    lines += [
        f"**Status:** {run.status}",
        f"**Findings:** {len(run.findings)}"
        + (f" · **fixed since last run:** {len(run.fixed)}" if run.fixed else ""),
        "",
    ]
    for f in run.findings:
        lines.append(f"- [{f.status}] `{f.path}:{f.line}` — {f.title} ({f.rule})")
        if f.evidence:
            lines.append(f"  `{f.evidence}`")
    return "\n".join(lines) + "\n"
