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
    return folder


def _summary(run) -> str:
    lines = [
        "# Security scan summary",
        "",
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
