"""Writes the Results Folder. Runs on the host, as the invoking user (ADR-0001)."""

from __future__ import annotations

from pathlib import Path

RESULTS_DIR = ".security-scan"


def write(workspace: Path, run, artifacts=()) -> Path:
    folder = workspace / RESULTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    # The folder ignores itself. This is THE guarantee that results are never
    # committed (F7.2) — it survives someone tidying the project's root .gitignore,
    # and it travels with the folder if it is copied elsewhere.
    (folder / ".gitignore").write_text("*\n", encoding="utf-8")
    (folder / "SUMMARY.md").write_text(_summary(run), encoding="utf-8")
    (folder / "run.json").write_text(_provenance(run), encoding="utf-8")
    for name, content in artifacts:
        (folder / name).write_text(content, encoding="utf-8")
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
                # Stated plainly, because we criticise competitors for being vague
                # about exactly this. Package NAMES (never source) are sent to public
                # registries by the dependency-reality check on standard and deep.
                "enrichment": {
                    "kev_source": getattr(run, "kev_source", ""),
                    "kev_age_days": round(getattr(run, "kev_age_days", None) or 0, 2),
                    "stale": (getattr(run, "kev_age_days", None) or 0) > 30,
                },
                "network": {
                    "used": getattr(run, "network_used", False),
                    "what_left_the_machine": (
                        "dependency package names (to PyPI, by the dependency-reality "
                        "check) and the CVE identifiers found in this workspace (to "
                        "FIRST, for EPSS scores)"
                        if getattr(run, "network_used", False)
                        else "nothing"
                    ),
                },
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
    age = getattr(run, "kev_age_days", None)
    if age is not None and age > 30:
        lines += [
            f"> ⚠ Exploit intelligence is {age:.0f} days old. Run `valvur update`.",
            "> Confident answers from stale data are worse than no answer.",
            "",
        ]

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
    if run.fixed:
        lines += ["", "## Fixed since the last scan", ""]
        lines += [f"- {title}" for title in run.fixed]
        lines += [""]

    for f in sorted(run.findings, key=lambda x: x.rank or 10**9):
        badge = ""
        if f.exploit and f.exploit.ransomware:
            badge = " **[KEV · RANSOMWARE]**"
        elif f.exploit and f.exploit.kev:
            badge = " **[KEV — exploited in the wild]**"
        elif f.exploit and f.exploit.epss is not None and f.exploit.epss >= 0.10:
            badge = f" **[EPSS {f.exploit.epss:.0%}]**"
        scope = ""
        if f.dependency and f.dependency.scope == "development":
            scope = " _(dev-only)_"
        lines.append(
            f"- [{f.status}] `{f.path}:{f.line}` — {f.title} ({f.rule}){badge}{scope}"
        )
        if f.evidence:
            lines.append(f"  `{f.evidence}`")
    return "\n".join(lines) + "\n"
