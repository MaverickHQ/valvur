"""What git knows about a path, which changes what a finding means.

Found by scanning a real project: we reported a secret in a gitignored `.env` as
**critical**. Every developer has one, and keeping credentials out of git is the
*correct* practice — flagging it at top severity penalises the right behaviour and
trains people to ignore the tool.

A secret in a **tracked** file is critical: it is in the history, on every clone, and
on the remote. A secret in an **ignored** file is a local credential doing its job.
Both are worth reporting; only one is an emergency.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def ignored_paths(workspace: Path, paths: list[str]) -> set[str]:
    """Which of these paths git is ignoring. Empty set when this is not a repo."""
    if not paths or not (workspace / ".git").exists():
        return set()
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(workspace), "check-ignore", "--stdin"],
            input="\n".join(paths),
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def tracked_paths(workspace: Path) -> set[str]:
    """Everything git actually tracks. A file can be neither tracked nor ignored."""
    if not (workspace / ".git").exists():
        return set()
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(workspace), "ls-files"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


SECRET_RULES = ("secret", "token", "key", "password", "credential", "api-key")


def is_secret(finding) -> bool:
    rule = finding.rule.lower()
    return any(word in rule for word in SECRET_RULES)


def apply(workspace: Path, findings: list) -> list:
    """Downgrade secrets in files git is not carrying, and say why."""
    from dataclasses import replace

    secrets = [f for f in findings if is_secret(f)]
    if not secrets:
        return findings

    ignored = ignored_paths(workspace, sorted({f.path for f in secrets}))
    tracked = tracked_paths(workspace)
    if not ignored:
        return findings

    out = []
    for finding in findings:
        if is_secret(finding) and finding.path in ignored and finding.path not in tracked:
            out.append(replace(
                finding,
                severity="medium",
                title=(
                    f"{finding.title} — in `{finding.path}`, which git is ignoring, "
                    "so it is not committed or pushed"
                ),
            ))
        else:
            out.append(finding)
    return out
