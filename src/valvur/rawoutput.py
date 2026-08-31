"""raw/ — each Scanner's unmodified output, redacted (F2.8, F5.7, P2).

This is the credibility artifact: when valvur says Trivy found CVE-X, a reviewer must
be able to check we did not mangle it, and our normalisation is testable against
ground truth rather than against itself.

**It needs its own redaction pass.** Redaction elsewhere happens at the Finding
boundary, so a secret never enters the model. `raw/` is *pre-model* Scanner output
and bypasses that entirely — Gitleaks emits live credential values in its JSON. Left
alone, our security tool would copy your credentials to a second cleartext location
on disk, which is precisely the failure F5.7 exists to prevent.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .redact import fingerprint

KEEP_RUNS = 3


def secrets_in(gitleaks_stdout: str) -> set[str]:
    """The values Gitleaks reports. It tells us exactly what to remove."""
    try:
        entries = json.loads(gitleaks_stdout or "[]")
    except json.JSONDecodeError:
        return set()
    found = set()
    for entry in entries:
        for key in ("Secret", "Match"):
            value = entry.get(key)
            if value and len(str(value)) >= 8:
                found.add(str(value))
    return found


def scrub(text: str, secrets: set[str]) -> str:
    """Replace every known secret with its non-reversible fingerprint."""
    # Longest first, so a Match containing a Secret does not leave a fragment behind.
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, f"[REDACTED:{fingerprint(secret)}]")
    return text


def write(results_dir: Path, outputs: list[tuple[str, str]]) -> Path:
    """Write per-Scanner output, redacted, and prune older runs (N3.3)."""
    secrets: set[str] = set()
    for tool, body in outputs:
        if tool == "gitleaks":
            secrets |= secrets_in(body)

    raw = results_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    # Output from a Scanner that did not run this time must not survive into this
    # run's folder. A quick scan inheriting a standard scan's osv-scanner.json shows
    # a reader vulnerability data attributed to a run that never looked for it.
    for stale in raw.glob("*.json"):
        stale.unlink()
    for tool, body in outputs:
        (raw / f"{tool}.json").write_text(scrub(body, secrets), encoding="utf-8")

    _prune(results_dir)
    return raw


def _prune(results_dir: Path) -> None:
    """raw/ is the bulk of the folder and grows without this."""
    archives = sorted(
        (p for p in results_dir.glob("raw-*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    for stale in archives[KEEP_RUNS:]:
        shutil.rmtree(stale, ignore_errors=True)
