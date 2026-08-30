"""Redaction.

Applied where a Finding is built, never in a writer. A secret value therefore never
enters the model at all, so no projection of it — SUMMARY.md, findings.json, SARIF,
raw/ — can leak one. That is a structural guarantee rather than a filter someone has
to remember to apply in six places (design §6, F5.7, N2.4).
"""

from __future__ import annotations

import hashlib


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def redact(text: str, secret: str) -> str:
    """Replace a secret inside surrounding context with a stable, non-reversible marker."""
    if not secret or not text:
        return text
    return text.replace(secret, f"[REDACTED:{fingerprint(secret)}]")
