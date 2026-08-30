"""Fingerprints — a Finding's identity across Scan Runs.

Derived from each Finding Class's *natural* key, never from a line number: line
numbers shift on every edit, which would make the rescan diff useless (ADR-0003).

Paths are Workspace-relative and inputs are normalised, so a fingerprint is
byte-identical across machines and operating systems (F5.4). That matters because
Suppressions reference fingerprints and are committed and shared.

FP_VERSION is a compatibility surface from the first commit: changing the algorithm
invalidates every Suppression in every project using valvur.
"""

from __future__ import annotations

import hashlib
import unicodedata

FP_VERSION = 1


def _norm(value: str) -> str:
    return unicodedata.normalize("NFC", value.strip()).lower()


def derive(*parts: str) -> str:
    joined = "\x1f".join(_norm(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]


def for_secret(rule: str, path: str, secret: str) -> str:
    """Identity is the secret itself, not where it sits. Rotating it *is* the fix."""
    secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    return derive("secret", rule, path, secret_hash)


def for_dependency_vuln(ecosystem: str, package: str, version: str, vuln_id: str) -> str:
    """Nothing to do with a location. Upgrading the package *is* the fix."""
    return derive("dependency_vuln", ecosystem, package, version, vuln_id)


def for_iac(rule: str, path: str, resource_address: str) -> str:
    """Terraform hands us a stable address; far better than any line hash."""
    return derive("iac_misconfig", rule, path, resource_address)


def for_licence(package: str, license_id: str) -> str:
    return derive("licence", package, license_id)


def for_dependency_reality(ecosystem: str, package: str) -> str:
    return derive("dependency_reality", ecosystem, package)


def for_sast(rule: str, path: str, matched_text: str, ordinal: int = 0) -> str:
    """The only class needing a content hash.

    Hashes the matched text ALONE — never surrounding context, because an edit
    nearby must not break identity. `ordinal` separates repeats of the same match
    within one file.
    """
    collapsed = " ".join(matched_text.split())
    match_hash = hashlib.sha256(_norm(collapsed).encode("utf-8")).hexdigest()[:16]
    return derive("sast", rule, path, match_hash, str(ordinal))
