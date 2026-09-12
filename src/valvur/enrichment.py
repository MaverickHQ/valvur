"""Exploit intelligence — whether a vulnerability is exploited in reality.

Behind an `EnrichmentProvider` interface with exactly one implementation (ADR-0007).
There is no external platform prerequisite: a bundled CISA KEV snapshot, refreshed
into the host cache, plus FIRST EPSS fetched on demand for the CVEs actually found.

**Placement.** This runs host-side, unlike Checks (ADR-0013). Enrichment is not
detection — it post-processes Findings that only exist once the fleet has finished,
on the host. Its network access is gated by Profile: `quick` fetches nothing, and
Phase 11's regression test asserts that over the whole process tree, not merely over
the container.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from . import cache
from .findings import Finding

STALE_AFTER_DAYS = 30
#: F6.2: the KEV snapshot shipped in the image, ransomware-campaign flag included
#: (`r` in each entry), refreshed into the host cache by `valvur update`.
_BUNDLED = Path(__file__).resolve().parent / "data" / "kev.json"


class EnrichmentProvider(Protocol):  # F6.8: the interface; no platform behind it
    def enrich(self, findings: list[Finding], *, network: bool) -> list[Finding]: ...


class LocalProvider:
    """KEV from disk, EPSS from FIRST. No account, no platform, no lock-in."""

    def __init__(self) -> None:
        self._kev, self._kev_age, self._kev_source = _load_kev()

    @property
    def kev_age_days(self) -> float | None:
        return self._kev_age

    @property
    def kev_source(self) -> str:
        return self._kev_source

    @property
    def is_stale(self) -> bool:
        return self._kev_age is not None and self._kev_age > STALE_AFTER_DAYS

    def enrich(self, findings: list[Finding], *, network: bool) -> list[Finding]:
        # F6.1: every Finding carrying a CVE gets its Exploit Signals — KEV always,
        # EPSS when the Profile allows the lookup.
        cves = {
            f.exploit.cve for f in findings
            if f.exploit and f.exploit.cve.startswith("CVE-")
        }
        if not cves:
            return findings

        epss = _fetch_epss(cves) if network else {}

        enriched = []
        for finding in findings:
            if not (finding.exploit and finding.exploit.cve):
                enriched.append(finding)
                continue
            cve = finding.exploit.cve
            entry = self._kev.get(cve)
            score, date = epss.get(cve, (None, ""))
            enriched.append(replace(finding, exploit=replace(
                finding.exploit,
                # False, not None: "checked and absent" is a different claim from
                # "never looked", and only one of them is reportable.
                kev=entry is not None,
                ransomware=bool(entry and entry.get("r")),
                epss=score,
                epss_date=date,
            )))
        return enriched


def _load_kev() -> tuple[dict, float | None, str]:
    """Prefer a fresher host-cached copy over the bundled snapshot.

    The bundle is a floor so `quick` works offline on a clean machine; the cache is
    how the data stays current without republishing the image (the ADR-0012
    argument, applied to a second dataset).
    """
    cached = cache.root() / "kev.json"
    candidates = [(cached, "host cache"), (_BUNDLED, "bundled snapshot")]
    best: tuple[dict, float | None, str] = ({}, None, "unavailable")
    for path, label in candidates:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        age = (time.time() - path.stat().st_mtime) / 86400
        if best[1] is None or age < best[1]:
            best = (data.get("entries", {}), age, label)
    return best


def _fetch_epss(cves: set[str]) -> dict[str, tuple[float, str]]:
    """One batched request for the CVEs actually found, never one call per finding."""
    import urllib.error
    import urllib.request

    out: dict[str, tuple[float, str]] = {}
    ordered = sorted(cves)
    for start in range(0, len(ordered), 100):      # the API caps a query's length
        batch = ordered[start:start + 100]
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(batch)
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                payload = json.load(response)
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            return out                              # degrade to KEV only (F6.4)
        for row in payload.get("data", []):
            try:
                out[row["cve"]] = (float(row["epss"]), row.get("date", ""))
            except (KeyError, TypeError, ValueError):
                continue
    return out
