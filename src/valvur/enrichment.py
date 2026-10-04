"""Exploit intelligence — whether a vulnerability is exploited in reality.

Behind an `EnrichmentProvider` interface with exactly one implementation (ADR-0007).
There is no external platform prerequisite: a bundled CISA KEV snapshot, refreshed
into the host cache, and FIRST's daily EPSS file beside it (D25, R11.4).

**Placement.** This runs host-side, unlike Checks (ADR-0013). Enrichment is not
detection — it post-processes Findings that only exist once the fleet has finished,
on the host. It reads files and opens no socket, on any Profile: until R11.4 `full`
sent the CVEs it found to FIRST's API, and `offline` ranked without EPSS at all.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from . import cache
from . import epss as _epss
from .findings import Finding
from .settings import ENVIRONMENT as _ENVIRONMENT

#: CISA's catalog of vulnerabilities exploited in reality (F6.2). The image ships a
#: snapshot as the offline floor; `valvur update` refreshes it into the host cache,
#: because exploitation data changes daily and image releases do not — ADR-0012's
#: argument applied to a second dataset.
#:
#: Here rather than in `cli.py`, where they lived until task 27.3.1: the fetch is
#: this module's, and `doctor` needs the same two values to say which hosts a first
#: run touches. A diagnostic reaching up into the entry point for a constant is the
#: dependency pointing the wrong way, and it meant `doctor` could not be imported
#: without the whole CLI behind it.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
#: An air-gapped mirror of the catalog above: one JSON file, so any static server
#: holding a copy of it will do (22.B.3, `docs/AIR-GAPPED.md`).
KEV_URL_ENV = _ENVIRONMENT["kev_url"]

#: F6.2: the KEV snapshot shipped in the image, ransomware-campaign flag included
#: (`r` in each entry), refreshed into the host cache by `valvur update`.
_BUNDLED = Path(__file__).resolve().parent / "data" / "kev.json"


class EnrichmentProvider(Protocol):  # F6.8: the interface; no platform behind it
    def enrich(self, findings: list[Finding]) -> list[Finding]: ...


class LocalProvider:
    """KEV and EPSS, both from disk. No account, no platform, no lock-in."""

    def __init__(self) -> None:
        (self._kev, self._kev_age, self._kev_source, self._kev_catalog,
         self._kev_basis, self._kev_checked) = _load_kev()
        self._epss_age, self._epss_basis = _epss.age()
        self._epss_scored = _epss.scored()

    @property
    def kev_age_days(self) -> float | None:
        return self._kev_age

    @property
    def kev_source(self) -> str:
        return self._kev_source

    @property
    def kev_catalog(self) -> str:
        """The day the catalog in use was released, `YYYY-MM-DD`; empty when it does
        not say, and then its age is its fetch's (`kev_age_basis`)."""
        return self._kev_catalog

    @property
    def kev_age_basis(self) -> str:
        """`released` when the age is the catalog's own, `fetched` when it is the
        file's (D23): a copy with no release date is labelled as such."""
        return self._kev_basis

    @property
    def kev_checked_days(self) -> float | None:
        """Days since a check last found the catalog in use CISA's newest (D76); None
        when it never has, as for the bundled snapshot, which no check updates."""
        return self._kev_checked

    @property
    def epss_age_days(self) -> float | None:
        """The EPSS scores' age, from their `score_date`; None with no file."""
        return self._epss_age

    @property
    def epss_scored(self) -> str:
        """The day the scores in use were computed, `YYYY-MM-DD`; empty with none."""
        return self._epss_scored

    @property
    def epss_age_basis(self) -> str:
        """`scored` from the file's own date, `fetched` from its time (D23)."""
        return self._epss_basis

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        # F6.1: every Finding carrying a CVE gets its Exploit Signals, KEV and EPSS,
        # on every Profile: both are files in the host cache (D25).
        cves = {
            f.exploit.cve for f in findings
            if f.exploit and f.exploit.cve.startswith("CVE-")
        }
        if not cves:
            return findings

        epss = _epss.scores(cves)

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


def _load_kev() -> tuple[dict, float | None, str, str, str, float | None]:
    """The newer of the host-cached copy and the bundled snapshot, by the catalog's
    own release date: (entries, age in days, source, release day, basis, days since
    a check found it CISA's newest).

    The bundle is a floor so `offline` works on a clean machine; the cache is how
    the data stays current without republishing the image (the ADR-0012 argument,
    applied to a second dataset). Its age is the catalog's `dateReleased` (D23,
    F6.12): it was the file's time, so a package installed today called a month-old
    catalog new. A copy that carries no release date is aged by its file and says
    so, `fetched`, never `released`.
    """
    cached = cache.root() / "kev.json"
    candidates = [(cached, "host cache"), (_BUNDLED, "bundled snapshot")]
    best: tuple[dict, float | None, str, str, str, float | None] = (
        {}, None, "unavailable", "", "", None)
    for path, label in candidates:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        released = data.get("dateReleased") if isinstance(data, dict) else None
        age = cache.stamp_age_days(released) if released else None
        catalog, basis = (str(released)[:10], "released") if age is not None else ("", "fetched")
        if age is None:
            age = (time.time() - path.stat().st_mtime) / 86400
        if best[1] is None or age < best[1]:
            checked = data.get("checked") if path == cached else None
            best = (data.get("entries", {}), age, label, catalog, basis,
                    cache.stamp_age_days(checked) if checked else None)
    return best
