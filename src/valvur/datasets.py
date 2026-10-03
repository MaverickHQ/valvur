"""Every dataset a scan reads, once (D52a, ADR-0027).

Each row says where the data comes from (the machine setting that names a mirror),
how it is verified, how its age is read, when a scan refreshes it, and when its age
makes a nil result `inconclusive`. A scan, `update`, `doctor`, `run.json` and the
reply all read this table. Until R23.5 those numbers lived in four modules and a
literal, and disagreed: a scan refreshed the Name Index past 2 days, `update
--if-stale` only past 30, and left KEV and EPSS alone while the database was current.

The refresh thresholds are D24's. The `inconclusive` ones are F7.16's and F7.17's,
unchanged: fresh data is fetched well before old data stops being evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


def _database_age(_: str | None) -> float | None:
    from . import cache

    return cache.db_age_days() if cache.db_present() else None


def _index_age(_: str | None) -> float | None:
    from . import cache

    return cache.name_index_age_days() if cache.name_index_present() else None


def _malicious_age(_: str | None) -> float | None:
    from . import cache
    from .name_index import malicious

    return malicious.age_days(cache.name_index())


def _kev_age(_: str | None) -> float | None:
    from . import enrichment

    return enrichment.LocalProvider().kev_age_days


def _epss_age(_: str | None) -> float | None:
    from . import epss

    return epss.age()[0]


def _osv_age(ecosystem: str | None) -> float | None:
    from . import osv_offline

    return osv_offline.age(ecosystem)[0] if ecosystem else None


@dataclass(frozen=True)
class Dataset:
    """One dataset, and every rule about its age."""

    key: str
    #: What every surface calls it.
    title: str
    #: A scan refreshes it, and `update --if-stale` does, once it is older than this
    #: or absent (D24).
    refresh_after_days: float
    #: Past this, a nil result is not evidence (F7.16); None for data that only ranks.
    inconclusive_after_days: float | None
    #: The machine setting that names a mirror for it (ADR-0025, `AIR-GAPPED.md`).
    setting: str
    #: How what arrives is checked.
    verifier: str
    #: Its age in days, from its data's own date where it says one (D23); None when
    #: absent. OSV's is per ecosystem.
    reader: Callable[[str | None], float | None]
    #: Past this, its age is said beside the findings it ranked; None for none.
    warn_after_days: float | None = None

    def age(self, ecosystem: str | None = None) -> float | None:
        return self.reader(ecosystem)

    def due(self, age: float | None) -> bool:
        """Absent, or old enough that a scan refreshes it."""
        return age is None or age > self.refresh_after_days

    def stale(self, age: float | None) -> bool:
        """Present and too old for a nil result to be evidence."""
        return (self.inconclusive_after_days is not None and age is not None
                and age > self.inconclusive_after_days)

    def warns(self, age: float | None) -> bool:
        """Present and old enough that the findings it ranked say so."""
        return self.warn_after_days is not None and age is not None \
            and age > self.warn_after_days


#: The database that decides whether findings exist. Trivy rebuilds it every 24
#: hours, so seven days is seven missed rebuilds: the difference between "we looked
#: and found nothing" and "we did not look recently enough to know".
DATABASE = Dataset("database", "vulnerability database", 7, 7, "db_repository",
                   "Trivy's own pull, by the artifact's digest", _database_age)
#: The package-name index (ADR-0018), published daily. Thirty days is roughly 16,000
#: PyPI and 48,000 npm names of drift; an old index is missing names, so it
#: overstates, reporting a package newer than it as nonexistent.
NAME_INDEX = Dataset("name_index", "package-name index", 2, 30, "name_index_url",
                     "its cosign signature, pulled back and verified", _index_age)
#: Known-malicious names beside the index (D26), published daily.
MALICIOUS = Dataset("malicious", "malicious list", 2, None, "name_index_url",
                    "its cosign signature, as the index's", _malicious_age)
#: CISA KEV, released most days. It ranks and finds nothing, so its age makes no
#: verdict; past thirty days the summary says how old the ranking's evidence is.
KEV = Dataset("kev", "KEV catalog", 2, None, "kev_url",
              "HTTPS to cisa.gov, or the operator's mirror", _kev_age, warn_after_days=30)
#: FIRST's EPSS scores, one file a day (D25).
EPSS = Dataset("epss", "EPSS scores", 2, None, "epss_url",
               "HTTPS to FIRST, or the operator's mirror", _epss_age)
#: OSV's offline databases, one per ecosystem the File Set has a lockfile for (R4.6).
OSV = Dataset("osv", "OSV database", 7, None, "osv_url",
              "HTTPS to OSV's export, or the operator's mirror", _osv_age)

ALL: tuple[Dataset, ...] = (DATABASE, NAME_INDEX, MALICIOUS, KEV, EPSS, OSV)


def get(key: str) -> Dataset:
    return next(dataset for dataset in ALL if dataset.key == key)
