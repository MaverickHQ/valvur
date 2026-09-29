"""Is the data a verdict rests on too old to support it? (F6.11, F7.16 and F7.17)

Two predicates, shared by the writer (`run.json`'s `stale` flags) and the reader
(`SUMMARY.md`'s prose, `summary.py`). They lived in `results.py` until task 27.3.3
split the rendering out; both callers now import them from here rather than one
importing the other. And every dataset's age in one place (R11.6), which each
surface says: `run.json`'s `data`, `SUMMARY.md`'s `Data:` line, the MCP reply.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import cache as _cache

if TYPE_CHECKING:
    from .api import ScanRun


def db_is_stale(run: ScanRun) -> bool:
    age = run.db_age_days
    return age is not None and age > _cache.DB_STALE_AFTER_DAYS


def index_is_stale(run: ScanRun) -> bool:
    age = run.name_index_age_days
    return age is not None and age > _cache.NAME_INDEX_STALE_AFTER_DAYS


def data_ages(provider=None, osv=()) -> dict:
    """Each dataset's age in days and what it is measured from (D23): `built` for
    the database, the index and the malicious list; `released` or `scored` when KEV
    or EPSS says, `published` when OSV's export did; `fetched` when a copy does not
    say, and `absent` with no age when there is no copy. `osv` names the ecosystems
    whose offline database the scan read; `provider` the enrichment that ranked it,
    else KEV and EPSS are read afresh."""
    from . import osv_offline
    from .name_index import malicious

    def entry(age: float | None, basis: str) -> dict:
        return ({"age_days": None, "basis": "absent"} if age is None
                else {"age_days": round(age, 2), "basis": basis})

    if provider is None:
        from .enrichment import LocalProvider

        provider = LocalProvider()
    index = _cache.name_index_age_days() if _cache.name_index_present() else None
    return {
        "database": entry(_cache.db_age_days(), "built"),
        "name_index": entry(index, "built"),
        "malicious": entry(malicious.age_days(_cache.name_index()), "built"),
        "kev": entry(provider.kev_age_days, provider.kev_age_basis or "fetched"),
        "epss": entry(provider.epss_age_days, provider.epss_age_basis or "fetched"),
        "osv": {name: entry(*osv_offline.age(name)) for name in osv},
    }
