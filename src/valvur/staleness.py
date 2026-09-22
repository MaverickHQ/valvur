"""Is the data a verdict rests on too old to support it? (F6.11, F7.16 and F7.17)

Two predicates, shared by the writer (`run.json`'s `stale` flags) and the reader
(`SUMMARY.md`'s prose, `summary.py`). They lived in `results.py` until task 27.3.3
split the rendering out; both callers now import them from here rather than one
importing the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import ScanRun


def db_is_stale(run: ScanRun) -> bool:
    from . import cache as _cache

    age = run.db_age_days
    return age is not None and age > _cache.DB_STALE_AFTER_DAYS


def index_is_stale(run: ScanRun) -> bool:
    from . import cache as _cache

    age = run.name_index_age_days
    return age is not None and age > _cache.NAME_INDEX_STALE_AFTER_DAYS
