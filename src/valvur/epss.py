"""FIRST's EPSS scores, from the daily file in the host cache (D25, F6.13, ADR-0027).

Until R11.4 `full` asked FIRST's API for the CVE identifiers a scan found, and
`offline`, the default, had no EPSS at all. FIRST publishes every score in one file a
day: 2.7 MB compressed, 380,528 lines, measured 2026-09-29. Fetched as public data
by `valvur update` and by a scan past two days, it is read on every Profile, and no
request carries anything of the Workspace.

The file's first line says when the scores were computed, which is their age (D23):
`#model_version:v2026.06.15,score_date:2026-09-29T12:00:22Z`, then the header
`cve,epss,percentile`, then one line per CVE.
"""

from __future__ import annotations

import gzip
import zlib
from collections.abc import Callable

# Where the file is and how old it is are the cache's, beside every other dataset's.
from .cache import epss_age as age
from .cache import epss_path as path
from .cache import epss_scored as scored
from .cache import score_date as _score_date
from .settings import ENVIRONMENT as _ENVIRONMENT

__all__ = ["URL", "URL_ENV", "NotTheFile", "age", "fetch", "path", "scored", "scores"]

#: FIRST's documented location (first.org/epss/data_stats). It answers with a 301 to
#: `epss.empiricalsecurity.com`, then a 302 to the day's dated file on that host:
#: `egress.EPSS_HOSTS` names both, and nothing else is reached for EPSS.
URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
#: An air-gapped mirror: one file, so any static server holding a copy will do.
URL_ENV = _ENVIRONMENT["epss_url"]
_HEADER = "cve,epss,percentile"


class NotTheFile(ValueError):
    """What arrived is not FIRST's scores: a captive portal, a truncated download."""


def scores(cves: set[str]) -> dict[str, tuple[float, str]]:
    """Each of `cves` the file scores, with the day it was scored. One pass over the
    file, and only when a scan found a CVE; a CVE it does not list has no score."""
    file = path()
    if not cves or not file.is_file():
        return {}
    out: dict[str, tuple[float, str]] = {}
    try:
        with gzip.open(file, "rt", encoding="utf-8") as lines:
            day = _score_date(lines.readline())[:10]
            for line in lines:
                cve, _, rest = line.partition(",")
                if cve in cves:
                    try:
                        out[cve] = (float(rest.partition(",")[0]), day)
                    except ValueError:
                        continue
    except (OSError, EOFError, zlib.error, UnicodeDecodeError):
        return out                                  # degrade to KEV only (F6.4)
    return out


def fetch(url: str, opener: Callable | None = None, timeout: float = 120) -> tuple[int, str]:
    """Download the file into place and return (scores, the day scored). What
    arrived is checked whole before it replaces the copy in use, so a failure of any
    kind leaves that copy as it was."""
    import urllib.request

    # A fixed public URL, or the operator's mirror; never a Workspace's.
    with (opener or urllib.request.urlopen)(url, timeout=timeout) as response:
        body = response.read()
    try:
        text = gzip.decompress(body).decode("utf-8")
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as exc:
        raise NotTheFile(f"not a gzip of EPSS scores: {exc}") from None
    first, _, rest = text.partition("\n")
    header, _, rows = rest.partition("\n")
    day = _score_date(first)[:10]
    if not day or header.strip() != _HEADER:
        raise NotTheFile("no score_date and cve,epss,percentile header")
    target = path()
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".partial")
    try:
        partial.write_bytes(body)
        partial.replace(target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return sum(1 for row in rows.splitlines() if row), day
