"""OSV-Scanner's offline database, for the `offline` Profile (R4.6; F3.2, ADR-0023).

R4.1 measured it: with no network and npm's database fetched once, OSV-Scanner
reported repository 8's planted malicious package, which nothing else in valvur
could. So the database joins `offline`: fetched by the shim, like Trivy's, only for
the ecosystems the File Set holds a lockfile for and only when absent (24.1), into
the host cache in the layout OSV-Scanner reads, and mounted read-only into the Scan
Container. What leaves the machine for it is which ecosystems' public databases are
fetched, recorded in `run.json` like every fetch.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path

#: OSV's public export, one zip per ecosystem (https://google.github.io/osv.dev/data/).
#: `VALVUR_OSV_URL` names a mirror for air-gapped use.
DEFAULT_URL = "https://osv-vulnerabilities.storage.googleapis.com"


def base_url() -> str:
    """OSV's bucket, or the mirror the machine names (`osv_url`, R6.7)."""
    from . import settings

    return settings.get("osv_url") or DEFAULT_URL
#: Where OSV-Scanner 2.6 looks under `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`.
LAYOUT = "osv-scalibr"
#: Where the Scan Container sees the cache.
MOUNT = "/cache/osv"

#: valvur's ecosystem keys, as `ecosystems.VULNERABILITY_MANIFESTS` names them, to
#: OSV's names for the same ecosystems.
OSV_NAMES = {"pip": "PyPI", "npm": "npm", "cargo": "crates.io", "gomod": "Go",
             "maven": "Maven", "gem": "RubyGems", "composer": "Packagist"}


def directory() -> Path:
    from . import cache

    return cache.root() / "osv"


def path(name: str) -> Path:
    return directory() / LAYOUT / name / "all.zip"


def needed(files: list[str]) -> list[str]:
    """OSV's names for the ecosystems whose lockfiles the File Set holds."""
    from .ecosystems import VULNERABILITY_MANIFESTS

    found = set()
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        for key, patterns in VULNERABILITY_MANIFESTS.items():
            if key in OSV_NAMES and any(fnmatch(name, pattern) for pattern in patterns):
                found.add(OSV_NAMES[key])
    return sorted(found)


def absent(names: list[str]) -> list[str]:
    return [name for name in names if not path(name).is_file()]


#: Where each fetch keeps its export's date (D23): beside the databases, not in
#: OSV-Scanner's own layout.
AGES = "ages.json"


def _ages() -> dict:
    import json

    try:
        data = json.loads((directory() / AGES).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def age(name: str) -> tuple[float | None, str]:
    """(days, basis): the export's age from the `Last-Modified` its fetch kept,
    `published`; else the file's, `fetched` (D23, F6.12). (None, "") when absent."""
    import time
    from email.utils import parsedate_to_datetime

    if not path(name).is_file():
        return None, ""
    stamp = (_ages().get(name) or {}).get("last_modified")
    if stamp:
        try:
            published = parsedate_to_datetime(stamp).timestamp()
        except (TypeError, ValueError):
            published = None
        if published is not None:
            return (time.time() - published) / 86400, "published"
    return (time.time() - path(name).stat().st_mtime) / 86400, "fetched"


def stale(names: list[str], due: Callable[[float | None], bool]) -> list[str]:
    """The present databases `due` says are old enough to refresh, by the export's
    own date where the fetch kept it (R11.2): a mirror can serve an old export today.
    `due` is the datasets table's (D52a), which this module does not import."""
    return [name for name in names if path(name).is_file() and due(age(name)[0])]


def fetch(name: str, opener: Callable | None = None, timeout: float = 600) -> dict:
    """Download `name`'s database into place; a failure leaves nothing behind.
    Returns the record `run.json` keeps (28.0.4)."""
    import urllib.request

    url = f"{base_url()}/{name}/all.zip"
    target = path(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".partial")
    started = time.monotonic()
    try:
        # A fixed public URL, or the operator's mirror; never a Workspace's.
        with (opener or urllib.request.urlopen)(url, timeout=timeout) as response, \
                open(partial, "wb") as out:
            while chunk := response.read(1 << 20):
                out.write(chunk)
            published = (getattr(response, "headers", None) or {}).get("Last-Modified")
        partial.replace(target)
        _keep_age(name, published)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return {"what": f"OSV database ({name})", "source": url,
            "size_mb": max(1, round(target.stat().st_size / 1_000_000)),
            "seconds": round(time.monotonic() - started, 1)}


def _keep_age(name: str, published: str | None) -> None:
    """Record the export's date beside the databases, or drop a stale record: a
    fetch without the header is aged by its file, and says so."""
    import json

    ages = _ages()
    if published:
        ages[name] = {"last_modified": published}
    else:
        ages.pop(name, None)
    (directory() / AGES).write_text(json.dumps(ages, indent=1) + "\n", encoding="utf-8")


def ensure(files: list[str], say: Callable[[str], None], *,
           due: Callable[[float | None], bool]) -> tuple[list[dict], list[str]]:
    """OSV's database for each ecosystem `files` hold a lockfile for, fetched when
    absent or stale (R4.6, ADR-0025), each under the cache lock and said: the
    records `run.json` keeps, and a sentence per failure. What a scan does before
    its Scanners start, and `valvur update PATH` ahead of one (R8.2)."""
    from . import cache, locking

    names = needed(files)
    missing, old = absent(names), stale(names, due)
    records: list[dict] = []
    failed: list[str] = []
    for name in missing + old:
        say(f"fetching the OSV database for {name} — the first run for it only"
            if name in missing else
            f"refreshing the OSV database for {name} ({age(name)[0] or 0:.0f} days old)")
        try:
            with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
                record = fetch(name)
        except OSError as exc:
            failed.append(f"{name}: {exc}")
            say(f"OSV database not fetched for {name}: {exc}")
            continue
        say(f"OSV database fetched for {name} ({record['seconds']:.0f}s)")
        records.append(record)
    return records, failed
