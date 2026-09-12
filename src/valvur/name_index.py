"""The package-name index — existence answered offline (ADR-0018).

Two halves, one file, because the format is the contract between them:

- **Building**, on the host, by `valvur update`. PyPI is one request for its simple
  index; npm is walked from the registry's own replication database, in full the
  first time and incrementally from its change feed after that. Both land in the
  host cache beside the vulnerability database (ADR-0012), never in the image.
- **Reading**, in the container, by the dependency-reality Check. The cache is
  mounted read-only at `/cache/names`, and a name is looked up by binary search over
  the memory-mapped file — 8µs a name, measured, with nothing to load first.

The format is one canonical name per line, sorted bytewise, UTF-8, LF. Plain text
on purpose: `grep -x reqeusts ~/.cache/valvur/names/pypi.txt` is the whole audit.
"""

from __future__ import annotations

import gzip
import json
import mmap
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

PYPI_SIMPLE = "https://pypi.org/simple/"
NPM_REPLICATE = "https://replicate.npmjs.com"

#: One file per ecosystem, keyed by the ecosystem name the Check already uses for
#: Finding identity (ADR-0003) — so the Check can go from a declared package to a file
#: without a second table that could disagree with the first.
FILES: dict[str, str] = {"pip": "pypi.txt", "npm": "npm.txt"}
METADATA = "metadata.json"

#: The replication server's page cap, measured 2026-09-12: 10,000 rows per request
#: for both `_all_docs` and `_changes`, and `skip` refused outright.
PAGE = 10_000
TIMEOUT = 120
_ATTEMPTS = 4

#: Past this age the change feed costs about what a full walk does, and a `since`
#: that old is more likely to have been compacted away. Start over.
FULL_REPULL_AFTER_DAYS = 90

#: A fetched list smaller than this is a truncated response, not a registry that
#: shrank. Writing it would report real packages as hallucinated by the thousand —
#: the worst finding this product can emit — so it is refused. PyPI measured at
#: 890,006 names and npm at 4,382,736 on 2026-09-12.
MINIMUM_NAMES: dict[str, int] = {"pip": 500_000, "npm": 2_000_000}

_UA = {"User-Agent": "valvur (+https://github.com/MaverickHQ/valvur)"}

Progress = Callable[[str], None]


class IndexUnavailable(RuntimeError):
    """The index could not be fetched. Whatever was on disk before is untouched."""


# ------------------------------------------------------------------ reading

class NameIndex:
    """Membership over one ecosystem's sorted file, without loading it.

    Opened once per Check run and asked about every declared name. The file is
    memory-mapped and searched by bisection on byte offsets, re-aligned to a line
    start at each probe. Names must be in the file's canonical form already — the
    index does not normalise, because which normalisation applies is the
    ecosystem's business and the Check's to know.
    """

    def __init__(self, path: Path):
        self.path = path
        self._file = open(path, "rb")  # closed in close()
        size = os.fstat(self._file.fileno()).st_size
        # mmap refuses a zero-length file; an empty index is a valid one that
        # contains nothing.
        self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ) if size else None

    def __enter__(self) -> NameIndex:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._map is not None:
            self._map.close()
            self._map = None
        self._file.close()

    def contains(self, name: str) -> bool:
        if self._map is None or not name:
            return False
        target = name.encode("utf-8")
        view = self._map
        lo, hi = 0, len(view)
        while lo < hi:
            mid = (lo + hi) // 2
            newline = view.rfind(b"\n", lo, mid)
            start = lo if newline == -1 else newline + 1
            end = view.find(b"\n", start, hi)
            if end == -1:
                end = hi
            line = view[start:end]
            if line == target:
                return True
            if line < target:
                lo = end + 1
            else:
                hi = start
        return False


def open_index(directory: Path, ecosystem: str) -> NameIndex | None:
    """The index for one ecosystem, or None when it has not been fetched."""
    filename = FILES.get(ecosystem)
    if filename is None:
        return None
    path = directory / filename
    if not path.is_file():
        return None
    return NameIndex(path)


# ----------------------------------------------------------------- building

def refresh(directory: Path, *, ecosystems: Iterable[str] = tuple(FILES),
            progress: Progress = lambda _: None) -> dict:
    """Fetch every ecosystem's names into `directory`. Returns the metadata written.

    Each file is written whole and renamed into place, so a scan reading the index
    while it is refreshed sees the old list or the new one, never a partial one. The
    caller holds the cache lock (exclusive) around this; see `cli.py`.
    """
    directory.mkdir(parents=True, exist_ok=True)
    metadata = _read_metadata(directory)
    for ecosystem in ecosystems:
        if ecosystem not in FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        previous = metadata["ecosystems"].get(ecosystem) or {}
        if ecosystem == "pip":
            names = fetch_pypi(progress)
            entry: dict = {"source": PYPI_SIMPLE}
        else:
            names, seq = _fetch_npm(directory, previous, progress)
            entry = {"source": f"{NPM_REPLICATE}/_all_docs", "update_seq": seq}
        if len(names) < MINIMUM_NAMES[ecosystem]:
            raise IndexUnavailable(
                f"{ecosystem}: the registry returned {len(names):,} names, far fewer "
                f"than the {MINIMUM_NAMES[ecosystem]:,} it is known to hold. Refusing to "
                "write a truncated index — it would report real packages as hallucinated."
            )
        _write_names(directory / FILES[ecosystem], names)
        entry.update(built_at=_now(), count=len(names))
        metadata["ecosystems"][ecosystem] = entry
        _write_metadata(directory, metadata)
        progress(f"{ecosystem}: {len(names):,} names")
    return metadata


def fetch_pypi(progress: Progress = lambda _: None) -> set[str]:
    """Every project on PyPI, in PEP 503 canonical form. One request (PEP 691)."""
    from .checks.dependency_reality import canonical

    progress("PyPI: fetching the simple index (about 10MB)")
    body = _get(PYPI_SIMPLE, accept="application/vnd.pypi.simple.v1+json")
    try:
        projects = json.loads(body)["projects"]
        return {canonical(p["name"]) for p in projects if isinstance(p.get("name"), str)}
    except (KeyError, TypeError, ValueError) as exc:
        raise IndexUnavailable(f"PyPI returned an index this version cannot read: {exc}") from exc


def _fetch_npm(directory: Path, previous: dict, progress: Progress) -> tuple[set[str], object]:
    """Incrementally when there is something to build on, in full otherwise."""
    existing = directory / FILES["npm"]
    since = previous.get("update_seq")
    age = _age_days(previous.get("built_at"))
    recent = age is not None and age < FULL_REPULL_AFTER_DAYS
    if since is not None and existing.is_file() and recent:
        current = {line for line in existing.read_text(encoding="utf-8").split("\n") if line}
        return fetch_npm_changes(current, since, progress)
    return fetch_npm_full(progress)


def fetch_npm_full(progress: Progress = lambda _: None) -> tuple[set[str], object]:
    """Every package on npm, walked from the replication database.

    The sequence number is read BEFORE the walk and stored with the result, so the
    next refresh replays anything that changed during these five minutes rather than
    missing it. Replaying is idempotent; missing is not.
    """
    progress("npm: no index yet, so walking the whole registry (about 146MB in 439 "
             "requests; roughly five minutes)")
    seq = _json(_get(NPM_REPLICATE + "/")).get("update_seq")
    names: set[str] = set()
    start: str | None = None
    pages = 0
    while True:
        query: dict = {"limit": PAGE}
        if start is not None:
            query["start_key"] = json.dumps(start)
        rows = _json(_get(f"{NPM_REPLICATE}/_all_docs?{urlencode(query)}")).get("rows") or []
        # `start_key` is inclusive, so the last key of the previous page leads this one.
        if start is not None and rows and rows[0].get("key") == start:
            rows = rows[1:]
        if not rows:
            break
        for row in rows:
            key = row.get("key")
            if isinstance(key, str) and key and not key.startswith("_"):
                names.add(key.lower())
        start = rows[-1]["key"]
        pages += 1
        if pages % 50 == 0:
            progress(f"npm: {len(names):,} names so far")
        if len(rows) < PAGE - 1:
            break
    return names, seq


def fetch_npm_changes(current: set[str], since: object,
                      progress: Progress = lambda _: None) -> tuple[set[str], object]:
    """Apply the change feed since `since` to an existing set of names.

    One entry per changed document with its latest state, so an entry is either a
    name that now exists (added or republished — adding is idempotent) or one that
    was deleted. Measured at ~24,000 entries a day: a week of drift is ~17 requests.
    """
    progress("npm: fetching changes since the last update")
    names = set(current)
    last = since
    pages = 0
    while True:
        query = urlencode({"since": last, "limit": PAGE})
        data = _json(_get(f"{NPM_REPLICATE}/_changes?{query}"))
        results = data.get("results") or []
        for change in results:
            name = change.get("id")
            if not isinstance(name, str) or not name or name.startswith("_"):
                continue
            if change.get("deleted"):
                names.discard(name.lower())
            else:
                names.add(name.lower())
        new_last = data.get("last_seq", last)
        pages += 1
        if len(results) < PAGE or new_last == last:
            last = new_last
            break
        last = new_last
    progress(f"npm: applied {pages} page(s) of changes")
    return names, last


# ------------------------------------------------------------------ plumbing

def _get(url: str, *, accept: str = "application/json") -> bytes:
    if not url.startswith("https://"):
        raise IndexUnavailable(f"refusing a non-https index source: {url!r}")
    request = urllib.request.Request(  # noqa: S310 — https asserted above
        url, headers={**_UA, "Accept": accept, "Accept-Encoding": "gzip"}
    )
    for attempt in range(_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
                raw = response.read()
                if response.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return raw
        except urllib.error.HTTPError as exc:
            # A client error will not improve with retrying; a server one might.
            if exc.code < 500 or attempt == _ATTEMPTS - 1:
                raise IndexUnavailable(f"{url}: {exc}") from exc
        except (urllib.error.URLError, OSError, TimeoutError, EOFError) as exc:
            if attempt == _ATTEMPTS - 1:
                raise IndexUnavailable(f"{url}: {exc}") from exc
        time.sleep(2 * (attempt + 1))
    raise IndexUnavailable(url)  # unreachable; keeps the type checker honest


def _json(body: bytes) -> dict:
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise IndexUnavailable(f"the registry returned something other than JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _write_names(path: Path, names: set[str]) -> None:
    """Sorted bytewise — the order `NameIndex.contains` bisects in — via a sibling
    temporary file and an atomic rename."""
    ordered = sorted(n.encode("utf-8") for n in names if n and "\n" not in n)
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "wb") as handle:
        for name in ordered:
            handle.write(name)
            handle.write(b"\n")
    os.replace(temporary, path)


def _read_metadata(directory: Path) -> dict:
    path = directory / METADATA
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict) or not isinstance(data.get("ecosystems"), dict):
        data = {"schema": 1, "ecosystems": {}}
    return data


def _write_metadata(directory: Path, metadata: dict) -> None:
    path = directory / METADATA
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _age_days(stamp: object) -> float | None:
    from . import cache

    return cache.stamp_age_days(stamp)
