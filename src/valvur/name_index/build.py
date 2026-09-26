"""Building the index: the static mirror, and the five registries walked
directly — what the publishing workflow runs, and what `valvur update` falls
back to when the published index cannot be reached. Split from
`name_index.py` (28.4.2): a scan never imports this; the hot path stopped
importing `csv`, `tarfile` and five registry walkers to open a file.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import tarfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlencode

from .. import ecosystems as _ecosystems
from . import published as _published
from . import reader as _reader
from .reader import Progress

PYPI_SIMPLE = "https://pypi.org/simple/"
NPM_REPLICATE = "https://replicate.npmjs.com"
RUBYGEMS_NAMES = "https://rubygems.org/names"
PACKAGIST_LIST = "https://packagist.org/packages/list.json"
CRATES_DUMP = "https://static.crates.io/db-dump.tar.gz"
#: The replication server's page cap, measured 2026-09-12: 10,000 rows per request
#: for both `_all_docs` and `_changes`, and `skip` refused outright.
PAGE = 10_000
TIMEOUT = 120
_ATTEMPTS = 4
#: Past this age the change feed costs about what a full walk does, and a `since`
#: that old is more likely to have been compacted away. Start over.
FULL_REPULL_AFTER_DAYS = 90
#: A registry walked this recently is not walked again unless asked (`--build-index`).
#: The registries change slowly against a 30-day staleness threshold, the published
#: index is cut once a day, and the fallback walk is 400MB — a CI job restoring
#: yesterday's cache, or a user running `valvur update` twice while GHCR is down,
#: should not pay that twice in a day.
WALK_MIN_INTERVAL_HOURS = 20
_UA = {"User-Agent": "valvur (+https://github.com/MaverickHQ/valvur)"}

# ----------------------------------------------------------------- building

def refresh(directory: Path, *, ecosystems: Iterable[str] | None = None,
            progress: Progress = lambda _: None, published: bool = True,
            fallback: bool = True) -> dict:
    """Bring `directory` up to date from the first source that answers. Returns the
    metadata written.

    The order is the cost order. A static mirror (`VALVUR_NAME_INDEX_URL`) is the
    operator saying "here, and nowhere else". The published index is one pull. The
    registries are the fallback — a walk of five of them, minutes rather than
    seconds — and what the workflow that publishes the index runs. `published=False`
    is that walk on demand (`valvur update --build-index`); `fallback=False` rules
    it out, for a first scan fetching an absent index (24.1): seven minutes and
    700MB is the download 14.2 called hostile inside a scan, and it stays out of one.

    Each file is written whole and renamed into place, so a scan reading the index
    while it is refreshed sees the old list or the new one, never a partial one. The
    caller holds the cache lock (exclusive) around this; see `cli.py` and `api.py`.
    """
    directory.mkdir(parents=True, exist_ok=True)
    mirror = os.environ.get(_reader.MIRROR_ENV, "").strip()
    if mirror:
        return fetch_mirror(mirror, directory, ecosystems=ecosystems, progress=progress)
    if published:
        named = os.environ.get(_reader.INDEX_REPOSITORY_ENV, "").strip()
        try:
            return _published.fetch_published(_published.repository(), directory,
                                              ecosystems=ecosystems,
                                   progress=progress)
        except _reader.IndexUnavailable as exc:
            if named or not fallback:
                raise      # an operator's mirror failed; the internet is not the answer
            progress(f"the published index is unavailable ({exc}); building it from the "
                     "registries directly instead")
    return walk(directory, ecosystems=ecosystems or tuple(_reader.FILES), progress=progress,
                force=not published)


def walk(directory: Path, *, ecosystems: Iterable[str] = tuple(_reader.FILES),
         progress: Progress = lambda _: None, force: bool = False) -> dict:
    """Fetch every ecosystem's names from its registry into `directory` — skipping
    one walked within `WALK_MIN_INTERVAL_HOURS` unless `force`."""
    directory.mkdir(parents=True, exist_ok=True)
    metadata = _reader._read_metadata(directory)
    for ecosystem in ecosystems:
        if ecosystem not in _reader.FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        previous = metadata["ecosystems"].get(ecosystem) or {}
        age = _reader._age_days(previous.get("built_at"))
        if (not force and (directory / _reader.FILES[ecosystem]).is_file()
                and age is not None and age * 24 < WALK_MIN_INTERVAL_HOURS):
            progress(f"{ecosystem}: walked {age * 24:.0f}h ago; not again today")
            continue
        names, entry = _fetch_one(ecosystem, directory, previous, progress)
        _reader._refuse_if_truncated(ecosystem, len(names), "the registry returned")
        _reader._write_names(directory / _reader.FILES[ecosystem], names)
        entry.update(built_at=_reader._now(), count=len(names))
        metadata["ecosystems"][ecosystem] = entry
        _reader._write_metadata(directory, metadata)
        progress(f"{ecosystem}: {len(names):,} names")
    return metadata


def _fetch_one(ecosystem: str, directory: Path, previous: dict,
               progress: Progress) -> tuple[set[str], dict]:
    if ecosystem == "pip":
        return fetch_pypi(progress), {"source": PYPI_SIMPLE}
    if ecosystem == "npm":
        names, seq = _fetch_npm(directory, previous, progress)
        return names, {"source": f"{NPM_REPLICATE}/_all_docs", "update_seq": seq}
    if ecosystem == "gem":
        return fetch_rubygems(progress), {"source": RUBYGEMS_NAMES}
    if ecosystem == "composer":
        return fetch_packagist(progress), {"source": PACKAGIST_LIST}
    return fetch_crates(progress), {"source": CRATES_DUMP}


# ------------------------------------------------------------- a static mirror

def fetch_mirror(base: str, directory: Path, *, ecosystems: Iterable[str] | None = None,
                 progress: Progress = lambda _: None) -> dict:
    """Copy the index from a mirror serving this directory's files verbatim.

    The mirror's `metadata.json` is what gets written, with its `built_at` intact —
    a copy taken this morning of a list built in March is a March list, and the
    scan must say so. Each file is validated against the same floor as a registry
    fetch: a truncated mirror is refused for the same reason a truncated registry
    response is. Without an explicit list, every ecosystem the mirror has is taken.
    """
    base = base.rstrip("/")
    if not base.startswith(("https://", "http://")):
        raise _reader.IndexUnavailable(f"{_reader.MIRROR_ENV} must be an http(s) URL, not {base!r}")
    progress(f"fetching the package-name index from the mirror at {base}")
    remote = _reader._json(_get(f"{base}/{_reader.METADATA}", allow_http=True))
    entries = remote.get("ecosystems") if isinstance(remote.get("ecosystems"), dict) else None
    if not entries:
        raise _reader.IndexUnavailable(f"{base}/{_reader.METADATA} carries no ecosystems; "
                                       "is this a mirror of "
                               "~/.cache/valvur/names?")
    wanted = (list(ecosystems) if ecosystems is not None
              else [e for e in _reader.FILES if e in entries])
    metadata = _reader._read_metadata(directory)
    for ecosystem in wanted:
        if ecosystem not in _reader.FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        if ecosystem not in entries:
            raise _reader.IndexUnavailable(f"the mirror at {base} has no {ecosystem} index")
        body = _get(f"{base}/{_reader.FILES[ecosystem]}", accept="text/plain", allow_http=True)
        names = {line for line in body.decode("utf-8", errors="replace").split("\n") if line}
        _reader._refuse_if_truncated(ecosystem, len(names), "the mirror served")
        _reader._write_names(directory / _reader.FILES[ecosystem], names)
        entry = dict(entries[ecosystem])
        entry["mirror"] = base
        metadata["ecosystems"][ecosystem] = entry
        _reader._write_metadata(directory, metadata)
        progress(f"{ecosystem}: {len(names):,} names, built {entry.get('built_at', '?')}")
    return metadata


# --------------------------------------------------------------- the registries

def fetch_pypi(progress: Progress = lambda _: None) -> set[str]:
    """Every project on PyPI, in PEP 503 canonical form. One request (PEP 691)."""
    progress("PyPI: fetching the simple index (about 10MB)")
    body = _get(PYPI_SIMPLE, accept="application/vnd.pypi.simple.v1+json")
    try:
        projects = json.loads(body)["projects"]
        return {_ecosystems.registry.pep503(p["name"])
                for p in projects if isinstance(p.get("name"), str)}
    except (KeyError, TypeError, ValueError) as exc:
        raise _reader.IndexUnavailable(
            f"PyPI returned an index this version cannot read: {exc}") from exc


def fetch_rubygems(progress: Progress = lambda _: None) -> set[str]:
    """Every gem on RubyGems, as published. One request, plain text, one name per
    line under a `---` document marker (2.8MB, measured 2026-09-12).

    Stored exactly as spelled: RubyGems is case-sensitive — `rails.json` answers
    200 and `Rails.json` 404 from the same API, measured the same day — so a
    `Gemfile` naming `Rails` names a gem that does not exist, and the index has to
    be able to say so.
    """
    progress("RubyGems: fetching the name list (about 3MB)")
    body = _get(RUBYGEMS_NAMES, accept="text/plain")
    return {line for line in body.decode("utf-8", errors="replace").split("\n")
            if line and line != "---"}


def fetch_packagist(progress: Progress = lambda _: None) -> set[str]:
    """Every package on Packagist, lowercase, `vendor/name`. One request (3.6MB
    gzip-encoded on the wire, 12MB decoded, measured 2026-09-12)."""
    progress("Packagist: fetching the package list (about 4MB)")
    data = _reader._json(_get(PACKAGIST_LIST))
    names = data.get("packageNames")
    if not isinstance(names, list):
        raise _reader.IndexUnavailable("Packagist returned a list this version cannot read "
                               "(no `packageNames`)")
    return {n.lower() for n in names if isinstance(n, str) and "/" in n}


def fetch_crates(progress: Progress = lambda _: None) -> set[str]:
    """Every crate on crates.io, in canonical form, streamed out of the registry's
    database dump.

    The dump is 1.86GB and there is no other list. But `data/crates.csv` is the
    third member of the archive, so a streaming read reaches it after 2MB and can
    stop when it ends: **381MB read, 17.5 seconds, 91MB of memory**, measured
    2026-09-12 — the phase note that called this "impossible per user" was written
    before measuring it. The CSV carries every crate's README, so fields run past
    the `csv` module's default limit and only the `name` column is kept.

    Canonical form is lowercase with `-` folded to `_`: crates.io answers
    `serde-json` and `Serde` with `serde_json` and `serde` (measured), and the dump
    has no two names that collide under the fold.
    """
    import sys

    progress("crates.io: streaming the crate list out of the database dump (about 380MB "
             "of the 1.9GB archive; stops after the list)")
    request = urllib.request.Request(
        CRATES_DUMP, headers={**_UA, "Accept": "application/gzip"}
    )
    csv.field_size_limit(sys.maxsize)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            with tarfile.open(fileobj=_Readable(response), mode="r|gz") as archive:
                for member in archive:
                    if not member.name.endswith("/data/crates.csv") or not member.isfile():
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        break
                    text = io.TextIOWrapper(io.BufferedReader(_Readable(stream), 1 << 20),
                                            encoding="utf-8", newline="")
                    reader = csv.reader(text)
                    header = next(reader, [])
                    if "name" not in header:
                        raise _reader.IndexUnavailable("crates.io's dump has no `name` column in "
                                               "crates.csv")
                    column = header.index("name")
                    return {_ecosystems.registry.crate(row[column])
                            for row in reader if len(row) > column}
    except (urllib.error.URLError, OSError, TimeoutError, EOFError, tarfile.TarError,
            csv.Error, UnicodeDecodeError) as exc:
        raise _reader.IndexUnavailable(f"{CRATES_DUMP}: {exc}") from exc
    raise _reader.IndexUnavailable("crates.io's dump holds no data/crates.csv")


class _Readable(io.RawIOBase):
    """The minimum `tarfile` and `TextIOWrapper` need from a response or a tar
    member: `read`, and a `readable()` that says so."""

    def __init__(self, stream):
        self._stream = stream

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        data = self._stream.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def _fetch_npm(directory: Path, previous: dict, progress: Progress) -> tuple[set[str], object]:
    """Incrementally when there is something to build on, in full otherwise."""
    existing = directory / _reader.FILES["npm"]
    since = previous.get("update_seq")
    age = _reader._age_days(previous.get("built_at"))
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
    seq = _reader._json(_get(NPM_REPLICATE + "/")).get("update_seq")
    names: set[str] = set()
    start: str | None = None
    pages = 0
    while True:
        query: dict = {"limit": PAGE}
        if start is not None:
            query["start_key"] = json.dumps(start)
        page = _reader._json(_get(f"{NPM_REPLICATE}/_all_docs?{urlencode(query)}"))
        rows = page.get("rows") or []
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
        data = _reader._json(_get(f"{NPM_REPLICATE}/_changes?{query}"))
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


def _get(url: str, *, accept: str = "application/json", allow_http: bool = False) -> bytes:
    permitted = ("https://", "http://") if allow_http else ("https://",)
    if not url.startswith(permitted):
        raise _reader.IndexUnavailable(f"refusing a non-https index source: {url!r}")
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
                raise _reader.IndexUnavailable(f"{url}: {exc}") from exc
        except (urllib.error.URLError, OSError, TimeoutError, EOFError) as exc:
            if attempt == _ATTEMPTS - 1:
                raise _reader.IndexUnavailable(f"{url}: {exc}") from exc
        time.sleep(2 * (attempt + 1))
    raise _reader.IndexUnavailable(url)  # unreachable; keeps the type checker honest


# ---------------------------------------------------------------- entry point

def _main(argv: list[str]) -> int:
    """`python -m valvur.name_index build DIR [ECOSYSTEM ...]` walks the registries
    into DIR — what the publishing workflow runs — and `pull DIR` fetches the
    published index into DIR with the same code every `valvur update` uses, which
    is how the workflow proves its own round trip before the day's tag moves."""
    import sys

    if len(argv) < 2 or argv[0] not in ("build", "pull"):
        print("usage: python -m valvur.name_index {build|pull} DIR [ECOSYSTEM ...]",
              file=sys.stderr)
        return 2
    directory = Path(argv[1])
    ecosystems = tuple(argv[2:]) or None
    try:
        if argv[0] == "build":
            walk(directory, ecosystems=ecosystems or tuple(_reader.FILES), progress=print,
                 force=True)
        else:
            _published.fetch_published(_published.repository(), directory,
                                       ecosystems=ecosystems, progress=print)
    except _reader.IndexUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


