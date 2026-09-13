"""The package-name index — existence answered offline (ADR-0018).

Two halves, one file, because the format is the contract between them:

- **Building**, on the host, by `valvur update`. Three sources, tried in order:
  an operator's static mirror; the **published index** — the same files, built
  daily by a workflow in this repository and pushed to GHCR as a signed OCI artifact
  (23.2.1), which is one pull rather than a walk of five registries; and, when
  neither is reachable, the registries themselves. PyPI, RubyGems and Packagist
  each publish their list in one request; crates.io's is streamed out of its
  database dump; npm is walked from the registry's own replication database, in
  full the first time and incrementally from its change feed after that. All of it
  lands in the host cache beside the vulnerability database (ADR-0012), never in
  the image.
- **Reading**, in the container, by the dependency-reality Check. The cache is
  mounted read-only at `/cache/names`, and a name is looked up by binary search over
  the memory-mapped file — 8µs a name, measured, with nothing to load first.

The format is one canonical name per line, sorted bytewise, UTF-8, LF. Plain text
on purpose: `grep -x reqeusts ~/.cache/valvur/names/pypi.txt` is the whole audit.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import mmap
import os
import tarfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

PYPI_SIMPLE = "https://pypi.org/simple/"
NPM_REPLICATE = "https://replicate.npmjs.com"
RUBYGEMS_NAMES = "https://rubygems.org/names"
PACKAGIST_LIST = "https://packagist.org/packages/list.json"
CRATES_DUMP = "https://static.crates.io/db-dump.tar.gz"

#: An air-gapped site's copy of the index (22.B.3): a URL under which the files of
#: this directory — one per ecosystem, and `metadata.json` — are served as-is, by
#: any static file server, from a machine that ran `valvur update` with a network.
#: `built_at` travels with them, so the age a scan reports is the age of the data
#: (F6.11), not of the copy. Plain HTTP is accepted here and nowhere else: this URL
#: is set by an operator, never derived from a package name.
MIRROR_ENV = "VALVUR_NAME_INDEX_URL"

#: The published index (23.2.1): the OCI repository `valvur update` pulls the index
#: from before it considers walking the registries. Mirrored the way the
#: vulnerability database is (`VALVUR_DB_REPOSITORY`): copy the artifact into any
#: registry — `cosign copy` or `oras cp --recursive` carries its signature along —
#: and name it here. Set explicitly, it is the only source tried; an operator who
#: named a mirror wants to hear that the mirror failed, not watch a fallback try
#: the internet.
INDEX_REPOSITORY_ENV = "VALVUR_INDEX_REPOSITORY"
DEFAULT_INDEX_REPOSITORY = "ghcr.io/maverickhq/valvur-index:latest"
#: `VALVUR_DB_INSECURE`'s counterpart: TLS without verification, or plain HTTP, for
#: a mirror registry that has neither a public certificate nor any TLS at all.
INDEX_INSECURE_ENV = "VALVUR_INDEX_INSECURE"
#: The artifact type the workflow pushes and the only one the shim will unpack.
ARTIFACT_TYPE = "application/vnd.valvur.name-index.v1"
CONFIG_TYPE = "application/vnd.valvur.name-index.config.v1+json"
LAYER_TYPE = "application/vnd.valvur.name-index.layer.v1+gzip"

#: One file per ecosystem, keyed by the ecosystem name the Check already uses for
#: Finding identity (ADR-0003) — so the Check can go from a declared package to a file
#: without a second table that could disagree with the first.
FILES: dict[str, str] = {
    "pip": "pypi.txt",
    "npm": "npm.txt",
    "gem": "rubygems.txt",
    "composer": "packagist.txt",
    "cargo": "crates.txt",
}
METADATA = "metadata.json"

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

#: A fetched list smaller than this is a truncated response, not a registry that
#: shrank. Writing it would report real packages as hallucinated by the thousand —
#: the worst finding this product can emit — so it is refused. Measured 2026-09-12:
#: PyPI 890,006; npm 4,382,736; RubyGems 196,829; Packagist 461,638; crates.io
#: 332,494.
MINIMUM_NAMES: dict[str, int] = {
    "pip": 500_000, "npm": 2_000_000, "gem": 100_000, "composer": 250_000, "cargo": 150_000,
}

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

def repository() -> str:
    """The OCI repository the published index is pulled from: the operator's mirror
    when named, the one this project publishes otherwise."""
    return os.environ.get(INDEX_REPOSITORY_ENV, "").strip() or DEFAULT_INDEX_REPOSITORY


def published_size_mb() -> int | None:
    """What pulling the published index will cost, from its manifest — for the line
    that says a first scan is fetching it (24.1). None when the registry cannot say,
    and for a static mirror, which has no manifest to ask."""
    from . import oci

    if os.environ.get(MIRROR_ENV, "").strip():
        return None
    size = oci.image_size(repository(), insecure=os.environ.get(INDEX_INSECURE_ENV) == "1")
    return None if size is None else max(1, round(size / 1_000_000))


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
    mirror = os.environ.get(MIRROR_ENV, "").strip()
    if mirror:
        return fetch_mirror(mirror, directory, ecosystems=ecosystems, progress=progress)
    if published:
        named = os.environ.get(INDEX_REPOSITORY_ENV, "").strip()
        try:
            return fetch_published(repository(), directory, ecosystems=ecosystems,
                                   progress=progress)
        except IndexUnavailable as exc:
            if named or not fallback:
                raise      # an operator's mirror failed; the internet is not the answer
            progress(f"the published index is unavailable ({exc}); building it from the "
                     "registries directly instead")
    return walk(directory, ecosystems=ecosystems or tuple(FILES), progress=progress,
                force=not published)


def walk(directory: Path, *, ecosystems: Iterable[str] = tuple(FILES),
         progress: Progress = lambda _: None, force: bool = False) -> dict:
    """Fetch every ecosystem's names from its registry into `directory` — skipping
    one walked within `WALK_MIN_INTERVAL_HOURS` unless `force`."""
    directory.mkdir(parents=True, exist_ok=True)
    metadata = _read_metadata(directory)
    for ecosystem in ecosystems:
        if ecosystem not in FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        previous = metadata["ecosystems"].get(ecosystem) or {}
        age = _age_days(previous.get("built_at"))
        if (not force and (directory / FILES[ecosystem]).is_file()
                and age is not None and age * 24 < WALK_MIN_INTERVAL_HOURS):
            progress(f"{ecosystem}: walked {age * 24:.0f}h ago; not again today")
            continue
        names, entry = _fetch_one(ecosystem, directory, previous, progress)
        _refuse_if_truncated(ecosystem, len(names), "the registry returned")
        _write_names(directory / FILES[ecosystem], names)
        entry.update(built_at=_now(), count=len(names))
        metadata["ecosystems"][ecosystem] = entry
        _write_metadata(directory, metadata)
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


def _refuse_if_truncated(ecosystem: str, count: int, who: str) -> None:
    if count < MINIMUM_NAMES[ecosystem]:
        raise IndexUnavailable(
            f"{ecosystem}: {who} {count:,} names, far fewer than the "
            f"{MINIMUM_NAMES[ecosystem]:,} the registry is known to hold. Refusing to "
            "write a truncated index — it would report real packages as hallucinated."
        )


# ------------------------------------------------------------ the published index

def fetch_published(repository: str, directory: Path, *, ecosystems: Iterable[str] | None = None,
                    progress: Progress = lambda _: None) -> dict:
    """Pull the index from an OCI registry (23.2.1) — the `trivy-db` pattern.

    The artifact's config blob IS the `metadata.json` the workflow built it with, so
    what the index will say about its own age is known from two small requests
    before a byte of names is fetched — and when every ecosystem on disk already
    carries the same `built_at`, nothing is. Each layer is one ecosystem's file,
    gzip-compressed, named by its title annotation; each is checked by digest as it
    streams, then for the invariants the reader bisects on — sorted, no blank lines,
    at least the floor — and only then renamed into place.

    The signature is verified before anything is written, by cosign when it is
    installed (`oci.verify_signature`); the outcome is recorded in the metadata so
    `run.json` can carry it.
    """
    from . import oci

    directory.mkdir(parents=True, exist_ok=True)
    insecure = os.environ.get(INDEX_INSECURE_ENV) == "1"
    try:
        reference = oci.Reference.parse(repository)
        registry = oci.Registry(reference, insecure=insecure)
        progress(f"fetching the package-name index from {reference}")
        manifest = registry.manifest()
        if manifest.body.get("artifactType") != ARTIFACT_TYPE:
            raise IndexUnavailable(f"{reference} is not a valvur name index "
                                   f"(artifactType {manifest.body.get('artifactType')!r})")
        config = manifest.body.get("config") or {}
        remote = _json(registry.blob_bytes(config.get("digest", ""), size=config.get("size")))
    except oci.RegistryError as exc:
        raise IndexUnavailable(str(exc)) from exc
    entries = remote.get("ecosystems") if isinstance(remote.get("ecosystems"), dict) else None
    if not entries:
        raise IndexUnavailable(f"{reference}@{manifest.digest} carries no ecosystems in its config")

    wanted = list(ecosystems) if ecosystems is not None else [e for e in FILES if e in entries]
    for ecosystem in wanted:
        if ecosystem not in FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        if ecosystem not in entries:
            raise IndexUnavailable(f"{reference} has no {ecosystem} index")
    layers = {}
    for layer in manifest.body.get("layers") or []:
        title = (layer.get("annotations") or {}).get("org.opencontainers.image.title", "")
        layers[title.removesuffix(".gz")] = layer

    metadata = _read_metadata(directory)
    current = [
        e for e in wanted
        if (metadata["ecosystems"].get(e) or {}).get("built_at") == entries[e].get("built_at")
        and (directory / FILES[e]).is_file()
    ]
    if len(current) == len(wanted):
        progress(f"the index is already the published one ({manifest.digest[:19]}); "
                 "nothing to fetch")
        return metadata

    verification = oci.verify_signature(f"{reference.repository}@{manifest.digest}",
                                        insecure=insecure)
    progress(f"signature: {verification}")

    for ecosystem in wanted:
        if ecosystem in current:
            continue
        layer = layers.get(FILES[ecosystem])
        if layer is None or layer.get("mediaType") != LAYER_TYPE:
            raise IndexUnavailable(f"{reference} has no {LAYER_TYPE} layer titled "
                                   f"{FILES[ecosystem]}.gz")
        target = directory / FILES[ecosystem]
        temporary = target.with_name(target.name + ".tmp")
        try:
            with open(temporary, "wb") as handle:
                count = _stream_layer(registry, layer, handle, ecosystem)
            os.replace(temporary, target)
        except (oci.RegistryError, OSError, EOFError, gzip.BadGzipFile) as exc:
            _discard(temporary)
            raise IndexUnavailable(f"{reference}: {exc}") from exc
        except IndexUnavailable:
            _discard(temporary)
            raise
        entry = dict(entries[ecosystem])
        entry["published"] = {
            "repository": reference.repository, "digest": manifest.digest,
            "signature": verification,
        }
        metadata["ecosystems"][ecosystem] = entry
        _write_metadata(directory, metadata)
        progress(f"{ecosystem}: {count:,} names, built {entry.get('built_at', '?')}")
    return metadata


def _stream_layer(registry, layer: dict, handle, ecosystem: str) -> int:
    """Blob → gunzip → file, checking as it goes what the reader will later assume:
    bytewise-sorted lines, none of them empty. A file that is not sorted would make
    `NameIndex.contains` answer "absent" for names it holds, so it is refused here,
    where the fix is to fetch again, rather than reported per package."""
    import zlib

    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    previous = b""
    tail = b""
    count = 0

    def take(chunk: bytes) -> None:
        nonlocal previous, tail, count
        data = tail + inflater.decompress(chunk)
        lines = data.split(b"\n")
        # The last piece is a line still in flight; it is checked and written with
        # the chunk that completes it. (Writing `data` whole here wrote every
        # boundary fragment twice — found by `cmp` on the first real round trip.)
        tail = lines.pop()
        for line in lines:
            if not line or line <= previous:
                raise IndexUnavailable(f"{ecosystem}: the published file is not a sorted "
                                       f"list at line {count + 1}; refusing it")
            previous = line
            count += 1
        handle.write(data[: len(data) - len(tail)])

    registry.blob(layer["digest"], take, size=layer.get("size"))
    if inflater.flush() or tail:
        raise IndexUnavailable(f"{ecosystem}: the published file does not end in a newline")
    _refuse_if_truncated(ecosystem, count, "the published index holds")
    return count


def _discard(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


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
        raise IndexUnavailable(f"{MIRROR_ENV} must be an http(s) URL, not {base!r}")
    progress(f"fetching the package-name index from the mirror at {base}")
    remote = _json(_get(f"{base}/{METADATA}", allow_http=True))
    entries = remote.get("ecosystems") if isinstance(remote.get("ecosystems"), dict) else None
    if not entries:
        raise IndexUnavailable(f"{base}/{METADATA} carries no ecosystems; is this a mirror of "
                               "~/.cache/valvur/names?")
    wanted = list(ecosystems) if ecosystems is not None else [e for e in FILES if e in entries]
    metadata = _read_metadata(directory)
    for ecosystem in wanted:
        if ecosystem not in FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        if ecosystem not in entries:
            raise IndexUnavailable(f"the mirror at {base} has no {ecosystem} index")
        body = _get(f"{base}/{FILES[ecosystem]}", accept="text/plain", allow_http=True)
        names = {line for line in body.decode("utf-8", errors="replace").split("\n") if line}
        _refuse_if_truncated(ecosystem, len(names), "the mirror served")
        _write_names(directory / FILES[ecosystem], names)
        entry = dict(entries[ecosystem])
        entry["mirror"] = base
        metadata["ecosystems"][ecosystem] = entry
        _write_metadata(directory, metadata)
        progress(f"{ecosystem}: {len(names):,} names, built {entry.get('built_at', '?')}")
    return metadata


# --------------------------------------------------------------- the registries

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
    data = _json(_get(PACKAGIST_LIST))
    names = data.get("packageNames")
    if not isinstance(names, list):
        raise IndexUnavailable("Packagist returned a list this version cannot read "
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
                        raise IndexUnavailable("crates.io's dump has no `name` column in "
                                               "crates.csv")
                    column = header.index("name")
                    return {crate_canonical(row[column]) for row in reader if len(row) > column}
    except (urllib.error.URLError, OSError, TimeoutError, EOFError, tarfile.TarError,
            csv.Error, UnicodeDecodeError) as exc:
        raise IndexUnavailable(f"{CRATES_DUMP}: {exc}") from exc
    raise IndexUnavailable("crates.io's dump holds no data/crates.csv")


def crate_canonical(name: str) -> str:
    return name.lower().replace("-", "_")


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

def _get(url: str, *, accept: str = "application/json", allow_http: bool = False) -> bytes:
    permitted = ("https://", "http://") if allow_http else ("https://",)
    if not url.startswith(permitted):
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
            walk(directory, ecosystems=ecosystems or tuple(FILES), progress=print, force=True)
        else:
            fetch_published(repository(), directory, ecosystems=ecosystems, progress=print)
    except IndexUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(_main(sys.argv[1:]))
