"""Known-malicious packages, published daily beside the index (D26, F3.14, ADR-0027).

ossf/malicious-packages (Apache-2.0) keeps one OSV record per package published to
attack whoever installs it: 238,545 records on 2026-09-29, 93% of them npm. OSV's
offline database carries the same records, but a scan refreshes it past seven days,
and the attack runs at install. So `index.yml` builds from the repository, daily, a
sorted list per ecosystem the index covers, and publishes it as the tags `malicious`
and `malicious-<date>` of the index's own package, signed and pulled back before it
is tagged, as the index is. The dependency-reality Check reads it offline by
bisection, as it reads the index, from beside it in the same mount.

**The format.** One line per name, sorted bytewise, UTF-8, LF: the name in the
index's form, a tab, the versions, a tab, the `MAL-` identifiers, comma-separated.
The versions are `*` when every version is malicious (a range from 0 with no end),
else each version a record names and each range it states, as `>=A`, `>=A<B` or
`>=A<=B`. A tab sorts below every character a name holds, so the file's order is its
names' order and `NameIndex.line` bisects it. `grep -P '^atez\\t' npm.txt` is the
whole audit.

Measured 2026-09-29: the repository's tarball is 46 MB and arrives in 1.8 s, against
296 MB of OSV's exports for the same ecosystems, so the tarball is the source. It is
read as a stream: unpacking its files to disk took 72 s on a Mac.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .. import ecosystems as _ecosystems
from .. import oci, settings
from . import published
from . import reader as _reader
from .build import _get
from .reader import IndexUnavailable, Progress

#: The day's state of the repository, as one gzip tarball.
SOURCE = "https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main"
DIRECTORY = "malicious"
#: One file per ecosystem the index covers, named as the index's are. Go and Maven
#: (20 records) have no offline index, and NuGet and VS Code (803) no parser.
FILES: dict[str, str] = dict(_reader.FILES)
TAG = "malicious"
ARTIFACT_TYPE = "application/vnd.valvur.malicious-list.v1"
CONFIG_TYPE = "application/vnd.valvur.malicious-list.config.v1+json"
LAYER_TYPE = "application/vnd.valvur.malicious-list.layer.v1+gzip"
_TOKEN = re.compile(r"[^\s,\t]+")
_RANGE = re.compile(r">=([^<]+)(?:(<=?)(.+))?")


def directory(names: Path) -> Path:
    return names / DIRECTORY


# ------------------------------------------------------------------ reading


@dataclass(frozen=True)
class Entry:
    """One name's line: the versions it covers, None for every version, and the
    records that say so."""

    versions: frozenset[str] | None
    ids: tuple[str, ...]

    def names(self, version: str | None) -> bool:
        """Whether this entry covers `version`. A declared package with no version
        locked is covered only when every version is (D26)."""
        if self.versions is None:
            return True
        if not version:
            return False
        return any(_covers(token, version) for token in self.versions)


def _release(version: str) -> tuple[tuple[int, ...], int] | None:
    """A version's release numbers, and whether it is a release (1) or a pre-release
    of it (0), which sorts first. None when it does not start with a number: then no
    range can be judged, and only an exact version matches."""
    match = re.match(r"v?(\d+(?:\.\d+)*)(.*)", version.strip())
    if not match:
        return None
    numbers = tuple(int(part) for part in match.group(1).split("."))
    return numbers, 0 if match.group(2)[:1] in ("-", "a", "b", "r", "c") else 1


def _before(a: tuple[tuple[int, ...], int], b: tuple[tuple[int, ...], int]) -> int:
    width = max(len(a[0]), len(b[0]))
    left = (a[0] + (0,) * (width - len(a[0])), a[1])
    right = (b[0] + (0,) * (width - len(b[0])), b[1])
    return (left > right) - (left < right)


def _covers(token: str, version: str) -> bool:
    ranged = _RANGE.fullmatch(token)
    if not ranged:
        return token == version
    have, low = _release(version), _release(ranged.group(1))
    if have is None or low is None or _before(have, low) < 0:
        return False
    if not ranged.group(2):
        return True
    high = _release(ranged.group(3))
    if high is None:
        return False
    order = _before(have, high)
    return order < 0 or (order == 0 and ranged.group(2) == "<=")


class MaliciousList(_reader.NameIndex):
    """One ecosystem's list, memory-mapped and bisected like the index."""

    def lookup(self, name: str) -> Entry | None:
        line = self.line(name)
        if line is None:
            return None
        _, versions, ids = line.decode("utf-8").split("\t")
        return Entry(None if versions == "*" else frozenset(versions.split(",")),
                     tuple(ids.split(",")))


def open_list(names: Path, ecosystem: str) -> MaliciousList | None:
    """The list for one ecosystem, or None when there is none to read."""
    filename = FILES.get(ecosystem)
    path = directory(names) / filename if filename else None
    return MaliciousList(path) if path is not None and path.is_file() else None


def metadata(names: Path) -> dict:
    try:
        data = json.loads((directory(names) / _reader.METADATA).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def age_days(names: Path) -> float | None:
    """How old the list is, from when it was built; None when there is none."""
    built = metadata(names).get("built_at")
    return _reader._age_days(built) if built else None


# ------------------------------------------------------------------ building


def _records(source: str) -> Iterator[dict]:
    """Every record under `osv/malicious/` in a checkout, a tarball or its URL. Only
    files: nine package directories there are themselves named `*.json`."""
    import tarfile

    def wanted(path: str) -> bool:
        return "/osv/malicious/" in f"/{path}" and path.endswith(".json")

    if Path(source).is_dir():
        for path in sorted(Path(source).rglob("*.json")):
            if path.is_file() and wanted(path.as_posix()):
                yield from _parsed(path.read_bytes())
        return
    if source.startswith(("https://", "http://")):
        import urllib.request

        stream = urllib.request.urlopen(source, timeout=300)  # noqa: S310 — a fixed https URL
    else:
        stream = open(source, "rb")
    with stream, tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            if member.isfile() and wanted(member.name):
                handle = archive.extractfile(member)
                if handle is not None:
                    yield from _parsed(handle.read())


def _readable(source: str) -> Iterator[dict]:
    """`_records`, with any failure to reach or read the source as the one error a
    refresh reports and survives."""
    import tarfile
    import zlib

    try:
        yield from _records(source)
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise IndexUnavailable(f"the malicious list's source could not be read: {exc}") \
            from exc


def _parsed(body: bytes) -> Iterator[dict]:
    try:
        record = json.loads(body)
    except ValueError:
        return
    if isinstance(record, dict) and not record.get("withdrawn"):
        yield record


def _scope(affected: dict) -> set[str] | None:
    """The versions one `affected` entry covers, None for every version: a range
    introduced at 0 with no end, or an entry that names no version at all."""
    tokens = {v for v in affected.get("versions") or [] if _TOKEN.fullmatch(str(v))}
    for stated in affected.get("ranges") or []:
        if stated.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue                         # a GIT range names commits, not versions
        start: str | None = None
        for event in stated.get("events") or []:
            if "introduced" in event:
                start = str(event["introduced"])
                continue
            for key, bound in (("fixed", "<"), ("last_affected", "<="), ("limit", "<")):
                if key in event and start is not None:
                    tokens.add(f">={start}{bound}{event[key]}")
                    start = None
        if start == "0":
            return None
        if start is not None:
            tokens.add(f">={start}")
    tokens = {t for t in tokens if _TOKEN.fullmatch(t)}
    return tokens or None


def build_lists(names: Path, source: str, *, progress: Progress = lambda _: None) -> dict:
    """The lists from `source`, written into `directory(names)` whole and renamed
    into place, with their metadata. Returns the metadata."""
    progress(f"building the malicious list from {source}")
    found: dict[str, dict[str, tuple[set[str] | None, set[str]]]] = {e: {} for e in FILES}
    passed_over: Counter[str] = Counter()
    records = 0
    for record in _readable(source):
        records += 1
        identifier = str(record.get("id", ""))
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            spelled = str(package.get("ecosystem") or "unnamed")
            ecosystem = _ecosystems.normalise(spelled)
            raw = str(package.get("name") or "")
            if ecosystem not in FILES or not raw:
                passed_over[spelled] += 1
                continue
            name = _ecosystems.index_form(ecosystem, raw)
            if not name.isprintable() or "\t" in name:
                passed_over[spelled] += 1
                continue
            scope = _scope(affected)
            versions, ids = found[ecosystem].get(name, (set(), set()))
            merged = None if scope is None or versions is None else versions | scope
            found[ecosystem][name] = (merged, ids | {identifier})

    target = directory(names)
    target.mkdir(parents=True, exist_ok=True)
    built_at = _reader._now()
    entries = {}
    for ecosystem, file in FILES.items():
        lines = sorted(
            f"{name}\t{'*' if versions is None else ','.join(sorted(versions))}"
            f"\t{','.join(sorted(ids))}\n".encode()
            for name, (versions, ids) in found[ecosystem].items())
        temporary = target / f"{file}.tmp"
        temporary.write_bytes(b"".join(lines))
        os.replace(temporary, target / file)
        entries[ecosystem] = {"count": len(lines), "built_at": built_at}
        progress(f"{ecosystem}: {len(lines):,} malicious names")
    written = {"schema": 1, "built_at": built_at, "source": source, "records": records,
               "ecosystems": entries, "passed_over": dict(sorted(passed_over.items()))}
    _reader._write_metadata(target, written)
    return written


# ------------------------------------------------------------------ fetching


def reference() -> str:
    """The list's tag in the index's own repository, or the operator's mirror of it."""
    try:
        parsed = oci.Reference.parse(published.repository())
    except oci.RegistryError as exc:
        raise IndexUnavailable(str(exc)) from exc
    return f"{parsed.repository}:{TAG}"


def fetch_published(ref: str, names: Path, *, progress: Progress = lambda _: None) -> dict:
    """Pull the published list, as `published.fetch_published` pulls the index: the
    signature verified before anything is written, each layer checked sorted as it
    streams, each file renamed into place. Nothing moves when the list on disk is
    the one published."""
    insecure = settings.get("index_insecure") == "1"
    try:
        parsed = oci.Reference.parse(ref)
        registry = oci.Registry(parsed, insecure=insecure)
        progress(f"fetching the malicious list from {parsed}")
        manifest = registry.manifest()
        if manifest.body.get("artifactType") != ARTIFACT_TYPE:
            raise IndexUnavailable(f"{parsed} is not a valvur malicious list "
                                   f"(artifactType {manifest.body.get('artifactType')!r})")
        config = manifest.body.get("config") or {}
        remote = _reader._json(registry.blob_bytes(config.get("digest", ""),
                                                   size=config.get("size")))
    except oci.RegistryError as exc:
        raise IndexUnavailable(str(exc)) from exc
    target = directory(names)
    local = metadata(names)
    if (local.get("built_at") and local.get("built_at") == remote.get("built_at")
            and all((target / file).is_file() for file in FILES.values())):
        progress(f"the malicious list is already the published one ({manifest.digest[:19]})")
        return local
    verification = oci.verify_signature(f"{parsed.repository}@{manifest.digest}",
                                        insecure=insecure)
    progress(f"signature: {verification}")
    layers = {(layer.get("annotations") or {}).get("org.opencontainers.image.title", ""): layer
              for layer in manifest.body.get("layers") or []}
    target.mkdir(parents=True, exist_ok=True)
    for ecosystem, file in FILES.items():
        layer = layers.get(f"{file}.gz")
        if layer is None or layer.get("mediaType") != LAYER_TYPE:
            raise IndexUnavailable(f"{parsed} has no {LAYER_TYPE} layer titled {file}.gz")
        temporary = target / f"{file}.tmp"
        try:
            with open(temporary, "wb") as handle:
                published._stream_layer(registry, layer, handle, ecosystem, floor=False)
            os.replace(temporary, target / file)
        except (oci.RegistryError, OSError, EOFError) as exc:
            temporary.unlink(missing_ok=True)
            raise IndexUnavailable(f"{parsed}: {exc}") from exc
        except IndexUnavailable:
            temporary.unlink(missing_ok=True)
            raise
    remote["published"] = {"repository": parsed.repository, "digest": manifest.digest,
                           "signature": verification}
    _reader._write_metadata(target, remote)
    progress(f"malicious list: built {remote.get('built_at', '?')}")
    return remote


def fetch_mirror(base: str, names: Path, *, progress: Progress = lambda _: None) -> dict:
    """The list from a static mirror of the index, under its `malicious/`."""
    base = f"{base.rstrip('/')}/{DIRECTORY}"
    progress(f"fetching the malicious list from the mirror at {base}")
    remote = _reader._json(_get(f"{base}/{_reader.METADATA}", allow_http=True))
    target = directory(names)
    target.mkdir(parents=True, exist_ok=True)
    for file in FILES.values():
        body = _get(f"{base}/{file}", accept="text/plain", allow_http=True)
        keys = [line.partition(b"\t")[0] for line in body.split(b"\n") if line]
        if keys != sorted(set(keys)):
            raise IndexUnavailable(f"{base}/{file} is not a sorted list; refusing it")
        (target / f"{file}.tmp").write_bytes(body)
        os.replace(target / f"{file}.tmp", target / file)
    remote["mirror"] = base
    _reader._write_metadata(target, remote)
    return remote


def refresh(names: Path, *, build: bool = False, fallback: bool = True,
            progress: Progress = lambda _: None) -> dict:
    """The list from the first source that answers, in the index's order: an
    operator's mirror, then the published list, then the repository itself. A scan
    passes `fallback=False` and never builds; `valvur update` builds when the list
    is not published, which it is not until `index.yml` runs from `main`, and
    `build` (`--build-index`) builds without asking."""
    mirror = settings.get("name_index_url")
    if mirror:
        return fetch_mirror(mirror, names, progress=progress)
    if not build:
        try:
            return fetch_published(reference(), names, progress=progress)
        except IndexUnavailable as exc:
            if settings.get("index_repository") or not fallback:
                raise
            progress(f"the published malicious list is unavailable ({exc}); "
                     "building it from its source instead")
    return build_lists(names, SOURCE, progress=progress)


def _main(argv: list[str]) -> int:
    """`python -m valvur.name_index build-malicious DIR [SOURCE]` builds the list into
    DIR/malicious from the repository, a tarball of it or a checkout, as `index.yml`
    does daily; `pull-malicious DIR [REFERENCE]` pulls it with the client every
    `valvur update` runs, which is how the workflow proves its round trip."""
    import sys

    if len(argv) < 2 or argv[0] not in ("build-malicious", "pull-malicious"):
        print("usage: python -m valvur.name_index {build-malicious DIR [SOURCE] | "
              "pull-malicious DIR [REFERENCE]}", file=sys.stderr)
        return 2
    names = Path(argv[1])
    try:
        if argv[0] == "build-malicious":
            build_lists(names, argv[2] if len(argv) > 2 else SOURCE, progress=print)
        else:
            fetch_published(argv[2] if len(argv) > 2 else reference(), names, progress=print)
    except IndexUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
