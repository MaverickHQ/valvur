"""The published index (23.2.1): the OCI artifact `valvur update` pulls — the
`trivy-db` pattern — verified by cosign when installed. Split from
`name_index.py` (28.4.2): this is the pull every user's machine makes; the
registry walk that builds what is pulled is `build.py`, and neither is needed
to read the index a scan uses (`reader.py`).
"""

from __future__ import annotations

import gzip
import os
import shutil
from collections.abc import Iterable
from pathlib import Path

from . import reader as _reader
from .reader import Progress

#: The published index (23.2.1): the OCI repository `valvur update` pulls the index
#: from before it considers walking the registries. Mirrored the way the
#: vulnerability database is (`VALVUR_DB_REPOSITORY`): copy the artifact into any
#: registry — `cosign copy` or `oras cp --recursive` carries its signature along —
#: and name it here. Set explicitly, it is the only source tried; an operator who
#: named a mirror wants to hear that the mirror failed, not watch a fallback try
#: the internet.
#: The one verdict that can improve without the index changing: cosign absent when
#: the index was pulled, installed by the time of the next `update` (27.1.3). Matched
#: as a prefix because `oci.verify_signature` appends the fix to it.
_COSIGN_ABSENT = "not verified: cosign is not installed"
#: The artifact type the workflow pushes and the only one the shim will unpack.
ARTIFACT_TYPE = "application/vnd.valvur.name-index.v1"
CONFIG_TYPE = "application/vnd.valvur.name-index.config.v1+json"
LAYER_TYPE = "application/vnd.valvur.name-index.layer.v1+gzip"

def repository() -> str:
    """The OCI repository the published index is pulled from: the operator's mirror
    when named, the one this project publishes otherwise."""
    named = os.environ.get(_reader.INDEX_REPOSITORY_ENV, "").strip()
    return named or _reader.DEFAULT_INDEX_REPOSITORY


def published_size_mb() -> int | None:
    """What pulling the published index will cost, from its manifest — for the line
    that says a first scan is fetching it (24.1). None when the registry cannot say,
    and for a static mirror, which has no manifest to ask."""
    from .. import oci

    if os.environ.get(_reader.MIRROR_ENV, "").strip():
        return None
    size = oci.image_size(repository(), insecure=os.environ.get(_reader.INDEX_INSECURE_ENV) == "1")
    return None if size is None else max(1, round(size / 1_000_000))


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
    from .. import oci

    directory.mkdir(parents=True, exist_ok=True)
    insecure = os.environ.get(_reader.INDEX_INSECURE_ENV) == "1"
    try:
        reference = oci.Reference.parse(repository)
        registry = oci.Registry(reference, insecure=insecure)
        progress(f"fetching the package-name index from {reference}")
        manifest = registry.manifest()
        if manifest.body.get("artifactType") != ARTIFACT_TYPE:
            raise _reader.IndexUnavailable(f"{reference} is not a valvur name index "
                                   f"(artifactType {manifest.body.get('artifactType')!r})")
        config = manifest.body.get("config") or {}
        remote = _reader._json(registry.blob_bytes(config.get("digest", ""),
                                                   size=config.get("size")))
    except oci.RegistryError as exc:
        raise _reader.IndexUnavailable(str(exc)) from exc
    entries = remote.get("ecosystems") if isinstance(remote.get("ecosystems"), dict) else None
    if not entries:
        raise _reader.IndexUnavailable(
            f"{reference}@{manifest.digest} carries no ecosystems in its config")

    wanted = (list(ecosystems) if ecosystems is not None
              else [e for e in _reader.FILES if e in entries])
    for ecosystem in wanted:
        if ecosystem not in _reader.FILES:
            raise ValueError(f"no index is defined for {ecosystem!r}")
        if ecosystem not in entries:
            raise _reader.IndexUnavailable(f"{reference} has no {ecosystem} index")
    layers = {}
    for layer in manifest.body.get("layers") or []:
        title = (layer.get("annotations") or {}).get("org.opencontainers.image.title", "")
        layers[title.removesuffix(".gz")] = layer

    metadata = _reader._read_metadata(directory)
    current = [
        e for e in wanted
        if (metadata["ecosystems"].get(e) or {}).get("built_at") == entries[e].get("built_at")
        and (directory / _reader.FILES[e]).is_file()
    ]
    if len(current) == len(wanted):
        progress(f"the index is already the published one ({manifest.digest[:19]}); "
                 "nothing to fetch")
        return _reverify(directory, metadata, wanted, reference, manifest.digest,
                         insecure=insecure, progress=progress)

    verification = oci.verify_signature(f"{reference.repository}@{manifest.digest}",
                                        insecure=insecure)
    progress(f"signature: {verification}")

    for ecosystem in wanted:
        if ecosystem in current:
            continue
        layer = layers.get(_reader.FILES[ecosystem])
        if layer is None or layer.get("mediaType") != LAYER_TYPE:
            raise _reader.IndexUnavailable(f"{reference} has no {LAYER_TYPE} layer titled "
                                   f"{_reader.FILES[ecosystem]}.gz")
        target = directory / _reader.FILES[ecosystem]
        temporary = target.with_name(target.name + ".tmp")
        try:
            with open(temporary, "wb") as handle:
                count = _stream_layer(registry, layer, handle, ecosystem)
            os.replace(temporary, target)
        except (oci.RegistryError, OSError, EOFError, gzip.BadGzipFile) as exc:
            _discard(temporary)
            raise _reader.IndexUnavailable(f"{reference}: {exc}") from exc
        except _reader.IndexUnavailable:
            _discard(temporary)
            raise
        entry = dict(entries[ecosystem])
        entry["published"] = {
            "repository": reference.repository, "digest": manifest.digest,
            "signature": verification,
        }
        metadata["ecosystems"][ecosystem] = entry
        _reader._write_metadata(directory, metadata)
        progress(f"{ecosystem}: {count:,} names, built {entry.get('built_at', '?')}")
    return metadata


def _reverify(directory: Path, metadata: dict, wanted: list[str], reference,
              digest: str, *, insecure: bool, progress: Progress) -> dict:
    """Check the signature of an index already on disk, when the verdict recorded
    for it was "cosign is not installed" and cosign now is (task 27.1.3).

    The shortcut above is what makes a daily `update` free on a current machine,
    and it returned before the signature was ever looked at — so an index pulled
    without cosign kept that verdict for as long as that build stayed published,
    a trust state the user could not improve by installing the tool the message
    named. Only the recorded digest is verified: no layer moves, and a verdict
    already recorded for this digest is not paid for twice.

    A refusal is `oci.SignatureInvalid` out of `verify_signature`, uncaught, as
    everywhere else. The files stay as they are — this path fetched nothing, so
    there is nothing of this run's to undo, and a half-deleted index would leave
    the machine worse than the one it distrusts.
    """
    from .. import oci

    stale = [e for e in wanted
             if ((metadata["ecosystems"].get(e) or {}).get("published") or {})
             .get("signature", "").startswith(_COSIGN_ABSENT)]
    if not stale or shutil.which("cosign") is None:
        return metadata

    verification = oci.verify_signature(f"{reference.repository}@{digest}", insecure=insecure)
    progress(f"signature: {verification}")
    if verification.startswith(_COSIGN_ABSENT):     # it went away between the two calls
        return metadata
    for ecosystem in stale:
        metadata["ecosystems"][ecosystem]["published"]["signature"] = verification
    _reader._write_metadata(directory, metadata)
    return metadata


def _stream_layer(registry, layer: dict, handle, ecosystem: str) -> int:
    """Blob → gunzip → file, checking as it goes what the reader will later assume:
    bytewise-sorted lines, none of them empty. A file that is not sorted would make
    `_reader.NameIndex.contains` answer "absent" for names it holds, so it is refused here,
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
                raise _reader.IndexUnavailable(f"{ecosystem}: the published file is not a sorted "
                                       f"list at line {count + 1}; refusing it")
            previous = line
            count += 1
        handle.write(data[: len(data) - len(tail)])

    registry.blob(layer["digest"], take, size=layer.get("size"))
    if inflater.flush() or tail:
        raise _reader.IndexUnavailable(f"{ecosystem}: the published file does not end in a newline")
    _reader._refuse_if_truncated(ecosystem, count, "the published index holds")
    return count


def _discard(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


