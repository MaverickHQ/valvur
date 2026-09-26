"""The package-name index — reading, and the on-disk contract (ADR-0018).

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

import json
import mmap
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .. import ecosystems as _ecosystems

#: An air-gapped site's copy of the index (22.B.3): a URL under which the files of
#: this directory — one per ecosystem, and `metadata.json` — are served as-is, by
#: any static file server, from a machine that ran `valvur update` with a network.
#: `built_at` travels with them, so the age a scan reports is the age of the data
#: (F6.11), not of the copy. Plain HTTP is accepted here and nowhere else: this URL
#: is set by an operator, never derived from a package name.
MIRROR_ENV = "VALVUR_NAME_INDEX_URL"
INDEX_REPOSITORY_ENV = "VALVUR_INDEX_REPOSITORY"
DEFAULT_INDEX_REPOSITORY = "ghcr.io/maverickhq/valvur-index:latest"
#: `VALVUR_DB_INSECURE`'s counterpart: TLS without verification, or plain HTTP, for
#: a mirror registry that has neither a public certificate nor any TLS at all.
INDEX_INSECURE_ENV = "VALVUR_INDEX_INSECURE"
#: One file per ecosystem, keyed by the ecosystem name the Check already uses for
#: Finding identity (ADR-0003) — so the Check can go from a declared package to a file
#: without a second table that could disagree with the first.
FILES: dict[str, str] = dict(_ecosystems.INDEX_FILES)
METADATA = "metadata.json"
#: A fetched list smaller than this is a truncated response, not a registry that
#: shrank. Writing it would report real packages as hallucinated by the thousand —
#: the worst finding this product can emit — so it is refused. Measured 2026-09-12:
#: PyPI 890,006; npm 4,382,736; RubyGems 196,829; Packagist 461,638; crates.io
#: 332,494.
MINIMUM_NAMES: dict[str, int] = {
    "pip": 500_000, "npm": 2_000_000, "gem": 100_000, "composer": 250_000, "cargo": 150_000,
}
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




# ------------------------------------------- the on-disk contract, shared

def _refuse_if_truncated(ecosystem: str, count: int, who: str) -> None:
    if count < MINIMUM_NAMES[ecosystem]:
        raise IndexUnavailable(
            f"{ecosystem}: {who} {count:,} names, far fewer than the "
            f"{MINIMUM_NAMES[ecosystem]:,} the registry is known to hold. Refusing to "
            "write a truncated index — it would report real packages as hallucinated."
        )


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
    from .. import cache

    return cache.stamp_age_days(stamp)


