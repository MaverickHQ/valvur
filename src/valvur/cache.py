"""Host-side cache for vulnerability data (ADR-0012) and the package-name index
(ADR-0018).

Lives outside the image so advisory freshness and image version stay independent —
they change at completely different rates.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import ecosystems as _ecosystems
from .version import IMAGE_REPOSITORY, __version__

STALE_AFTER_DAYS = 30

#: When a clean result stops being trustworthy. Trivy rebuilds its database every
#: 24 hours — `NextUpdate` is always `UpdatedAt + 24h` — so seven days is seven
#: missed rebuilds, not a number chosen because it sounded careful. Being a few
#: hours past due is normal and says nothing; a week of missed advisories is the
#: difference between "we looked and found nothing" and "we did not look recently
#: enough to know".
DB_STALE_AFTER_DAYS = 7

#: When the package-name index stops being evidence (ADR-0018). Thirty days is
#: roughly 16,000 PyPI and 48,000 npm names of drift, and matches the KEV threshold
#: already reported beside it. The failure direction is the opposite of the
#: database's: an old index is MISSING names, so it overstates — a package newer than
#: the index is reported nonexistent — rather than letting a hallucination through.
#: The threshold keeps the answer's age visible; it is not a cliff.
NAME_INDEX_STALE_AFTER_DAYS = 30


def root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.environ.get("VALVUR_CACHE")
    return Path(base or (Path.home() / ".cache")) / "valvur"


def trivy_db() -> Path:
    return root() / "trivy"


def name_index() -> Path:
    """Where the package-name index lives: one sorted plain-text file per ecosystem
    and a `metadata.json` saying when each was built (ADR-0018). Mounted read-only
    into every container at `/cache/names`."""
    return root() / "names"


def name_index_present() -> bool:
    return (name_index() / "metadata.json").is_file()


def name_index_age_days() -> float | None:
    """Age of the OLDEST ecosystem in the index, or None when there is no index.

    The oldest, because the verdict is one verdict: a fresh PyPI list beside a
    six-week-old npm list is a six-week-old answer for any project with a
    `package.json`. Built time, not download time, for the same reason as the
    database (F6.11): a mirror can hand over old data this morning.
    """
    import json

    marker = name_index() / "metadata.json"
    if not marker.is_file():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        ecosystems = data.get("ecosystems") or {}
        if not isinstance(ecosystems, dict) or not ecosystems:
            return None
        ages = [stamp_age_days(entry.get("built_at")) for entry in ecosystems.values()]
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return None
    if any(age is None for age in ages):
        return None
    return max(ages)  # type: ignore[type-var]


def stamp_age_days(stamp: object) -> float | None:
    from datetime import UTC, datetime

    try:
        built = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if built.tzinfo is None:
        built = built.replace(tzinfo=UTC)
    return (datetime.now(UTC) - built).total_seconds() / 86400


def db_present() -> bool:
    return (trivy_db() / "db" / "trivy.db").is_file()


def db_age_days() -> float | None:
    """How old the DATA is, not how long ago it was downloaded (F6.11).

    Those differ, and the difference matters most to the users who need it most.
    An air-gapped mirror (F10.5) can hand over a six-month-old database this
    morning: the file's mtime would read as fresh while every advisory in it is
    half a year out of date. Trivy stamps the build time in `UpdatedAt`, so that is
    what we ask. mtime is the fallback for a database that carries no metadata.
    """
    marker = trivy_db() / "db" / "metadata.json"
    if not marker.is_file():
        return None
    stamped = _metadata_time(marker, "UpdatedAt")
    if stamped is not None:
        return stamped
    return (time.time() - marker.stat().st_mtime) / 86400


def db_overdue_days() -> float | None:
    """Days past the moment Trivy itself said the database should be replaced.

    Trivy's own opinion beats ours: `NextUpdate` is what the tool that built the
    data considers its shelf life.
    """
    marker = trivy_db() / "db" / "metadata.json"
    if not marker.is_file():
        return None
    return _metadata_time(marker, "NextUpdate")


def _metadata_time(marker: Path, field: str) -> float | None:
    """Days elapsed since a timestamp in Trivy's metadata, or None if unreadable.

    Unreadable is not zero. A corrupt or unexpected metadata file must not produce a
    confident "0 days old" — that is the failure this whole phase exists to remove.
    """
    import json
    from datetime import UTC, datetime

    try:
        raw = json.loads(marker.read_text(encoding="utf-8")).get(field)
        stamped = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return (datetime.now(UTC) - stamped).total_seconds() / 86400


# ------------------------------------------------------------- `valvur cache`
#
# What is cached, how old, how large, and `--clear` (task 23.3.5). The image is the
# runtime's to keep and is not here: `valvur doctor` says whether it is present.


@dataclass(frozen=True)
class Entry:
    name: str
    path: Path
    present: bool
    size: int
    age_days: float | None
    detail: str = ""


def inventory() -> list[Entry]:
    """The three things `valvur update` fetches, in the order it fetches them."""
    import json

    entries = [Entry("database", trivy_db(), db_present(), _tree_size(trivy_db()),
                     db_age_days())]

    names = name_index()
    detail = ""
    if name_index_present():
        try:
            ecosystems = json.loads((names / "metadata.json").read_text(encoding="utf-8"))
            ecosystems = ecosystems.get("ecosystems") or {}
        except (OSError, ValueError, AttributeError):
            ecosystems = {}
        detail = " · ".join(f"{eco} {int((entry or {}).get('count') or 0):,}"
                            for eco, entry in ecosystems.items())
    entries.append(Entry("index", names, name_index_present(), _tree_size(names),
                         name_index_age_days(), detail))

    kev = root() / "kev.json"
    present = kev.is_file()
    age = (time.time() - kev.stat().st_mtime) / 86400 if present else None
    entries.append(Entry("kev", kev, present, kev.stat().st_size if present else 0, age))
    return entries


def clear() -> list[str]:
    """Remove the cached data — never the directory, never the lock file — under the
    exclusive cache lock, so a scan reading the database finishes first (16.3).
    Returns what was removed."""
    import shutil

    from . import locking

    removed: list[str] = []
    with locking.held(locking.cache_lock(root()), exclusive=True, wait=True):
        for entry in inventory():
            if not entry.path.exists():
                continue
            if entry.path.is_dir():
                shutil.rmtree(entry.path)
            else:
                entry.path.unlink()
            removed.append(entry.name)
    return removed


# ------------------------------------------------------- `--prune` (task 28.3.7)
#
# Two things nothing removed: the published image's local tags from shims that
# are gone — each shim version pulls its own tag, and `:0.2.0` stayed when
# `:0.3.0` arrived — and files under the name index that its metadata no longer
# names. A flag, never a default; each item is listed before it goes; this shim's
# own image, the database and every named index file are never candidates.


class LocalImages(Protocol):
    """What the runtime holds for one repository, and how to drop one reference."""

    def list(self, repository: str) -> list[str]: ...
    def remove(self, reference: str) -> None: ...


class RuntimeImages:
    """The container runtime's image store, by its command line."""

    def __init__(self, runtime: str):
        self.runtime = runtime

    def list(self, repository: str) -> list[str]:
        import subprocess

        proc = subprocess.run(  # noqa: S603 — the runtime found by detect_runtime
            [self.runtime, "image", "ls", repository, "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode != 0:
            return []
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    def remove(self, reference: str) -> None:
        import subprocess

        subprocess.run([self.runtime, "image", "rm", reference],  # noqa: S603
                       capture_output=True, text=True, timeout=120, check=True)


def local_images(runtime: str) -> LocalImages:
    return RuntimeImages(runtime)


def superseded_images(images: LocalImages, *, keep: str | None = None) -> list[str]:
    """The published image's local tags that are not this shim's, sorted. `<none>`
    is a dangling layer the runtime owns, not a tag valvur pulled."""
    current = f"{IMAGE_REPOSITORY}:{keep or __version__}"
    return sorted(
        ref for ref in images.list(IMAGE_REPOSITORY)
        if ref != current and not ref.endswith(":<none>")
    )


def stray_index_files() -> list[Path]:
    """Files under the name index that neither `metadata.json` nor the index's
    own file table names: a retired ecosystem's list, a download that never
    finished. The named files are what a scan reads and are never here."""
    import json

    # `ecosystems.INDEX_FILES` is what `name_index.FILES` is built from; read here
    # rather than through `name_index`, which would put this module in the
    # import component the cycle ratchet holds closed.
    files = _ecosystems.INDEX_FILES
    names = name_index()
    if not names.is_dir():
        return []
    try:
        metadata = json.loads((names / "metadata.json").read_text(encoding="utf-8"))
        ecosystems = metadata.get("ecosystems") or {}
    except (OSError, ValueError, AttributeError):
        ecosystems = {}
    named = {"metadata.json"} | {files[eco] for eco in ecosystems if eco in files}
    return sorted(p for p in names.iterdir() if p.is_file() and p.name not in named)


def prune(images: LocalImages | None) -> tuple[list[str], list[str]]:
    """Remove the superseded images and the stray index files, under the exclusive
    cache lock like `clear`. Returns (images removed, files removed). `images`
    is None where no runtime was found: the files are still pruned."""
    from . import locking

    removed_images: list[str] = []
    removed_files: list[str] = []
    with locking.held(locking.cache_lock(root()), exclusive=True, wait=True):
        for reference in superseded_images(images) if images is not None else []:
            images.remove(reference)  # type: ignore[union-attr]
            removed_images.append(reference)
        for path in stray_index_files():
            path.unlink()
            removed_files.append(str(path))
    return removed_images, removed_files


def _tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    if not path.is_dir():
        return 0
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def human_size(size: int) -> str:
    """`1.35 GB`, `3.0 MB`, `900 B` — decimal, as the download sizes elsewhere are."""
    if size >= 1_000_000_000:
        return f"{size / 1_000_000_000:.2f} GB"
    if size >= 1_000_000:
        return f"{size / 1_000_000:.1f} MB"
    if size >= 1_000:
        return f"{size / 1_000:.0f} kB"
    return f"{size} B"
