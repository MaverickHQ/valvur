"""What the heal reads of PyPI (R44.2, D81e): a project's releases, and who published a file.

Two endpoints of pypi.org, which `src/valvur/egress.py` already names:

- `/pypi/<project>/json`: every version's files, each with its upload time and whether it
  was yanked;
- `/integrity/<project>/<version>/<file>/provenance`: the attestation on one file, and the
  Trusted Publisher that made it (PEP 740). 404 for a file with none.

Read with the standard library, nothing sent but the public names. What comes back is data:
no file is downloaded and no package's code runs.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

PYPI = "https://pypi.org"
#: A final release: `1.2.3`, or a post-release of one. Pre-releases and development
#: versions are never offered to the heal.
_FINAL = re.compile(r"\d+(?:\.\d+)*(?:\.post\d+)?")


class Unreadable(Exception):
    """PyPI did not answer, or answered something that is not what its API documents."""


@dataclass(frozen=True)
class Release:
    version: str
    #: When its first file was uploaded, `YYYY-MM-DDTHH:MM:SSZ`.
    uploaded: str
    files: tuple[str, ...]


def _get(url: str) -> object | None:
    """The JSON at `url`; None for a 404."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310 — pypi.org, https
            return json.loads(answer.read())
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise Unreadable(f"{url}: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise Unreadable(f"{url}: {error}") from error


def _stamp(text: str) -> str:
    """PyPI's `2026-10-11T08:09:10.123456Z` as `2026-10-11T08:09:10Z`."""
    return text.split(".")[0].rstrip("Z") + "Z"


def releases(project: str) -> list[Release]:
    """The project's final releases that have a file and are not yanked."""
    answer = _get(f"{PYPI}/pypi/{project}/json")
    if not isinstance(answer, dict) or not isinstance(answer.get("releases"), dict):
        raise Unreadable(f"{project}: PyPI lists no releases")
    found = []
    for version, files in answer["releases"].items():
        kept = [f for f in files if isinstance(f, dict) and not f.get("yanked")]
        if not kept or not _FINAL.fullmatch(version):
            continue
        found.append(Release(version=version,
                             uploaded=min(_stamp(f["upload_time_iso_8601"]) for f in kept),
                             files=tuple(sorted(f["filename"] for f in kept))))
    return found


def publisher(project: str, release: Release) -> dict[str, str] | None:
    """The one Trusted Publisher whose attestation every file of `release` carries, as its
    `kind`, `repository` and `workflow`. None when a file has no attestation, or when the
    files do not all name the same publisher."""
    seen: set[tuple[str, str, str]] = set()
    for filename in release.files:
        answer = _get(f"{PYPI}/integrity/{project}/{release.version}/{filename}/provenance")
        bundles = answer.get("attestation_bundles") if isinstance(answer, dict) else None
        if not bundles:
            return None
        for bundle in bundles:
            who = bundle.get("publisher") or {}
            seen.add((str(who.get("kind", "")), str(who.get("repository", "")),
                      str(who.get("workflow", ""))))
    if len(seen) != 1:
        return None
    kind, repository, workflow = next(iter(seen))
    return {"kind": kind, "repository": repository, "workflow": workflow}
