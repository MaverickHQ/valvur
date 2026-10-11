"""Track 9's real cases (R41, D80): the vulnerable code of published advisories in LLM
frameworks, beside the fixed code where a clean fix exists.

valvur writes its own twins for the track, so the twins alone would let it set its own
exam. These are code others shipped and others reported: each pinned by commit in
`tests/eval/sources.toml`, under a licence that allows it, and fetched into the build
cache, never vendored. Only the files that hold the flow are fetched, by one shallow,
blob-filtered fetch of the pinned commit, so a case costs its files and not a history.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = REPO / "tests" / "eval" / "sources.toml"
KEY = "llm-output-real"
#: Licences a case may be under: permissive, so its files may sit in the build cache.
LICENCES = frozenset({"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"})
KINDS = (("vulnerable", "commit"), ("fixed", "fixed"))


def entries() -> dict[str, dict]:
    return dict(tomllib.loads(SOURCES.read_text(encoding="utf-8")).get(KEY, {}))


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,  # noqa: S603
                          check=False)


def _files(url: str, commit: str, paths: list[str], clone: Path) -> dict[str, bytes]:
    """`paths` at `commit`, from a shallow, blob-filtered fetch of that one commit."""
    if not (clone / ".git").is_dir():
        clone.mkdir(parents=True, exist_ok=True)
        _git(clone, "init", "-q")
        _git(clone, "remote", "add", "origin", url)
    done = _git(clone, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit)
    if done.returncode != 0:
        raise RuntimeError(f"could not fetch {commit} from {url}: "
                           f"{done.stderr.decode(errors='replace').strip()}")
    found = {}
    for path in paths:
        shown = _git(clone, "show", f"{commit}:{path}")
        if shown.returncode != 0:
            raise RuntimeError(f"{url} has no {path} at {commit}")
        found[path] = shown.stdout
    return found


def fetch(dest: Path, chosen: dict[str, dict] | None = None) -> Path:
    """Each case's files at its commits, into `dest/<name>/<vulnerable|fixed>/`; a case
    already at its pin is left as it is."""
    for name, entry in (entries() if chosen is None else chosen).items():
        clone = dest / ".repos" / re.sub(r"[^\w.-]+", "_", entry["url"])
        for kind, field in KINDS:
            commit = entry.get(field)
            if not commit:
                continue
            target, stamp = dest / name / kind, dest / name / f".{kind}.pin"
            if stamp.is_file() and stamp.read_text().strip() == commit and target.is_dir():
                continue
            for path, data in _files(entry["url"], commit, entry["files"], clone).items():
                (target / path).parent.mkdir(parents=True, exist_ok=True)
                (target / path).write_bytes(data)
            stamp.write_text(commit + "\n")
    return dest
