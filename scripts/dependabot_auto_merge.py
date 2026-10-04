"""Whether a Dependabot pull request may land itself (R28.2, D64a).

    gh pr view <url> --json files,commits | python3 scripts/dependabot_auto_merge.py

Exit 0 when it may: every file it changes is a dependency file, and every commit carries
Dependabot's `update-type`, none of them a major version. Exit 1 when it is left for the
owner, saying why; exit 2 when the input cannot be read. Standard library only: the
workflow runs this from the base branch, never from the pull request's own code.

The files were read from Dependabot's pull requests on 2026-10-04. #200 changed
`requirements-checkov.in` beside its lock, and earlier ones that had code added to them
touched `src/` and `tests/`, which only the owner lands. Workflow files are left out
too: a merge made with the workflow's own token cannot change them, so an Actions update
would sit with auto-merge enabled and never merge.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from typing import TextIO

#: The dependency files Dependabot's updates may change, and nothing else.
ALLOWED = ("uv.lock", "requirements-*.in", "requirements-*.txt", "Dockerfile",
           ".clusterfuzzlite/Dockerfile")
_UPDATE_TYPE = re.compile(r"^\s*update-type:\s*(\S+)\s*$", re.M)
MAJOR = "version-update:semver-major"


def _allowed(path: str) -> bool:
    # fnmatch's `*` crosses `/`, so a pattern without a slash must match a root file.
    return any(fnmatch.fnmatch(path, pattern) and path.count("/") == pattern.count("/")
               for pattern in ALLOWED)


def decide(view: dict) -> tuple[bool, str]:
    """(eligible, why) for `gh pr view --json files,commits`."""
    files = [f.get("path", "") for f in view.get("files") or []]
    commits = view.get("commits") or []
    if not files or not commits:
        return False, "nothing to judge: no files or no commits"
    others = [path for path in files if not _allowed(path)]
    if others:
        return False, f"changes files that are not dependency files: {', '.join(others)}"
    for commit in commits:
        kinds = _UPDATE_TYPE.findall(commit.get("messageBody") or "")
        headline = commit.get("messageHeadline", "")
        if not kinds:
            return False, f"a commit carries no Dependabot update-type: {headline!r}"
        if MAJOR in kinds:
            return False, f"a major version update: {headline!r}"
    return True, f"eligible: {len(files)} dependency file(s), no major version"


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None) -> int:
    try:
        view = json.load(stdin or sys.stdin)
    except ValueError as error:
        print(f"cannot read the pull request: {error}")
        return 2
    eligible, why = decide(view)
    print(why)
    return 0 if eligible else 1


if __name__ == "__main__":
    sys.exit(main())
