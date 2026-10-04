"""Read CI's verdict on a commit, for the release's `verify` job (D62b, R26.3).

    python3 scripts/ci_verdict.py <sha>     # GITHUB_TOKEN and GITHUB_REPOSITORY from the runner

Every check `main`'s protection requires has already run on a commit that landed. So
the tag's run reads their results back instead of rerunning them: `verdict=passed`
when each one's newest completed run succeeded, and `verdict=failed`, exit 1, naming
each that did not. Standard library alone, so it runs before any install.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from collections.abc import Callable

#: The checks `main`'s branch protection requires, read from it on 2026-10-03 (R24.1).
#: `tests/test_ci_builds_once.py` holds `ci.yml` to these names.
REQUIRED = (
    "no scan output in tree",
    "lint, types, tests",
    "end-to-end (real container)",
    "self-scan release gate (N2.5)",
    "the published image, on amd64",
    "the published image, on arm64",
    "the tests on Python 3.11",
    "the tests on Python 3.13",
)


def fetch(sha: str) -> list[dict]:
    """Every check run on `sha`, through the REST API, every page."""
    repository = os.environ["GITHUB_REPOSITORY"]
    runs: list[dict] = []
    for page in range(1, 11):
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/commits/{sha}/check-runs"
            f"?per_page=100&page={page}",
            headers={"Accept": "application/vnd.github+json",
                     "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                     "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=30) as reply:  # noqa: S310 — a fixed https URL
            body = json.load(reply)
        runs += body["check_runs"]
        if len(runs) >= body["total_count"] or not body["check_runs"]:
            break
    return runs


def judge(runs: list[dict]) -> dict[str, str]:
    """Each required check's conclusion: its newest completed run's."""
    verdicts = {}
    for name in REQUIRED:
        done = [r for r in runs if r["name"] == name and r["status"] == "completed"]
        newest = max(done, key=lambda r: r["completed_at"] or "", default=None)
        verdicts[name] = newest["conclusion"] if newest else "missing"
    return verdicts


def _output(**values: str) -> None:
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as out:
            out.writelines(f"{key}={value}\n" for key, value in values.items())


def main(argv: list[str] | None = None, *,
         fetch: Callable[[str], list[dict]] = fetch) -> int:
    [sha] = argv if argv is not None else sys.argv[1:]
    verdicts = judge(fetch(sha))
    failed = {name: v for name, v in verdicts.items() if v != "success"}
    if failed:
        for name, verdict in failed.items():
            print(f"::error::{name}: {verdict}")
        _output(verdict="failed")
        return 1
    print(f"all {len(REQUIRED)} required checks passed on {sha[:12]}")
    _output(verdict="passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
