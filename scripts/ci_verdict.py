"""Read CI's verdict on a commit, for the release's `verify` job (D62b, R26.3).

    python3 scripts/ci_verdict.py <sha> [--wait 1800]   # GITHUB_TOKEN, GITHUB_REPOSITORY

Every check `main`'s protection requires has already run on a commit that landed. So
the tag's run reads their results back instead of rerunning them: `verdict=passed`
when each one's newest completed run succeeded, and `verdict=failed`, exit 1, naming
each that did not. A check it cannot judge makes the verdict `unreadable` (D62's
fallback): one with no completed run here, or skipped, or the API not answering. The
job then reruns `verify.sh` and the e2e suite itself, as before R26, and says so. A
run still in progress, as the push to `main` starts one, is waited for up to `--wait`
seconds. Standard library alone, so it runs before any install.
"""

from __future__ import annotations

import argparse
import json
import os
import time
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


#: Conclusions that say nothing about the commit: the check did not look.
_SILENT = {"skipped", "neutral", "stale", "missing"}
#: Seconds between two reads while a required check is still running.
POLL_S = 30


def judge(runs: list[dict]) -> dict[str, str]:
    """Each required check's conclusion: its newest completed run's, `pending` while
    one is running, or `missing`."""
    verdicts = {}
    for name in REQUIRED:
        mine = [r for r in runs if r["name"] == name]
        if any(r["status"] != "completed" for r in mine):
            verdicts[name] = "pending"
            continue
        newest = max(mine, key=lambda r: r["completed_at"] or "", default=None)
        verdicts[name] = (newest["conclusion"] or "missing") if newest else "missing"
    return verdicts


def _output(**values: str) -> None:
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as out:
            out.writelines(f"{key}={value}\n" for key, value in values.items())


def main(argv: list[str] | None = None, *,
         fetch: Callable[[str], list[dict]] = fetch,
         sleep: Callable[[float], object] = time.sleep) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sha")
    parser.add_argument("--wait", type=int, default=1800,
                        help="seconds to wait for a required check still running")
    args = parser.parse_args(argv)
    waited = 0
    while True:
        try:
            verdicts = judge(fetch(args.sha))
        except (OSError, ValueError, KeyError) as error:
            print(f"::warning::the check runs could not be read: {error}")
            return _unreadable()
        if "pending" not in verdicts.values() or waited >= args.wait:
            break
        sleep(POLL_S)
        waited += POLL_S
    failed = {n: v for n, v in verdicts.items() if v not in _SILENT | {"success", "pending"}}
    if failed:
        for name, verdict in failed.items():
            print(f"::error::{name}: {verdict}")
        _output(verdict="failed")
        return 1
    unjudged = {n: v for n, v in verdicts.items() if v != "success"}
    if unjudged:
        for name, verdict in unjudged.items():
            print(f"::warning::{name}: {verdict}")
        return _unreadable()
    print(f"all {len(REQUIRED)} required checks passed on {args.sha[:12]}")
    _output(verdict="passed")
    return 0


def _unreadable() -> int:
    print("CI's verdict cannot be read; rerunning verify.sh and the e2e suite here")
    _output(verdict="unreadable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
