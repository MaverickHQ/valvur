"""Every scheduled workflow, judged daily (R42.5, D81s, N3.8).

    python3 scripts/watchdog.py --repo MaverickHQ/valvur [--dry-run]

`refresh.yml` failed on 2026-10-12 and 2026-10-19 and filed no issue: its checkout ran
only on a month's first Monday, so its own `file-issue` step could not be found. This
reads every workflow under `.github/workflows/` that has a `schedule:`, and each one's
scheduled runs on `main` from the Actions API. A workflow is

- **failed** when its last completed scheduled run concluded `failure`, `timed_out` or
  `startup_failure`;
- **overdue** when no scheduled run started within its longest gap between two cron
  times plus `MARGIN_HOURS`.

Each workflow has one issue, titled `watchdog: <file>`, kept as `file-issue` keeps its
own: the first finding opens it, a later one comments on it, and a pass closes it,
naming the run. A workflow with no `schedule:` is never read. The token is `GH_TOKEN`
or `GITHUB_TOKEN`. Exit 0 when the watch ran, whatever it found; 2 when the API could
not be read. Standard library only, and no YAML parser: the crons are read line by line.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
#: Twice the longest start delay measured over the last runs of every scheduled
#: workflow, 9.0 hours (`corpus.yml`, 2026-10-24), and never under 12 (D81s).
MARGIN_HOURS = 18
FAILED = ("failure", "timed_out", "startup_failure")
TITLE = "watchdog: {}"

_CRON = re.compile(r"""^\s+- cron:\s*["']([^"']+)["']""")


def schedules(directory: Path) -> dict[str, list[str]]:
    """Each workflow file with a `schedule:` trigger, and its crons."""
    found: dict[str, list[str]] = {}
    for path in sorted(directory.glob("*.yml")):
        crons, inside = [], False
        for line in path.read_text().splitlines():
            if re.match(r"^  schedule:\s*$", line):
                inside = True
            elif inside and (cron := _CRON.match(line)):
                crons.append(cron.group(1).strip())
            elif inside and line.strip() and not line.lstrip().startswith("#"):
                inside = False
        if crons:
            found[path.name] = crons
    return found


def _field(spec: str, low: int, high: int) -> set[int]:
    values: set[int] = set()
    for part in spec.split(","):
        body, _, step = part.partition("/")
        if body == "*":
            start, end = low, high
        elif "-" in body:
            start, end = (int(v) for v in body.split("-"))
        else:
            start = end = int(body)
        values.update(range(start, end + 1, int(step or 1)))
    return values


def _parsed(cron: str) -> tuple[set[int], ...]:
    minute, hour, day, month, weekday = cron.split()
    return (_field(minute, 0, 59), _field(hour, 0, 23), _field(day, 1, 31),
            _field(month, 1, 12), {d % 7 for d in _field(weekday, 0, 7)})


def _matches(fields: tuple[set[int], ...], at: datetime) -> bool:
    minutes, hours, days, months, weekdays = fields
    return (at.minute in minutes and at.hour in hours and at.day in days
            and at.month in months and at.isoweekday() % 7 in weekdays)


def longest_gap_hours(crons: list[str]) -> float:
    """The longest time between two consecutive cron times, over five weeks."""
    parsed = [_parsed(cron) for cron in crons]
    at = datetime(2026, 1, 5, tzinfo=UTC)
    times = []
    for _ in range(35 * 24 * 60):
        if any(_matches(fields, at) for fields in parsed):
            times.append(at)
        at += timedelta(minutes=1)
    gaps = [(b - a).total_seconds() / 3600 for a, b in itertools.pairwise(times)]
    return max(gaps)


def _when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def judge(crons: list[str], runs: list[dict], now: datetime) -> tuple[str, str] | None:
    """('finding', what) for a failed or overdue workflow, ('passed', run URL) for one
    whose last completed run passed, None when there is nothing to say yet."""
    allowed = timedelta(hours=longest_gap_hours(crons) + MARGIN_HOURS)
    starts = [_when(r.get("run_started_at") or r["created_at"]) for r in runs]
    if not starts or now - max(starts) > allowed:
        last = f"the last started {max(starts):%Y-%m-%d %H:%M} UTC" if starts else "none has run"
        return ("finding", f"overdue: no scheduled run started within "
                           f"{allowed.total_seconds() / 3600:g} hours ({last})")
    completed = [r for r in runs if r.get("status") == "completed"]
    if not completed:
        return None
    run = completed[0]
    if run.get("conclusion") in FAILED:
        return ("finding", f"the scheduled run of {run['created_at'][:10]} concluded "
                           f"{run['conclusion']}: {run['html_url']}")
    if run.get("conclusion") == "success":
        return ("passed", run["html_url"])
    return None


class GitHub:
    def __init__(self, api: str, repo: str, token: str | None):
        self.base, self.token = f"{api.rstrip('/')}/repos/{repo}", token
        # An opener rather than `urlopen`: the same request for every method.
        self._opener = urllib.request.build_opener()

    def call(self, method: str, path: str, body: dict | None = None) -> Any:
        request = urllib.request.Request(  # noqa: S310 - the API's own https URL
            self.base + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        with self._opener.open(request, timeout=30) as answer:
            return json.load(answer)


def _runs(github: GitHub, name: str) -> list[dict]:
    """The workflow's scheduled runs on `main`, newest first. A workflow the API does
    not know yet, answered 404, has never run."""
    try:
        answer = github.call("GET", f"/actions/workflows/{name}/runs"
                                    "?event=schedule&branch=main&per_page=30")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return []
        raise
    return answer["workflow_runs"]


def watch(github: GitHub, directory: Path, now: datetime, *, dry_run: bool,
          only: str | None = None) -> list[str]:
    """What the watch did, or would do, one line each."""
    issues = github.call("GET", "/issues?state=open&per_page=100")
    open_by_title = {i["title"]: i["number"] for i in issues
                     if "pull_request" not in i}
    done = []
    for name, crons in schedules(directory).items():
        if only is not None and name != only:
            continue
        verdict = judge(crons, _runs(github, name), now)
        title, number = TITLE.format(name), open_by_title.get(TITLE.format(name))
        if verdict is None:
            continue
        kind, what = verdict
        if kind == "passed":
            if number is None:
                continue
            done.append(f"would close: {title}" if dry_run else f"closed: {title}")
            if not dry_run:
                github.call("POST", f"/issues/{number}/comments",
                            {"body": f"The next scheduled run passed: {what}"})
                github.call("PATCH", f"/issues/{number}", {"state": "closed"})
            continue
        body = (f"`{name}`: {what}\n\nSeen by the watchdog on {now:%Y-%m-%d %H:%M} UTC. "
                "Read the run, fix the cause, and dispatch the workflow again; the next "
                "scheduled run that passes closes this issue.")
        if number is None:
            done.append(f"would open: {title}" if dry_run else f"opened: {title}")
            if not dry_run:
                github.call("POST", "/issues", {"title": title, "body": body})
        else:
            done.append(f"would comment: {title}" if dry_run else f"commented: {title}")
            if not dry_run:
                github.call("POST", f"/issues/{number}/comments", {"body": body})
    return done


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--api", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--workflows", type=Path, default=REPO / ".github" / "workflows")
    parser.add_argument("--now", help="ISO 8601; the clock by default")
    parser.add_argument("--dry-run", action="store_true", help="list, and file nothing")
    parser.add_argument("--only", help="judge this workflow file alone, as the nightly "
                                       "judges watchdog.yml")
    args = parser.parse_args(argv)
    now = _when(args.now) if args.now else datetime.now(UTC)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        done = watch(GitHub(args.api, args.repo, token), args.workflows, now,
                     dry_run=args.dry_run, only=args.only)
    except (urllib.error.URLError, ValueError, KeyError, TypeError) as error:
        print(f"watchdog: cannot read the Actions API or the issues: {error}")
        return 2
    print("\n".join(done) if done else "every scheduled workflow is running and passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
