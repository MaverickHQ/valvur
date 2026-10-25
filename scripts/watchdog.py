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

With `--scanners`, it also watches what Dependabot cannot (D81d): an Opengrep release
newer than the image's pin and past the 7-day cooldown keeps one issue,
`watchdog: Opengrep <version>`, closed once the pin moves to it. With `--toolchains`, each
Scanner with no release in `LIVENESS_DAYS`, or whose binary in the image was built with a
Go that Go no longer supports (go.dev's list), keeps one issue, `watchdog: <Scanner>
liveness`, commented on when its reasons change and closed when none holds.
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
sys.path.insert(0, str(REPO / "scripts"))
import scanner_pins  # noqa: E402 - beside this script, standard library alone

#: Twice the longest start delay measured over the last runs of every scheduled
#: workflow, 9.0 hours (`corpus.yml`, 2026-10-24), and never under 12 (D81s).
MARGIN_HOURS = 18
FAILED = ("failure", "timed_out", "startup_failure")
TITLE = "watchdog: {}"
#: Dependabot's cooldown (D81d): a release is taken once it is this old.
COOLDOWN_DAYS = 7
OPENGREP = "watchdog: Opengrep "
#: A Scanner with no release in this long may have stopped (D81s).
LIVENESS_DAYS = 180
LIVENESS = "watchdog: {} liveness"
#: Each Scanner by its project's name, and where it publishes its releases.
UPSTREAM = {"gitleaks": ("Gitleaks", "gitleaks/gitleaks"),
            "trivy": ("Trivy", "aquasecurity/trivy"),
            "osv-scanner": ("OSV-Scanner", "google/osv-scanner"),
            "syft": ("Syft", "anchore/syft"),
            "opengrep": ("Opengrep", "opengrep/opengrep"),
            "zizmor": ("zizmor", "zizmorcore/zizmor"),
            "checkov": ("Checkov", "bridgecrewio/checkov")}
GO_RELEASES = "https://go.dev/dl/?mode=json"

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
        self.api, self.token = api.rstrip("/"), token
        self.base = f"{self.api}/repos/{repo}"
        # An opener rather than `urlopen`: the same request for every method.
        self._opener = urllib.request.build_opener()

    def call(self, method: str, path: str, body: dict | None = None) -> Any:
        """The repository's own API: `path` under `/repos/<repo>`."""
        return self.call_api(method, self.base.removeprefix(self.api) + path, body)

    def call_api(self, method: str, path: str, body: dict | None = None) -> Any:
        """Anywhere under the API, as an upstream repository's releases are."""
        request = urllib.request.Request(  # noqa: S310 - the API's own https URL
            self.api + path, method=method,
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


def _version(tag: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", tag)[:3])


def releases(github: GitHub, upstream: str) -> list[dict]:
    """The upstream repository's published releases, newest first."""
    answer = github.call_api("GET", f"/repos/{upstream}/releases?per_page=30")
    return [r for r in answer if not r.get("draft") and not r.get("prerelease")]


def taken(found: list[dict], pin: str, now: datetime) -> dict | None:
    """The newest release past the cooldown, when it is newer than the pin."""
    ready = [r for r in found
             if now - _when(r["published_at"]) >= timedelta(days=COOLDOWN_DAYS)]
    newest = max(ready, key=lambda r: _version(r["tag_name"]), default=None)
    return newest if newest and _version(newest["tag_name"]) > _version(pin) else None


def supported_go(github: GitHub, url: str) -> list[str]:
    """The Go minors Go supports, `go1.27` and the like, from go.dev's list."""
    with github._opener.open(url, timeout=30) as answer:
        listed = json.load(answer)
    return sorted({".".join(r["version"].split(".")[:2]) for r in listed if r.get("stable")},
                  key=_version)


def stopped(found: list[dict], go: str | None, supported: list[str] | None,
            now: datetime) -> list[str]:
    """Why a Scanner may have stopped: its last release's age, its binary's Go."""
    reasons = []
    newest = max((_when(r["published_at"]) for r in found), default=None)
    if newest is None or now - newest > timedelta(days=LIVENESS_DAYS):
        age = f"{(now - newest).days} days" if newest else "ever"
        reasons.append(f"no release in {age}, past the {LIVENESS_DAYS} days allowed")
    if go and supported and ".".join(go.split(".")[:2]) not in supported:
        reasons.append(f"its binary in the image was built with {go}, and Go supports only "
                       f"{' and '.join(supported)}")
    return reasons


def watch_liveness(github: GitHub, open_: dict[str, int], now: datetime, *, dry_run: bool,
                   toolchains: dict[str, str | None], supported: list[str] | None) -> list[str]:
    """One issue per Scanner that may have stopped, kept while a reason holds."""
    done = []
    for tool, (name, upstream) in UPSTREAM.items():
        title = LIVENESS.format(name)
        reasons = stopped(releases(github, upstream), toolchains.get(tool), supported, now)
        number = open_.get(title)
        if not reasons:
            if number is not None:
                done.append(f"would close: {title}" if dry_run else f"closed: {title}")
                if not dry_run:
                    github.call("POST", f"/issues/{number}/comments",
                                {"body": "Neither holds now: it has released, and its Go is "
                                         "supported."})
                    github.call("PATCH", f"/issues/{number}", {"state": "closed"})
            continue
        text = (f"{name} ({upstream}) may have stopped: " + "; ".join(reasons) + ". "
                "A Scanner that no longer releases, or that ships on an unsupported Go, "
                "carries advisories nothing will fix. Rebuild it from source with a current "
                "Go, or weigh replacing it.")
        if number is None:
            done.append(f"would open: {title}" if dry_run else f"opened: {title}")
            if not dry_run:
                github.call("POST", "/issues", {"title": title, "body": text})
            continue
        last = _last_said(github, number)
        if last != text:
            done.append(f"would comment: {title}" if dry_run else f"commented: {title}")
            if not dry_run:
                github.call("POST", f"/issues/{number}/comments", {"body": text})
    return done


def _last_said(github: GitHub, number: int) -> str:
    comments = github.call("GET", f"/issues/{number}/comments?per_page=100")
    if comments:
        return str(comments[-1].get("body", ""))
    return str(github.call("GET", f"/issues/{number}").get("body", ""))


def watch_scanners(github: GitHub, root: Path, now: datetime, *, dry_run: bool,
                   toolchains: dict[str, str | None] | None = None,
                   go_releases: str | None = None) -> list[str]:
    """Opengrep's releases against its pin, one issue kept for the one to take; then
    each Scanner's liveness."""
    issues = github.call("GET", "/issues?state=open&per_page=100")
    open_ = {i["title"]: i["number"] for i in issues if "pull_request" not in i}
    pin = scanner_pins.pins(scanner_pins.in_tree(root))["opengrep"]
    release = taken(releases(github, "opengrep/opengrep"), pin, now)
    done = []
    wanted = None if release is None else OPENGREP + release["tag_name"].lstrip("v")
    for title, number in open_.items():
        if title.startswith(OPENGREP) and title != wanted:
            done.append(f"would close: {title}" if dry_run else f"closed: {title}")
            if not dry_run:
                github.call("POST", f"/issues/{number}/comments",
                            {"body": f"Superseded by `{wanted.removeprefix('watchdog: ')}`."
                                     if wanted else f"The image pins Opengrep {pin} now."})
                github.call("PATCH", f"/issues/{number}", {"state": "closed"})
    if release is not None and wanted is not None and wanted not in open_:
        done.append(f"would open: {wanted}" if dry_run else f"opened: {wanted}")
        if not dry_run:
            github.call("POST", "/issues", {"title": wanted, "body": (
                f"Opengrep {release['tag_name'].lstrip('v')} ({release['html_url']}), "
                f"published {release['published_at'][:10]}, is past the {COOLDOWN_DAYS}-day "
                f"cooldown, and the image pins {pin}. Dependabot does not follow Opengrep: "
                "the image takes it from a release URL. Move `OPENGREP_URL` and its two "
                "sha256 `ARG`s together, check the signatures with "
                "`scripts/verify-opengrep.sh`, then run `scripts/scanner_upgrade.py "
                f"opengrep {pin} {release['tag_name'].lstrip('v')} --recapture` "
                "(`docs/MAINTENANCE.md`). This issue closes once the pin moves.")})
    if toolchains is None:
        return done
    supported = supported_go(github, go_releases) if go_releases else None
    return done + watch_liveness(github, open_, now, dry_run=dry_run,
                                 toolchains=toolchains, supported=supported)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--api", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--workflows", type=Path, default=REPO / ".github" / "workflows")
    parser.add_argument("--now", help="ISO 8601; the clock by default")
    parser.add_argument("--dry-run", action="store_true", help="list, and file nothing")
    parser.add_argument("--only", help="judge this workflow file alone, as the nightly "
                                       "judges watchdog.yml")
    parser.add_argument("--scanners", action="store_true",
                        help="also watch the Scanners Dependabot cannot follow")
    parser.add_argument("--root", type=Path, default=REPO,
                        help="the tree whose pins are read (default: this one)")
    parser.add_argument("--toolchains", type=Path, metavar="FILE",
                        help="JSON: each Scanner's binary's Go, as the image ships it")
    parser.add_argument("--go-releases", default=GO_RELEASES,
                        help="go.dev's list of supported releases")
    args = parser.parse_args(argv)
    now = _when(args.now) if args.now else datetime.now(UTC)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        github = GitHub(args.api, args.repo, token)
        done = watch(github, args.workflows, now, dry_run=args.dry_run, only=args.only)
        if args.scanners and args.only is None:
            toolchains = (json.loads(args.toolchains.read_text())
                          if args.toolchains else None)
            done += watch_scanners(github, args.root, now, dry_run=args.dry_run,
                                   toolchains=toolchains,
                                   go_releases=args.go_releases if toolchains else None)
    except (urllib.error.URLError, ValueError, KeyError, TypeError) as error:
        print(f"watchdog: cannot read the Actions API or the issues: {error}")
        return 2
    print("\n".join(done) if done else "every scheduled workflow is running and passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
