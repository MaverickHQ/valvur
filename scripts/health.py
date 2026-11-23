#!/usr/bin/env python3
"""The Health record: one issue, rewritten daily from recorded runs (R52.5, D82r, Req. 14.4).

    python3 scripts/health.py --repo MaverickHQ/valvur [--dry-run]

Four things an adopter asks, each read from a run GitHub recorded and none computed here:

- **the Score by track,** from the newest `eval-report` artifact of a run on `main`;
- **the published image's verdict by day,** from each `image-gate-published` artifact the
  nightly left, kept for 30 days;
- **the mutation score,** from the newest `mutation-report` artifact;
- **time to heal,** from `scripts/heal_report.py`, which reads pull requests and releases.

It writes them into the one issue titled *valvur health* that a workflow's own account
opened, and rewrites that issue each day. It commits nothing. An issue of that title opened
by anyone else is neither read nor written: the repository is public, and the record reads
its own last values back from the issue.

**A number that cannot be read keeps its last value and the day it was read, and says so.**
The last values are in the issue itself, in a comment at its end. A number never read is
said to be absent. Standard library alone. Exit 0 when the record was written, 2 when the
issue could not be read or written.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import watchdog

TITLE = "valvur health"
#: A workflow's own token writes as this account, and no other issue is the record.
ACCOUNT = "github-actions[bot]"
IMAGE_DAYS = 30
_STATE = re.compile(r"<!-- valvur-health-state\n(.*?)\n-->", re.S)
_READ_ERRORS = (urllib.error.URLError, OSError, ValueError, KeyError, TypeError,
                zipfile.BadZipFile)


class _NoTokenToStorage(urllib.request.HTTPRedirectHandler):
    """GitHub answers a download with a redirect to its storage, which holds its own
    signature in the address and refuses a request that carries a token as well."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


def _files(github: watchdog.GitHub, artifact: dict) -> dict[str, bytes]:
    """The files of one artifact, by name."""
    request = urllib.request.Request(  # noqa: S310 - the API's own URL
        f"{github.base}/actions/artifacts/{artifact['id']}/zip",
        headers={"Accept": "application/vnd.github+json",
                 **({"Authorization": f"Bearer {github.token}"} if github.token else {})})
    opener = urllib.request.build_opener(_NoTokenToStorage())
    with opener.open(request, timeout=60) as answer:
        archive = zipfile.ZipFile(io.BytesIO(answer.read()))
    return {Path(name).name: archive.read(name) for name in archive.namelist()}


def _artifacts(github: watchdog.GitHub, name: str) -> list[dict]:
    """The artifacts of that name from runs on `main`, unexpired, newest first."""
    listed = github.call("GET", f"/actions/artifacts?name={name}&per_page=100")["artifacts"]
    return sorted((a for a in listed if not a.get("expired")
                   and (a.get("workflow_run") or {}).get("head_branch") == "main"),
                  key=lambda a: str(a["created_at"]), reverse=True)


def read_score(github: watchdog.GitHub) -> dict | None:
    found = _artifacts(github, "eval-report")
    if not found:
        return None
    report = json.loads(_files(github, found[0])["score.json"])
    tracks = {str(name): float(track["score"] if isinstance(track, dict) else track)
              for name, track in sorted(report["tracks"].items())}
    return {"date": str(found[0]["created_at"])[:10], "score": float(report["score"]),
            "tracks": tracks}


def read_image(github: watchdog.GitHub, known: dict[str, dict], since: str
               ) -> dict[str, dict]:
    """Each day's verdict from `since` on, as counts. A day already in the record is not
    read again: a verdict does not change once the nightly has written it."""
    days = dict(known)
    for artifact in _artifacts(github, "image-gate-published"):
        day = str(artifact["created_at"])[:10]
        if day in days or day < since:
            continue
        verdict = json.loads(_files(github, artifact)["image-gate.json"])
        days[day] = {key: len(verdict[key]) for key in ("blocking", "unfixed", "accepted")}
    return days


def read_mutation(github: watchdog.GitHub) -> dict | None:
    found = _artifacts(github, "mutation-report")
    if not found:
        return None
    report = json.loads(_files(github, found[0])["mutation.json"])
    return {"date": str(found[0]["created_at"])[:10], "score": float(report["score"]),
            "caught": int(report["caught"]), "survived": int(report["survived"])}


def read_heal(github: watchdog.GitHub, now: datetime) -> str | None:
    """`heal_report.py`'s own summary for the month, or None while that script is not in
    the tree."""
    try:
        import heal_report
    except ImportError:
        return None
    return heal_report.summary(heal_report.report(github, now.strftime("%Y-%m"), now))


def state_of(body: str) -> dict:
    """What the record's last run read, from the comment at the issue's end."""
    found = _STATE.search(body or "")
    try:
        state = json.loads(found[1]) if found else {}
    except ValueError:
        state = {}
    return state if isinstance(state, dict) else {}


def _stale(what: dict, today: str) -> str:
    return (f" **It could not be read on {today}:** this is the last value read."
            if what.get("unread") else "")


def render(state: dict, heal: str | None, today: str) -> str:
    lines = [f"What is known of valvur's health, from recorded runs. Written on {today} by "
             "`health.yml`, which rewrites this issue daily: do not edit it, and a comment "
             "here is not read.", ""]
    score = state.get("score")
    lines += ["## The Score", ""]
    if score:
        lines += [f"**The Score: {score['score']}**, measured on {score['date']} by the "
                  f"weekly run on `main`.{_stale(score, today)}", "",
                  "| track | score |", "|---|---|",
                  *(f"| {name} | {value} |" for name, value in sorted(score["tracks"].items())),
                  ""]
    else:
        lines += ["**The Score:** no recorded run on `main` could be read.", ""]
    lines += ["## The published image, by day", ""]
    image = state.get("image") or {}
    if image:
        lines += ["What the image's own Trivy found in the published image each night. One "
                  "with a fixed version blocks a release.", "",
                  "| day | with a fix: blocking | with no fix yet | accepted by the owner |",
                  "|---|---|---|---|",
                  *(f"| {day} | {v['blocking']} | {v['unfixed']} | {v['accepted']} |"
                    for day, v in sorted(image.items(), reverse=True)), ""]
        if state.get("image_unread"):
            lines += [f"**The newest verdicts could not be read on {today}.**", ""]
    else:
        lines += ["For the published image, no verdict could be read.", ""]
    mutation = state.get("mutation")
    lines += ["## The mutation score", ""]
    if mutation:
        lines += [f"**The mutation score: {mutation['score']}**, measured on "
                  f"{mutation['date']}: of the week's code hunks, {mutation['caught']} "
                  f"reverted were noticed by a test and {mutation['survived']} were not."
                  f"{_stale(mutation, today)}", ""]
    else:
        lines += ["**The mutation score:** no recorded run could be read.", ""]
    lines += ["## Time to heal", ""]
    lines += [heal.rstrip(), ""] if heal else [
        "Not measured yet: the heal's report is not in this tree.", ""]
    kept = {key: state[key] for key in ("score", "image", "mutation") if state.get(key)}
    lines += ["<!-- valvur-health-state", json.dumps(kept, sort_keys=True), "-->"]
    return "\n".join(lines) + "\n"


def gather(github: watchdog.GitHub, last: dict, now: datetime) -> dict:
    """The record's state: each number as read today, or as last read, marked unread."""
    state: dict = {}
    for key, read in (("score", read_score), ("mutation", read_mutation)):
        try:
            fresh = read(github)
        except _READ_ERRORS:
            fresh = None
        if fresh is not None:
            state[key] = fresh
        elif last.get(key):
            state[key] = {**{k: v for k, v in last[key].items() if k != "unread"},
                          "unread": True}
    since = (now - timedelta(days=IMAGE_DAYS)).strftime("%Y-%m-%d")
    known = {day: counts for day, counts in (last.get("image") or {}).items()
             if day >= since}
    try:
        state["image"] = read_image(github, known, since)
    except _READ_ERRORS:
        state["image"], state["image_unread"] = known, True
    return state


def _own_issue(github: watchdog.GitHub) -> dict | None:
    """The open issue of the record's title that a workflow's own account opened."""
    issues = github.call("GET", "/issues?state=open&per_page=100")
    return next((i for i in issues if i.get("title") == TITLE and "pull_request" not in i
                 and (i.get("user") or {}).get("login") == ACCOUNT), None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--api", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--now", help="ISO 8601; the clock by default")
    parser.add_argument("--dry-run", action="store_true", help="print the record, write nothing")
    args = parser.parse_args(argv)
    now = (datetime.fromisoformat(args.now.rstrip("Z")).replace(tzinfo=UTC) if args.now
           else datetime.now(UTC))
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    github = watchdog.GitHub(args.api, args.repo, token)
    try:
        issue = _own_issue(github)
        state = gather(github, state_of(str((issue or {}).get("body") or "")), now)
        try:
            heal = read_heal(github, now)
        except _READ_ERRORS:
            heal = "Time to heal could not be read today."
        body = render(state, heal, now.strftime("%Y-%m-%d"))
        if args.dry_run:
            sys.stdout.write(body)
        elif issue is None:
            github.call("POST", "/issues", {"title": TITLE, "body": body})
        else:
            github.call("PATCH", f"/issues/{issue['number']}", {"body": body})
    except _READ_ERRORS as error:
        print(f"health: the record could not be written: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
