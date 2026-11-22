#!/usr/bin/env python3
"""Time to heal, from GitHub's API alone (R46.1, D81r, Requirement 13).

    python3 scripts/heal_report.py --repo MaverickHQ/valvur --month 2026-11 [--json]

For each advisory a heal answered in the month, four times: when it was published, when the
heal opened its pull request, when that merged, and when a release that holds it was
promoted. The measure is published to promoted, against a target of 48 hours (D81b).

It reads the heal App's merged pull requests whose branch is `heal/…`, each one's merge
commit for its `Heal-Advisory` trailers, and the releases. A heal is promoted by the first
release published after it merged. An advisory with no release yet counts its hours up to
now, and is outside the target once they pass it. An image heal's trailer carries no
publication time, so its hours are not computed, and the report says so.

The baseline is October 2026, by hand and before there was a heal: 136.5 hours from the
first of four advisories to 1.5.4. Standard library alone. Exit 0 when the report was
written, 2 when the API could not be read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import watchdog

#: D81b: the healing window, as a target.
TARGET_HOURS = 48
APP = "valvur-heal[bot]"
_ADVISORY = re.compile(r"^Heal-Advisory: (\S+) (.+?)(?: published (\S+))?$", re.M)
#: 2026-10: the first advisory's publication (OSV, CVE-2026-111064) to 1.5.4's (GitHub).
BASELINE = {"published": "2026-10-19T16:47:35Z", "promoted": "2026-10-25T09:17:06Z",
            "release": "v1.5.4", "hours": 136.5}


def _when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.split(".")[0].rstrip("Z")).replace(tzinfo=UTC)


def hours(start: str, end: str) -> float:
    """From one time to another, in hours, to one decimal."""
    return round((_when(end) - _when(start)).total_seconds() / 3600, 1)


def report(github: watchdog.GitHub, month: str, now: datetime) -> dict:
    releases = sorted((r for r in github.call("GET", "/releases?per_page=100")
                       if r.get("published_at") and not r.get("draft")),
                      key=lambda r: r["published_at"])
    pulls = [p for p in github.call("GET", "/pulls?state=all&sort=created&direction=desc"
                                           "&per_page=100")
             if (p.get("user") or {}).get("login") == APP
             and str((p.get("head") or {}).get("ref", "")).startswith("heal/")]
    advisories = []
    for pull in sorted(pulls, key=lambda p: p["number"]):
        merged = pull.get("merged_at")
        if not merged or not merged.startswith(month):
            continue
        message = github.call("GET", f"/commits/{pull['merge_commit_sha']}")["commit"]["message"]
        release = next((r for r in releases if r["published_at"] >= merged), None)
        promoted = release["published_at"] if release else None
        for advisory, subject, published in _ADVISORY.findall(message):
            spent = (hours(published, promoted or now.strftime("%Y-%m-%dT%H:%M:%SZ"))
                     if published else None)
            advisories.append({
                "advisory": advisory, "subject": subject, "pull": pull["number"],
                "published": published or None, "opened": pull["created_at"], "merged": merged,
                "release": release["tag_name"] if release else None, "promoted": promoted,
                "hours": spent, "within": None if spent is None else spent <= TARGET_HOURS})
    return {"month": month, "target_hours": TARGET_HOURS, "baseline": BASELINE,
            "advisories": advisories,
            "open": sorted(p["number"] for p in pulls if p.get("state") == "open")}


def summary(made: dict) -> str:
    """The report as Markdown, for a run's summary and for a person."""
    target = made["target_hours"]
    lines = ["| advisory | subject | pull request | published to promoted | against the target |",
             "|---|---|---|---|---|"]
    for a in made["advisories"]:
        spent = "not computed: no publication time" if a["hours"] is None else f"{a['hours']} h"
        if a["within"] is None:
            verdict = "not judged"
        elif a["promoted"] is None:
            verdict = f"not released yet, {'within' if a['within'] else 'past'} {target} h"
        else:
            verdict = f"{'within' if a['within'] else 'past'} {target} h"
        lines.append(f"| {a['advisory']} | {a['subject']} | #{a['pull']} | {spent} | {verdict} |")
    healed = [a for a in made["advisories"] if a["promoted"]]
    within = sum(1 for a in healed if a["within"])
    lines += ["", f"{made['month']}: {len(healed)} advisories healed, {within} within "
                  f"{target} hours. The baseline, by hand in October 2026: "
                  f"{made['baseline']['hours']} hours.",
              "Open heals: " + (", ".join(f"#{n}" for n in made["open"]) or "none") + "."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--api", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--month", required=True, help="YYYY-MM")
    parser.add_argument("--now", help="ISO 8601; the clock by default")
    parser.add_argument("--json", action="store_true", help="the report as JSON")
    args = parser.parse_args(argv)
    now = _when(args.now) if args.now else datetime.now(UTC)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        made = report(watchdog.GitHub(args.api, args.repo, token), args.month, now)
    except (urllib.error.URLError, ValueError, KeyError, TypeError) as error:
        print(f"heal report: cannot read GitHub's API: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(made, indent=2) + "\n" if args.json else summary(made))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
