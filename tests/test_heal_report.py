"""R46.1: time to heal, measured from GitHub's API alone (Requirement 13, D81r).

`scripts/heal_report.py --month YYYY-MM` reads the heal's merged pull requests, their
commits' trailers and the releases. For each advisory it gives four times: published, pull
request opened, merged, and promoted in a release. The measure is published to promoted,
against a 48-hour target. GitHub is `tests/fake_github.py`, on loopback.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from fake_github import FakeGitHub

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
_spec = importlib.util.spec_from_file_location("heal_report", REPO / "scripts" / "heal_report.py")
heal_report = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(heal_report)  # type: ignore[union-attr]

MESSAGE = ("fix: aiohttp 3.14.5 in the Checkov lock, by the heal\n\nHeal-Pin: aiohttp==3.14.5\n"
           "Heal-Advisory: CVE-2026-111064 aiohttp published 2026-11-03T10:00:00Z\n"
           "Heal-Advisory: CVE-2026-111066 aiohttp published 2026-11-03T16:00:00Z\n"
           "Heal-Run: https://example.invalid/1\n")


def _pull(number: int, sha: str, opened: str, merged: str | None, *,
          login: str = "valvur-heal[bot]", ref: str = "heal/2026-11-03-1a2b3c4") -> dict:
    return {"number": number, "created_at": opened, "merged_at": merged,
            "merge_commit_sha": sha, "user": {"login": login}, "head": {"ref": ref},
            "state": "closed" if merged else "open", "title": "fix: by the heal"}


@pytest.fixture
def github():
    with FakeGitHub() as fake:
        fake.releases[fake.repo] = [
            {"tag_name": "v1.6.4", "published_at": "2026-11-09T09:00:00Z", "draft": False},
            {"tag_name": "v1.6.3", "published_at": "2026-11-04T20:00:00Z", "draft": False},
            {"tag_name": "v1.6.2", "published_at": "2026-11-01T08:00:00Z", "draft": False}]
        fake.commits["a" * 40] = MESSAGE
        fake.pulls = [_pull(310, "a" * 40, "2026-11-03T18:41:00Z", "2026-11-03T19:10:00Z")]
        yield fake


def _report(github: FakeGitHub, capsys, *extra: str) -> tuple[int, str]:
    code = heal_report.main(["--repo", github.repo, "--api", github.url, "--month", "2026-11",
                             *extra])
    return code, capsys.readouterr().out


def test_each_advisory_has_its_four_times_and_its_hours_against_the_target(github, capsys):
    code, said = _report(github, capsys, "--json")

    assert code == 0
    report = json.loads(said)
    assert report["target_hours"] == 48
    assert report["advisories"] == [
        {"advisory": "CVE-2026-111064", "subject": "aiohttp", "pull": 310,
         "published": "2026-11-03T10:00:00Z", "opened": "2026-11-03T18:41:00Z",
         "merged": "2026-11-03T19:10:00Z", "release": "v1.6.3",
         "promoted": "2026-11-04T20:00:00Z", "hours": 34.0, "within": True},
        {"advisory": "CVE-2026-111066", "subject": "aiohttp", "pull": 310,
         "published": "2026-11-03T16:00:00Z", "opened": "2026-11-03T18:41:00Z",
         "merged": "2026-11-03T19:10:00Z", "release": "v1.6.3",
         "promoted": "2026-11-04T20:00:00Z", "hours": 28.0, "within": True}]


def test_a_heal_merged_and_not_yet_released_is_open_and_counts_the_hours_so_far(
        github, capsys):
    github.releases[github.repo] = github.releases[github.repo][2:]

    _code, said = _report(github, capsys, "--json", "--now", "2026-11-06T10:00:00Z")

    first = json.loads(said)["advisories"][0]
    assert first["release"] is None and first["promoted"] is None
    assert first["hours"] == 72.0 and first["within"] is False


def test_only_the_heals_own_merged_pull_requests_of_the_month_are_read(github, capsys):
    github.commits["b" * 40] = MESSAGE.replace("111064", "999999")
    github.pulls += [
        _pull(311, "b" * 40, "2026-11-05T00:00:00Z", "2026-11-05T01:00:00Z", login="a-stranger"),
        _pull(312, "b" * 40, "2026-11-05T00:00:00Z", "2026-11-05T01:00:00Z", ref="feature/x"),
        _pull(313, "b" * 40, "2026-10-30T00:00:00Z", "2026-10-30T01:00:00Z"),
        _pull(314, "b" * 40, "2026-11-05T00:00:00Z", None)]

    _code, said = _report(github, capsys, "--json")

    report = json.loads(said)
    assert {a["pull"] for a in report["advisories"]} == {310}
    assert report["open"] == [314]


def test_an_image_heals_advisory_has_no_publication_time_and_says_so(github, capsys):
    github.commits["a" * 40] = ("fix: tzdata 2026b-r0 in the image, by the heal\n\n"
                                "Heal-Raise: ALPINE_RAISE tzdata=2026b-r0\n"
                                "Heal-Advisory: CVE-2026-0003 tzdata\n")

    _code, said = _report(github, capsys, "--json")

    [only] = json.loads(said)["advisories"]
    assert only["published"] is None and only["hours"] is None and only["within"] is None


def test_the_summary_is_a_table_with_the_month_and_the_open_heals(github, capsys):
    github.pulls.append(_pull(314, "c" * 40, "2026-11-10T00:00:00Z", None))

    _code, said = _report(github, capsys)

    assert "| CVE-2026-111064 | aiohttp | #310 | 34.0 h | within 48 h |" in said
    assert "2026-11: 2 advisories healed, 2 within 48 hours" in said
    assert "Open heals: #314" in said


def test_octobers_incident_is_the_baseline():
    """By hand, before there was a heal: the first of the four advisories was published on
    2026-10-19T16:47:35Z (OSV), and 1.5.4 was published on 2026-10-25T09:17:06Z (GitHub)."""
    assert heal_report.BASELINE == {
        "published": "2026-10-19T16:47:35Z", "promoted": "2026-10-25T09:17:06Z",
        "release": "v1.5.4", "hours": 136.5}
    assert heal_report.hours("2026-10-19T16:47:35Z", "2026-10-25T09:17:06Z") == 136.5


def test_an_api_that_cannot_be_read_is_exit_two(capsys):
    assert heal_report.main(["--repo", "MaverickHQ/valvur", "--api", "http://127.0.0.1:9",
                             "--month", "2026-11"]) == 2
