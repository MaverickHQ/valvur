"""R22.1: OpenSSF Scorecard (D49a).

`scorecard.yml` runs `ossf/scorecard-action` weekly and on `main`, and publishes its
result to the public OpenSSF API, which the README's badge reads. The result
describes the repository, never a user's code. Each action is pinned by commit; the
scorecard job holds the action's documented minimum, `security-events: write` and
`id-token: write`, and nothing more; and `publish_results` is true on `main` alone,
since Scorecard publishes only from the default branch and a pull request measures
the branch with publishing off.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "scorecard.yml"


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1]
    keys = list(re.finditer(r"^  ([a-z][\w-]*):$", body, re.M))
    return {k[1]: body[k.end():keys[i + 1].start() if i + 1 < len(keys) else len(body)]
            for i, k in enumerate(keys)}


def _scorecard_job() -> str:
    [job] = [j for j in _jobs(WORKFLOW.read_text()).values() if "ossf/scorecard-action@" in j]
    return job


def test_every_action_is_pinned_by_commit():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())

    assert any(u.startswith("ossf/scorecard-action@") for u in uses)
    for use in uses:
        if use.startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", use), use


def test_the_scorecard_job_holds_the_documented_minimum_and_nothing_more():
    text = WORKFLOW.read_text()
    job = _scorecard_job()
    granted = re.search(r"^    permissions:\n((?:      [\w-]+: \w+.*\n)+)", job, re.M)

    assert granted, "the scorecard job declares no permissions of its own"
    assert dict(re.findall(r"^      ([\w-]+): (\w+)", granted.group(1), re.M)) == {
        "security-events": "write", "id-token": "write"}
    top = re.search(r"^permissions:\n((?:  [\w-]+: \w+\n)+)", text, re.M)
    assert top and "write" not in top.group(1), "write granted to the whole workflow"
    # What publishing a result requires of the workflow, by the action's rules.
    assert not re.search(r"^(env|defaults):", text, re.M)
    assert not re.search(r"^    (env|defaults|container|services):", job, re.M)
    assert text.count("id-token: write") == 1, "id-token granted beyond the scorecard job"


def test_it_publishes_from_main_alone():
    job = _scorecard_job()
    publish = re.search(r"^\s+publish_results: (.+)$", job, re.M)

    assert publish, "publish_results is not set"
    condition = publish.group(1)
    assert "github.ref == 'refs/heads/main'" in condition
    assert "github.event_name != 'pull_request'" in condition
    triggers = WORKFLOW.read_text().split("\njobs:", 1)[0]
    assert re.search(r"push:\n\s+branches: \[main\]", triggers)
    assert re.search(r"^\s+schedule:", triggers, re.M)


def test_the_readme_shows_the_badge_the_published_result_feeds():
    """The badge reads the result `main` publishes; until R22 lands it shows none, and
    the first run on `main` gives it a score (§8)."""
    first = "\n".join((REPO / "README.md").read_text().splitlines()[:24])

    assert ("[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/"
            "MaverickHQ/valvur/badge)](https://scorecard.dev/viewer/?uri=github.com/"
            "MaverickHQ/valvur)") in first
