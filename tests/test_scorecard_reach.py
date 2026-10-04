"""R27.5: Scorecard measured again, and what only a second maintainer lifts (D63d).

A pull request ran Scorecard, publishing off, only when it changed `scorecard.yml`
itself, so R27, which changes what Scorecard reads, could not measure itself. It
runs when anything Scorecard scores changes. The README's note beside the badge
names the checks one maintainer cannot lift, so a reader does not take them for
neglect.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_a_pull_request_that_changes_what_scorecard_reads_measures_itself():
    text = (REPO / ".github" / "workflows" / "scorecard.yml").read_text()
    on = text.split("\npull_request:\n", 1)[1] if "\npull_request:\n" in text else \
        text.split("  pull_request:\n", 1)[1].split("\npermissions:", 1)[0]
    paths = re.findall(r'^\s+- "([^"]+)"', on, re.M)

    for read in (".github/workflows/**", "Dockerfile", ".clusterfuzzlite/**",
                 "osv-scanner.toml", "fuzz/**", "tests/fixtures/**"):
        assert read in paths, f"a change to {read} does not measure itself"


def test_the_readme_names_what_only_a_second_maintainer_lifts():
    readme = (REPO / "README.md").read_text()
    head = readme.split("\n## ", 1)[0]
    badge = head.index("api.scorecard.dev")
    note = head[badge:].split("\n\n", 1)[0]

    for check in ("Code-Review", "Branch-Protection", "Contributors"):
        assert check in note, f"the note beside the badge does not name {check}"
    assert "second maintainer" in note
