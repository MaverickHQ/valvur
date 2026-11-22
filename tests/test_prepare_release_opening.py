"""R45.2: `prepare_release.py` can be reproduced, opening and trailers included.

A release the heal prepares carries an opening for its CHANGELOG entry, from one template,
and trailers on its commit. The policy runs the same command on the base branch and asks
for the same tree, so both are arguments, and the date is one already (`--date`).
"""

from __future__ import annotations

from test_prepare_release import NEXT, _git, _script, tree  # noqa: F401

OPENING = ("A security patch, released by the heal (ADR-0032): beta 1.0 to 1.1 in the Checkov "
           "lock, past CVE-2026-0001.")


def test_an_opening_is_written_under_the_versions_heading(tree):  # noqa: F811
    code = _script().main([NEXT, "--root", str(tree), "--date", "2026-11-22",
                           "--opening", OPENING])

    assert code == 0
    changelog = (tree / "CHANGELOG.md").read_text()
    assert f"## [Unreleased]\n\n## [{NEXT}] — 2026-11-22\n\n{OPENING}\n\n" in changelog


def test_trailers_follow_the_release_commits_subject(tree):  # noqa: F811
    _script().main([NEXT, "--root", str(tree), "--date", "2026-11-22",
                    "--trailer", "Release-Date: 2026-11-22",
                    "--trailer", "Heal-Run: https://example.invalid/7"])

    assert _git(tree, "log", "-1", "--format=%B").strip() == (
        f"chore: release {NEXT}\n\nRelease-Date: 2026-11-22\n"
        "Heal-Run: https://example.invalid/7")


def test_without_either_the_release_commit_is_what_it_was(tree):  # noqa: F811
    _script().main([NEXT, "--root", str(tree), "--date", "2026-11-22"])

    assert _git(tree, "log", "-1", "--format=%B").strip() == f"chore: release {NEXT}"
    changelog = (tree / "CHANGELOG.md").read_text()
    assert f"## [{NEXT}] — 2026-11-22\n\n" in changelog and "released by the heal" not in (
        changelog.split(f"## [{NEXT}]")[1].split("\n## [")[0].split("\n\n")[1])


def test_the_same_arguments_give_the_same_plan(tree):  # noqa: F811
    script = _script()

    one = script.planned(tree, NEXT, "2026-11-22", OPENING)
    two = script.planned(tree, NEXT, "2026-11-22", OPENING)

    assert one == two and OPENING in one[next(p for p in one if p.name == "CHANGELOG.md")]
