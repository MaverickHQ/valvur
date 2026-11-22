"""R44.3: the heal's proposal, made from a plan and checked as data (Requirement 7).

`scripts/heal.py apply` re-locks with the recipe and the plan's pins, and writes the two
files a heal changes into a directory of its own: the lock, and the CHANGELOG with one
`### Security` item for each package. It refuses its own result when a package moved that
the plan does not name. Resolution is real and hermetic (`heal_support.tree`).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from heal_support import HEAL, LOCK
from heal_support import tree as heal_tree

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="the recipe runs uv")

OLD = {"uploaded": "2026-01-01T00:00:00Z"}
CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n"
RUN = "https://github.com/MaverickHQ/valvur/actions/runs/1"


def _pin(package: str, old: str, new: str, why: str = "fix") -> dict:
    return {"package": package, "from": old, "to": new, "why": why, "rule": "cooldown",
            "uploaded": "2026-10-01T00:00:00Z"}


def _apply(tmp_path: Path, monkeypatch, pins: list[dict], have: dict[str, str],
           projects: dict[str, dict[str, dict]], *, top: tuple[str, ...] = (),
           findings: tuple[dict, ...] = (), changelog: str = CHANGELOG
           ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    tree = heal_tree(tmp_path, monkeypatch, have, projects, top=top)
    (tree / "CHANGELOG.md").write_text(changelog)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"schema": 1, "made": "2026-10-21T06:41:00Z", "lock": LOCK,
                                "findings": list(findings), "pins": pins, "escalations": []}))
    out = tmp_path / "out"
    run = subprocess.run([sys.executable, str(HEAL), "apply", "--plan", str(plan),
                          "--tree", str(tree), "--out", str(out), "--run", RUN],
                         capture_output=True, text=True, check=False)
    return run, tree, out


def test_the_recipe_is_run_with_the_plans_pins_and_the_lock_is_written_apart(
        tmp_path, monkeypatch):
    projects = {"beta": {"1.0": OLD, "1.1": OLD, "1.2": OLD}}

    run, tree, out = _apply(tmp_path, monkeypatch, [_pin("beta", "1.0", "1.1")],
                            {"beta": "1.0"}, projects)

    assert run.returncode == 0, run.stderr
    lock = (out / LOCK).read_text()
    assert "beta==1.1" in lock and "--hash=sha256:" in lock
    assert "beta==1.0" in (tree / LOCK).read_text(), "the tree's own lock is never written"


def test_a_result_that_moves_a_package_the_plan_does_not_name_is_refused(
        tmp_path, monkeypatch):
    projects = {"alpha": {"1.0": OLD, "1.1": {**OLD, "requires": ["beta>=1.1"]}},
                "beta": {"1.0": OLD, "1.1": OLD}}

    run, _tree, out = _apply(tmp_path, monkeypatch, [_pin("alpha", "1.0", "1.1")],
                             {"alpha": "1.0", "beta": "1.0"}, projects)

    assert run.returncode == 1
    assert "beta" in run.stderr and "1.1" in run.stderr
    assert not (out / LOCK).exists()


def _advisory(rule: str, package: str, version: str, fixed: str) -> dict:
    return {"rule": rule, "fingerprint": f"fp-{rule}", "package": package, "version": version,
            "fixed_version": fixed, "severity": "high",
            "advisory_published": "2026-10-19T16:47:35Z"}


def test_the_changelog_gains_one_security_item_for_each_package_under_unreleased(
        tmp_path, monkeypatch):
    projects = {"alpha": {"1.0": OLD, "1.1": {**OLD, "requires": ["beta>=1.1"]}},
                "beta": {"1.0": OLD, "1.1": OLD}}
    pins = [_pin("alpha", "1.0", "1.1"), _pin("beta", "1.0", "1.1", "floor of alpha 1.1")]
    findings = (_advisory("CVE-2026-0002", "alpha", "1.0", "1.1"),
                _advisory("CVE-2026-0001", "alpha", "1.0", "1.1"))

    run, _tree, out = _apply(tmp_path, monkeypatch, pins, {"alpha": "1.0", "beta": "1.0"},
                             projects, findings=findings)

    assert run.returncode == 0, run.stderr
    changelog = (out / "CHANGELOG.md").read_text()
    unreleased = changelog.split("## [Unreleased]")[1].split("## [1.0.0]")[0]
    assert unreleased.count("### Security") == 1
    items = [line for line in unreleased.splitlines() if line.startswith("- ")]
    assert items == [
        "- **alpha 1.1 in the Checkov lock,** from 1.0, past CVE-2026-0001 and CVE-2026-0002.",
        "- **beta 1.1 in the Checkov lock,** from 1.0, which alpha 1.1 requires.",
    ]
    assert "## [Unreleased]\n\n### Security\n\n- **alpha 1.1" in changelog
    assert changelog.endswith("requires.\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n")


def test_items_join_a_security_heading_unreleased_already_has(tmp_path, monkeypatch):
    had = ("# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- A fix.\n\n### Security\n\n"
           "- **An earlier item.**\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n")
    projects = {"beta": {"1.0": OLD, "1.1": OLD}}

    _run, _tree, out = _apply(tmp_path, monkeypatch, [_pin("beta", "1.0", "1.1")],
                              {"beta": "1.0"}, projects, changelog=had,
                              findings=(_advisory("CVE-2026-0001", "beta", "1.0", "1.1"),))

    changelog = (out / "CHANGELOG.md").read_text()
    assert changelog.count("### Security") == 1
    assert changelog.index("- **An earlier item.**") < changelog.index("- **beta 1.1")
    assert changelog.index("- **beta 1.1") < changelog.index("## [1.0.0]")
    kept = [line for line in had.splitlines() if line]
    assert [line for line in changelog.splitlines() if line in kept] == kept, "nothing removed"
