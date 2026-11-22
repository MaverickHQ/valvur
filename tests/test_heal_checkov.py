"""R44.7: Checkov's new versions arrive by the recipe, for the owner (D81q).

The heal never moves Checkov by itself. Once a week it looks for a newer release past the
cooldown and prepares the re-lock as one pull request, which the policy leaves for the
owner because Checkov moved. It replaces what Dependabot did for this lock.
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
MONDAY, TUESDAY = "2026-10-19T06:41:00Z", "2026-10-20T06:41:00Z"
PROJECTS = {"checkov": {"1.0": {**OLD, "requires": ["beta"]},
                        "1.1": {"uploaded": "2026-10-01T00:00:00Z", "requires": ["beta>=1.1"]},
                        "1.2": {"uploaded": "2026-10-16T00:00:00Z", "requires": ["beta>=1.1"]}},
            "beta": {"1.0": OLD, "1.1": OLD}}
HAVE = {"checkov": "1.0", "beta": "1.0"}


def _finding(package: str) -> dict:
    return {"rule": "CVE-2026-0001", "path": LOCK, "fingerprint": "fp", "severity": "high",
            "suppressed": None,
            "dependency": {"ecosystem": "pypi", "package": package, "version": "1.0",
                           "fixed_version": "1.1", "advisory_published": ""}}


def _mode(tmp_path: Path, monkeypatch, now: str, findings: tuple[dict, ...] = (),
          projects: dict | None = None) -> tuple[str, Path]:
    tree = heal_tree(tmp_path, monkeypatch, HAVE, projects or PROJECTS, top=("checkov==1.0",))
    scan = tmp_path / "findings.json"
    scan.write_text(json.dumps({"schema": 1, "findings": list(findings)}))
    run = subprocess.run([sys.executable, str(HEAL), "mode", "--findings", str(scan),
                          "--lock", str(tree / LOCK), "--now", now],
                         capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    return run.stdout.strip(), tree


def test_on_a_monday_a_newer_checkov_past_the_cooldown_is_mode_checkov(tmp_path, monkeypatch):
    assert _mode(tmp_path, monkeypatch, MONDAY)[0] == "checkov"


def test_on_any_other_day_it_is_none(tmp_path, monkeypatch):
    assert _mode(tmp_path, monkeypatch, TUESDAY)[0] == "none"


def test_a_newer_checkov_still_inside_the_cooldown_is_none(tmp_path, monkeypatch):
    young = {**PROJECTS, "checkov": {"1.0": PROJECTS["checkov"]["1.0"],
                                     "1.2": PROJECTS["checkov"]["1.2"]}}

    assert _mode(tmp_path, monkeypatch, MONDAY, projects=young)[0] == "none"


def test_a_finding_at_the_lock_comes_first_and_pypi_is_not_asked(tmp_path, monkeypatch):
    mode, _tree = _mode(tmp_path, monkeypatch, MONDAY, findings=(_finding("beta"),))

    assert mode == "heal"
    assert (tmp_path / "registry" / "asked.log").read_text() == ""


CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n"
POLICY = HEAL.parent / "heal_policy.py"


def _prepared(tmp_path: Path, monkeypatch) -> tuple[Path, dict, Path, str]:
    """The tree, the Checkov plan for it, and what `apply` makes of the plan."""
    tree = heal_tree(tmp_path, monkeypatch, HAVE, PROJECTS, top=("checkov==1.0",))
    (tree / "CHANGELOG.md").write_text(CHANGELOG)
    plan = tmp_path / "plan.json"
    planned = subprocess.run([sys.executable, str(HEAL), "plan", "--checkov", "--lock",
                              str(tree / LOCK), "--now", MONDAY, "--out", str(plan)],
                             capture_output=True, text=True, check=False)
    assert planned.returncode == 0, planned.stderr
    out = tmp_path / "out"
    applied = subprocess.run([sys.executable, str(HEAL), "apply", "--plan", str(plan),
                              "--tree", str(tree), "--out", str(out), "--run", "run-url"],
                             capture_output=True, text=True, check=False)
    assert applied.returncode == 0, applied.stderr
    return tree, json.loads(plan.read_text()), out, applied.stdout


def test_the_plan_takes_the_newest_checkov_past_the_cooldown_and_what_moves_with_it(
        tmp_path, monkeypatch):
    _tree, plan, _out, _message = _prepared(tmp_path, monkeypatch)

    assert plan["mode"] == "checkov"
    assert plan["pins"] == [
        {"package": "checkov", "from": "1.0", "to": "1.1", "why": "a new version",
         "rule": "cooldown", "uploaded": "2026-10-01T00:00:00Z"},
        {"package": "beta", "from": "1.0", "to": "1.1", "why": "moves with checkov 1.1",
         "rule": "resolution"},
    ]
    assert plan["escalations"] == []


def test_apply_edits_the_requirement_and_relocks(tmp_path, monkeypatch):
    tree, _plan, out, message = _prepared(tmp_path, monkeypatch)

    assert sorted(p.name for p in out.iterdir()) == [
        "CHANGELOG.md", "requirements-checkov.in", "requirements-checkov.txt"]
    assert (out / "requirements-checkov.in").read_text() == "checkov==1.1\n"
    lock = (out / LOCK).read_text()
    assert "checkov==1.1" in lock and "beta==1.1" in lock
    assert (tree / "requirements-checkov.in").read_text() == "checkov==1.0\n"
    changed = (out / "CHANGELOG.md").read_text().split("## [1.0.0]")[0]
    assert "### Changed\n\n- **Checkov 1.1 in the image,** from 1.0, with beta 1.1.\n" in changed
    assert message.splitlines()[0] == "chore: Checkov 1.1 in the lock, prepared by the heal"
    assert "Heal-Pin: checkov==1.1" in message


def test_verify_accepts_it_and_the_policy_leaves_it_for_the_owner(tmp_path, monkeypatch):
    tree, _plan, out, message = _prepared(tmp_path, monkeypatch)

    verified = subprocess.run([sys.executable, str(HEAL), "verify", "--plan",
                               str(tmp_path / "plan.json"), "--tree", str(tree), "--dir",
                               str(out)], capture_output=True, text=True, check=False)
    view = {"files": [{"path": p.name} for p in out.iterdir()],
            "commits": [{"sha": "0" * 40, "author": {"login": "valvur-heal[bot]"},
                         "committer": {"login": "web-flow"},
                         "commit": {"message": message, "verification": {"verified": True}}}]}
    judged = subprocess.run([sys.executable, str(POLICY), "lock", "--base", str(tree),
                             "--head", str(out)], input=json.dumps(view), capture_output=True,
                            text=True, check=False)

    assert verified.returncode == 0, verified.stderr
    assert judged.returncode == 1
    assert "requirements-checkov.in" in judged.stdout


def test_the_pull_request_is_the_notice_and_no_issue_is_opened(tmp_path, monkeypatch):
    _prepared(tmp_path, monkeypatch)
    (tmp_path / "none.json").write_text(json.dumps({"schema": 1, "findings": []}))
    (tmp_path / "issues.json").write_text("[]")

    run = subprocess.run([sys.executable, str(HEAL), "escalations", "--plan",
                          str(tmp_path / "plan.json"), "--observed", str(tmp_path / "none.json"),
                          "--issues", str(tmp_path / "issues.json"), "--now", MONDAY],
                         capture_output=True, text=True, check=False)

    assert json.loads(run.stdout)["actions"] == []


def test_the_same_plan_makes_the_same_bytes_so_a_rebuild_changes_nothing(tmp_path, monkeypatch):
    tree, _plan, out, message = _prepared(tmp_path, monkeypatch)
    again = tmp_path / "again"

    second = subprocess.run([sys.executable, str(HEAL), "apply", "--plan",
                             str(tmp_path / "plan.json"), "--tree", str(tree), "--out",
                             str(again), "--run", "run-url"],
                            capture_output=True, text=True, check=False)

    assert second.stdout == message
    for path in out.iterdir():
        assert (again / path.name).read_bytes() == path.read_bytes(), path.name


def test_with_no_newer_checkov_the_plan_is_empty(tmp_path, monkeypatch):
    only = {**PROJECTS, "checkov": {"1.0": PROJECTS["checkov"]["1.0"]}}
    tree = heal_tree(tmp_path, monkeypatch, HAVE, only, top=("checkov==1.0",))
    plan = tmp_path / "plan.json"

    run = subprocess.run([sys.executable, str(HEAL), "plan", "--checkov", "--lock",
                          str(tree / LOCK), "--now", MONDAY, "--out", str(plan)],
                         capture_output=True, text=True, check=False)

    assert run.returncode == 0, run.stderr
    assert json.loads(plan.read_text())["pins"] == []


def test_the_pull_requests_body_says_it_is_the_owners_to_land(tmp_path, monkeypatch):
    _prepared(tmp_path, monkeypatch)

    run = subprocess.run([sys.executable, str(HEAL), "body", "--plan",
                          str(tmp_path / "plan.json"), "--run", "run-url"],
                         capture_output=True, text=True, check=False)

    assert run.returncode == 0, run.stderr
    assert "for the owner to read and land" in run.stdout
    rows = [[cell.strip() for cell in line.strip("|").split("|")]
            for line in run.stdout.splitlines() if line.startswith("|")]
    assert ["checkov", "1.0", "1.1", "a new version",
            "cooldown: uploaded 2026-10-01, 18 days before this plan"] in rows
    assert ["beta", "1.0", "1.1", "moves with checkov 1.1",
            "resolution: the recipe moved it with Checkov"] in rows
