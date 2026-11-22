"""R44.2: the heal's plan for the Checkov lock (D81d, D81e).

`scripts/heal.py plan` reads a Scan Run's Findings at the lock, asks PyPI which versions
exist and when each was uploaded, and writes `plan.json`: a pin for each package it may
move, and an escalation for each it may not. PyPI is `tests/fake_registry.py`'s, answered
by URL in the script's own process, so nothing here opens a socket.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fake_registry import FakePackageRegistry, pypi_answers
from test_checkov_lock_recipe import _tree, _wheel

REPO = Path(__file__).resolve().parent.parent
HEAL = REPO / "scripts" / "heal.py"
LOCK = "requirements-checkov.txt"
NOW = "2026-10-21T06:41:00Z"

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="the recipe runs uv")


def _finding(package: str, version: str, fixed: str, *, rule: str = "CVE-2026-0001",
             path: str = LOCK, **more) -> dict:
    return {"rule": rule, "path": path, "fingerprint": f"fp-{rule}-{package}",
            "severity": "high", "suppressed": None,
            "dependency": {"ecosystem": "pypi", "package": package, "version": version,
                           "fixed_version": fixed,
                           "advisory_published": "2026-10-19T12:00:00Z"}, **more}


def _plan(tmp_path: Path, monkeypatch, findings: list[dict], have: dict[str, str],
          projects: dict[str, dict[str, dict]], *, top: tuple[str, ...] = ()
          ) -> tuple[subprocess.CompletedProcess[str], dict]:
    """Run `heal.py plan` on a tree whose lock the recipe itself wrote, holding `have`.

    Resolution is real and hermetic, as in `test_checkov_lock_recipe.py`: a wheel for every
    version in `projects` (its `requires` as `Requires-Dist`), read by uv from a directory.
    PyPI's facts about the same versions are the fake registry's."""
    FakePackageRegistry(tmp_path / "registry", pypi_answers(projects)).install(monkeypatch)
    tree, wheels = _tree(tmp_path, "\n".join(top or tuple(have)))
    for name, versions in projects.items():
        for version, facts in versions.items():
            _wheel(wheels, name, version, tuple(facts.get("requires", ())))
    # uv reads no index but the wheels: its `--no-index` has no environment variable, so
    # a configuration file says it, for the recipe here and for the one the heal runs.
    config = tmp_path / "uv.toml"
    config.write_text(f'[pip]\nno-index = true\nfind-links = ["{wheels}"]\n')
    monkeypatch.setenv("UV_CONFIG_FILE", str(config))
    start = tmp_path / "start.txt"
    start.write_text("".join(f"{name}=={version}\n" for name, version in have.items()))
    made = subprocess.run(["sh", str(tree / "scripts" / "lock-checkov.sh"), "--no-annotate",
                           "--constraint", str(start)], capture_output=True, text=True, check=False)
    assert made.returncode == 0, made.stderr
    scan = tmp_path / "findings.json"
    scan.write_text(json.dumps({"schema": 1, "findings": findings}))
    out = tmp_path / "plan.json"
    run = subprocess.run(
        [sys.executable, str(HEAL), "plan", "--findings", str(scan),
         "--lock", str(tree / LOCK), "--now", NOW, "--out", str(out)],
        capture_output=True, text=True, check=False)
    return run, json.loads(out.read_text()) if out.is_file() else {}


def test_a_fix_past_the_cooldown_is_pinned_at_the_newest_such_version_in_the_major(
        tmp_path, monkeypatch):
    projects = {"beta": {
        "1.0": {"uploaded": "2026-01-01T00:00:00Z"},
        "1.1": {"uploaded": "2026-09-20T00:00:00Z"},
        "1.2": {"uploaded": "2026-10-11T00:00:00Z"},
        "1.3": {"uploaded": "2026-10-19T00:00:00Z"},
        "2.0": {"uploaded": "2026-08-01T00:00:00Z"},
    }}

    run, plan = _plan(tmp_path, monkeypatch, [_finding("beta", "1.0", "1.1")],
                      {"beta": "1.0"}, projects)

    assert run.returncode == 0, run.stderr
    assert plan["schema"] == 1 and plan["made"] == NOW and plan["lock"] == LOCK
    assert plan["pins"] == [{"package": "beta", "from": "1.0", "to": "1.2", "why": "fix",
                             "rule": "cooldown", "uploaded": "2026-10-11T00:00:00Z"}]
    assert plan["escalations"] == []
    assert [f["rule"] for f in plan["findings"]] == ["CVE-2026-0001"]


OLD = {"uploaded": "2026-01-01T00:00:00Z"}
PUBLISHER = {"kind": "GitHub", "repository": "example/beta", "workflow": "release.yml"}


def test_a_young_fix_a_day_old_from_the_replaced_versions_publisher_is_pinned_as_young_attested(
        tmp_path, monkeypatch):
    projects = {"beta": {
        "1.0": {**OLD, "publisher": PUBLISHER},
        "1.1": {"uploaded": "2026-10-19T06:00:00Z", "publisher": PUBLISHER},
        "1.2": {"uploaded": "2026-10-20T00:00:00Z", "publisher": PUBLISHER},
    }}

    run, plan = _plan(tmp_path, monkeypatch, [_finding("beta", "1.0", "1.1")],
                      {"beta": "1.0"}, projects)

    assert run.returncode == 0, run.stderr
    assert plan["pins"] == [{"package": "beta", "from": "1.0", "to": "1.1", "why": "fix",
                             "rule": "young-attested", "uploaded": "2026-10-19T06:00:00Z",
                             "publisher": PUBLISHER}]
    assert plan["escalations"] == []


OTHER = {"kind": "GitHub", "repository": "someone-else/beta", "workflow": "release.yml"}


@pytest.mark.parametrize("young", [
    pytest.param({"uploaded": "2026-10-20T12:00:00Z", "publisher": PUBLISHER}, id="under-a-day"),
    pytest.param({"uploaded": "2026-10-19T06:00:00Z"}, id="unattested"),
    pytest.param({"uploaded": "2026-10-19T06:00:00Z", "publisher": OTHER}, id="another-publisher"),
])
def test_a_young_fix_that_fails_the_rule_is_escalated_and_not_pinned(tmp_path, monkeypatch, young):
    projects = {"beta": {"1.0": {**OLD, "publisher": PUBLISHER}, "1.1": young}}

    run, plan = _plan(tmp_path, monkeypatch, [_finding("beta", "1.0", "1.1")],
                      {"beta": "1.0"}, projects)

    assert run.returncode == 0, run.stderr
    assert plan["pins"] == []
    assert plan["escalations"] == [{"package": "beta", "reason": "young-unattested",
                                    "findings": ["fp-CVE-2026-0001-beta"]}]


def test_a_replaced_version_with_no_attestation_fails_the_rule(tmp_path, monkeypatch):
    projects = {"beta": {"1.0": OLD,
                         "1.1": {"uploaded": "2026-10-19T06:00:00Z", "publisher": PUBLISHER}}}

    _run, plan = _plan(tmp_path, monkeypatch, [_finding("beta", "1.0", "1.1")],
                       {"beta": "1.0"}, projects)

    assert plan["pins"] == []
    assert [e["reason"] for e in plan["escalations"]] == ["young-unattested"]


def test_a_finding_with_no_fixed_version_is_escalated_as_no_fix(tmp_path, monkeypatch):
    run, plan = _plan(tmp_path, monkeypatch, [_finding("beta", "1.0", "")],
                      {"beta": "1.0"}, {"beta": {"1.0": OLD}})

    assert run.returncode == 0, run.stderr
    assert plan["pins"] == []
    assert plan["escalations"] == [{"package": "beta", "reason": "no-fix",
                                    "findings": ["fp-CVE-2026-0001-beta"]}]


def test_a_fix_only_in_the_next_major_is_escalated_as_major(tmp_path, monkeypatch):
    projects = {"beta": {"1.0": OLD, "1.1": OLD, "2.0": {"uploaded": "2026-08-01T00:00:00Z"}}}

    run, plan = _plan(tmp_path, monkeypatch, [_finding("beta", "1.0", "2.0")],
                      {"beta": "1.0"}, projects)

    assert run.returncode == 0, run.stderr
    assert plan["pins"] == []
    assert plan["escalations"] == [{"package": "beta", "reason": "major",
                                    "findings": ["fp-CVE-2026-0001-beta"]}]


def test_a_version_the_resolution_forces_is_pinned_by_the_same_rule(tmp_path, monkeypatch):
    """As yarl under aiohttp on 2026-10-21. uv would take the newest beta it may, 1.2,
    which is two days old. The rule takes 1.1: the newest past the cooldown."""
    projects = {
        "alpha": {"1.0": {**OLD, "requires": ["beta>=1.0"]},
                  "1.1": {"uploaded": "2026-10-01T00:00:00Z", "requires": ["beta>=1.1"]}},
        "beta": {"1.0": OLD,
                 "1.1": {"uploaded": "2026-09-15T00:00:00Z"},
                 "1.2": {"uploaded": "2026-10-19T06:00:00Z"}},
    }

    run, plan = _plan(tmp_path, monkeypatch, [_finding("alpha", "1.0", "1.1")],
                      {"alpha": "1.0", "beta": "1.0"}, projects, top=("alpha",))

    assert run.returncode == 0, run.stderr
    assert plan["pins"] == [
        {"package": "alpha", "from": "1.0", "to": "1.1", "why": "fix", "rule": "cooldown",
         "uploaded": "2026-10-01T00:00:00Z"},
        {"package": "beta", "from": "1.0", "to": "1.1", "why": "floor of alpha 1.1",
         "rule": "cooldown", "uploaded": "2026-09-15T00:00:00Z"},
    ]
    assert plan["escalations"] == []
