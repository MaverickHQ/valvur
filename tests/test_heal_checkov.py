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
