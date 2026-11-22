"""R44.2: the heal's plan for the Checkov lock (D81d, D81e).

`scripts/heal.py plan` reads a Scan Run's Findings at the lock, asks PyPI which versions
exist and when each was uploaded, and writes `plan.json`: a pin for each package it may
move, and an escalation for each it may not. PyPI is `tests/fake_registry.py`'s, answered
by URL in the script's own process, so nothing here opens a socket.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fake_registry import FakePackageRegistry, pypi_answers

REPO = Path(__file__).resolve().parent.parent
HEAL = REPO / "scripts" / "heal.py"
LOCK = "requirements-checkov.txt"
NOW = "2026-10-21T06:41:00Z"


def _finding(package: str, version: str, fixed: str, *, rule: str = "CVE-2026-0001",
             path: str = LOCK, **more) -> dict:
    return {"rule": rule, "path": path, "fingerprint": f"fp-{rule}-{package}",
            "severity": "high", "suppressed": None,
            "dependency": {"ecosystem": "pypi", "package": package, "version": version,
                           "fixed_version": fixed,
                           "advisory_published": "2026-10-19T12:00:00Z"}, **more}


def _plan(tmp_path: Path, monkeypatch, findings: list[dict], lock: str,
          projects: dict[str, dict[str, dict]]) -> tuple[subprocess.CompletedProcess[str], dict]:
    FakePackageRegistry(tmp_path / "registry", pypi_answers(projects)).install(monkeypatch)
    scan = tmp_path / "findings.json"
    scan.write_text(json.dumps({"schema": 1, "findings": findings}))
    (tmp_path / LOCK).write_text(lock)
    out = tmp_path / "plan.json"
    run = subprocess.run(
        [sys.executable, str(HEAL), "plan", "--findings", str(scan),
         "--lock", str(tmp_path / LOCK), "--now", NOW, "--out", str(out)],
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
                      "beta==1.0 \\\n    --hash=sha256:00\n", projects)

    assert run.returncode == 0, run.stderr
    assert plan["schema"] == 1 and plan["made"] == NOW and plan["lock"] == LOCK
    assert plan["pins"] == [{"package": "beta", "from": "1.0", "to": "1.2", "why": "fix",
                             "rule": "cooldown", "uploaded": "2026-10-11T00:00:00Z"}]
    assert plan["escalations"] == []
    assert [f["rule"] for f in plan["findings"]] == ["CVE-2026-0001"]
