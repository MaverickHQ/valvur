"""R43.3 (D81b): a dependency advisory younger than the healing window is `healing`, not
blocking (N4.6).

The nightly judged a frozen tree against a database that moves every day, so every new
advisory in the Checkov lock turned it red before anything could have fixed it (#234).
A repository may set `healing_window_hours`; `6-self` sets 48. Only a dependency
vulnerability with a readable publication date younger than the window, and not a
`MAL-` entry, is healing. Missing data never widens the window. Judged on Results
Folders written by the test.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCANNED = datetime(2026, 10, 21, 6, 0, tzinfo=UTC)
WINDOW = {"run": {"complete": True, "healing_window_hours": 48}}


def _acceptance():
    spec = importlib.util.spec_from_file_location("acceptance", REPO / "scripts" / "acceptance.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _vuln(rule: str, published: str, *, severity: str = "high", aliases=()) -> dict:
    return {"rule": rule, "path": "requirements-checkov.txt", "severity": severity,
            "aliases": list(aliases),
            "dependency": {"ecosystem": "pip", "package": "aiohttp", "version": "3.14.3",
                           "fixed_version": "3.14.4", "advisory_published": published}}


def _results(tmp_path: Path, *findings: dict) -> Path:
    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "findings.json").write_text(json.dumps({"schema": 1, "findings": list(findings)}))
    (results / "run.json").write_text(json.dumps({"complete": True}))
    return results


def _judge(tmp_path, expected, *findings):
    return _acceptance().judge(_results(tmp_path, *findings), expected, "", scanned_at=SCANNED)


def test_an_advisory_published_an_hour_before_the_scan_is_healing(tmp_path):
    verdict = _judge(tmp_path, WINDOW, _vuln("CVE-2026-111064", "2026-10-21T05:00:00Z"))

    assert verdict.ok and verdict.blocking == []
    assert verdict.healing == ["CVE-2026-111064 at requirements-checkov.txt (high), 1 h old"]


def test_one_published_49_hours_before_blocks(tmp_path):
    verdict = _judge(tmp_path, WINDOW, _vuln("CVE-2026-111064", "2026-10-19T05:00:00Z"))

    assert not verdict.ok and verdict.healing == []
    assert verdict.blocking == ["CVE-2026-111064 at requirements-checkov.txt (high)"]


@pytest.mark.parametrize("published", ["", "soon", "2026-10-22T06:00:00Z"])
def test_one_with_no_date_an_unreadable_one_or_one_from_the_future_blocks(tmp_path, published):
    verdict = _judge(tmp_path, WINDOW, _vuln("CVE-2026-111064", published))

    assert not verdict.ok and len(verdict.blocking) == 1 and verdict.healing == []


@pytest.mark.parametrize(("rule", "aliases"), [
    ("MAL-2026-1234", ()), ("GHSA-xxxx-yyyy-zzzz", ("MAL-2026-1234",)),
    ("valvur.dependency.malicious", ())])
def test_a_malicious_package_blocks_however_young(tmp_path, rule, aliases):
    verdict = _judge(tmp_path, WINDOW, _vuln(rule, "2026-10-21T05:00:00Z", aliases=aliases))

    assert not verdict.ok and verdict.healing == []


@pytest.mark.parametrize("finding", [
    {"rule": "aws-access-token", "path": "config.py", "severity": "high"},
    {"rule": "valvur.llm.output-to-shell", "path": "app.py", "severity": "critical",
     "dependency": None},
])
def test_a_young_secret_or_static_analysis_finding_blocks(tmp_path, finding):
    verdict = _judge(tmp_path, WINDOW, finding)

    assert not verdict.ok and verdict.healing == []


def test_a_repository_without_the_key_is_judged_as_today(tmp_path):
    verdict = _judge(tmp_path, {"run": {"complete": True}},
                     _vuln("CVE-2026-111064", "2026-10-21T05:00:00Z"))

    assert not verdict.ok and verdict.healing == []


def test_the_report_has_a_healing_column_and_report_json_the_field(tmp_path):
    acceptance = _acceptance()
    verdict = _judge(tmp_path, WINDOW, _vuln("CVE-2026-111064", "2026-10-21T05:00:00Z"))
    result = acceptance.RepoResult("6-self", verdict, 1.0, 0)

    table = acceptance.render_markdown([result], {"platform": "test", "swap_gb": 0})
    header, _, row = table.splitlines()[2:5]
    columns = [c.strip() for c in header.strip("|").split("|")]
    cells = [c.strip() for c in row.strip("|").split("|")]

    assert cells[columns.index("healing")] == "1"
    assert acceptance.to_json([result], {})["repositories"][0]["healing"] == verdict.healing


def test_6_self_sets_a_48_hour_window(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "acceptance_generate", REPO / "scripts" / "acceptance" / "generate.py")
    generate = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_generate"] = generate
    spec.loader.exec_module(generate)  # type: ignore[union-attr]
    root = tmp_path / "6-self"

    generate.self_at_release(root)

    run = tomllib.loads((root / "expected.toml").read_text())["run"]
    assert run["healing_window_hours"] == 48
    others = [generate.lockfiles, generate.malicious_dependency]
    for builder in others:
        other = tmp_path / builder.__name__
        other.mkdir()
        builder(other)
        assert "healing_window_hours" not in (other / "expected.toml").read_text()
