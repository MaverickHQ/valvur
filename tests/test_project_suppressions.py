"""R38.4: an ignore is a suppression only with a reason and an expiry (D77c).

A project's ignore that states why and until when is an accepted risk, like a
suppression in `.security-scan.toml`: reported, suppressed, and back once it lapses,
which fails the gate. One without either stays active, named by `ignored_by`, since
an ignore nobody has to revisit is how a finding gets buried for good. `SUMMARY.md`
lists both kinds.
"""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

from project_ignores import OSV_IGNORED, build

from valvur import artifacts, gate, summary
from valvur import fingerprint as _fp
from valvur import project_ignores as _ignores
from valvur.api import ScanRun
from valvur.findings import Finding

ROOT = Path(__file__).resolve().parent.parent
TODAY = date(2026, 10, 4)


def _osv(rule: str = "CVE-2019-11236", aliases=(OSV_IGNORED,), path="requirements.txt"):
    return Finding(rule=rule, path=path, line=0, title=rule, sources=("osv-scanner",),
                   aliases=aliases, fingerprint=_fp.derive(rule, path))


def _project(tmp_path, until: str | None, reason: str = "measured by R38.4") -> Path:
    ws = build(tmp_path / "project")
    (ws / "osv-scanner.toml").write_text(
        f'[[IgnoredVulns]]\nid = "{OSV_IGNORED}"\n'
        + (f'reason = "{reason}"\n' if reason else "")
        + (f"ignoreUntil = {until}\n" if until else ""))
    return ws


def _decided(ws: Path, findings: list[Finding], today: date = TODAY) -> list[Finding]:
    return _ignores.accept(_ignores.mark(ws, findings), today=today)


def test_an_ignore_with_a_reason_and_an_expiry_suppresses(tmp_path):
    ws = _project(tmp_path, "2027-01-31T00:00:00Z")

    [finding] = _decided(ws, [_osv()])

    assert finding.suppressed and "measured by R38.4" in finding.suppressed
    assert "2027-01-31" in finding.suppressed and "osv-scanner.toml" in finding.suppressed
    [result] = json.loads(artifacts.sarif([finding], version="1.5.0"))["runs"][0]["results"]
    assert [(s["kind"], s["status"]) for s in result["suppressions"]] == [
        ("external", "accepted")]


def test_an_expiry_is_inclusive_as_a_suppression_s_is(tmp_path):
    ws = _project(tmp_path, "2026-10-04T00:00:00Z")

    [finding] = _decided(ws, [_osv()])

    assert finding.suppressed


def test_a_lapsed_ignore_reports_its_finding_again_and_fails_the_gate(tmp_path):
    ws = _project(tmp_path, "2026-10-01T00:00:00Z")

    decided = _decided(ws, [_osv()])

    [finding] = [f for f in decided if f.rule == "CVE-2019-11236"]
    assert not finding.suppressed and finding.ignored_by.expires == "2026-10-01"
    [lapsed] = [f for f in decided if f.rule != "CVE-2019-11236"]
    assert lapsed.rule in gate.SUPPRESSION_RULES
    assert lapsed.path == "osv-scanner.toml"
    assert "2026-10-01" in lapsed.title and "CVE-2019-11236" in lapsed.title

    results = ws / ".security-scan"
    results.mkdir()
    (results / "run.json").write_text(json.dumps({"status": "findings", "complete": True}))
    (results / "findings.json").write_text(
        artifacts.findings_json([f for f in decided if f is not finding], status="findings",
                                complete=True))
    verdict = gate.evaluate(ws, fail_on="critical")
    assert any("osv-scanner.toml" in line for line in verdict.failures), verdict


def test_a_lapsed_ignore_s_identity_is_stable_and_its_own(tmp_path):
    ws = _project(tmp_path, "2026-10-01T00:00:00Z")

    first = [f for f in _decided(ws, [_osv()]) if f.rule in gate.SUPPRESSION_RULES]
    again = [f for f in _decided(ws, [_osv()]) if f.rule in gate.SUPPRESSION_RULES]
    other = [f for f in _decided(ws, [_osv("CVE-2019-99999")])
             if f.rule in gate.SUPPRESSION_RULES]

    assert first[0].fingerprint == again[0].fingerprint != other[0].fingerprint


def test_an_ignore_without_an_expiry_leaves_its_finding_active_and_marked(tmp_path):
    ws = _project(tmp_path, None)

    [finding] = _decided(ws, [_osv()])

    assert not finding.suppressed
    assert finding.ignored_by.ignore == "osv-scanner.toml"
    assert finding.ignored_by.reason == "measured by R38.4"


def test_an_ignore_without_a_reason_leaves_its_finding_active_and_marked(tmp_path):
    """A `.trivyignore` entry can say when (`exp:`) but never why."""
    ws = build(tmp_path / "project")
    (ws / ".trivyignore").write_text("CVE-2019-11324 exp:2027-01-31\n")
    trivy = Finding(rule="CVE-2019-11324", path="requirements.txt", line=0, title="t",
                    sources=("trivy",), fingerprint=_fp.derive("trivy"))

    [finding] = _decided(ws, [trivy])

    assert not finding.suppressed and finding.ignored_by.expires == "2027-01-31"


def test_a_suppression_in_security_scan_toml_is_left_as_it_was():
    already = Finding(rule="r", path="p", line=0, title="t", fingerprint="f" * 32,
                      suppressed="r at p (expires 2027-01-01)",
                      ignored_by=_ignores.IgnoredBy("nosemgrep", "p:1", "# nosemgrep",
                                                    "inSource"))

    assert _ignores.accept([already], today=TODAY) == [already]


def test_summary_lists_the_accepted_and_the_merely_ignored(tmp_path):
    accepted_ws = _project(tmp_path / "a", "2027-01-31T00:00:00Z")
    open_ws = _project(tmp_path / "b", None)
    [accepted] = _decided(accepted_ws, [_osv()])
    [ignored] = _decided(open_ws, [_osv("CVE-2019-11324", path="sub/requirements.txt",
                                        aliases=(OSV_IGNORED,))])

    text = summary.render(ScanRun(findings=[accepted, ignored]))

    suppressed = text.split("## Suppressed (1)", 1)[1].split("\n## ", 1)[0]
    assert "CVE-2019-11236" in suppressed and "measured by R38.4" in suppressed
    assert "osv-scanner.toml" in suppressed.split("_", 2)[1], "the caption names the source"
    ignoring = text.split("## Ignored by the project, not accepted (1)", 1)[1]
    ignoring = ignoring.split("\n## ", 1)[0]
    assert "CVE-2019-11324" in ignoring and "osv-scanner.toml" in ignoring
    assert "reason" in ignoring and "expiry" in ignoring


def test_valvur_s_own_accepted_checkov_advisory_stays_suppressed(tmp_path):
    """The one ignore valvur's repository carries (R27.2): python-ecdsa's advisory,
    reached through Checkov, accepted with a reason and a review date."""
    ws = tmp_path / "valvur"
    ws.mkdir()
    shutil.copy(ROOT / "osv-scanner.toml", ws / "osv-scanner.toml")
    shutil.copy(ROOT / "requirements-checkov.txt", ws / "requirements-checkov.txt")
    advisory = Finding(rule="CVE-2024-23342", path="requirements-checkov.txt", line=0,
                       title="ecdsa", sources=("trivy", "osv-scanner"),
                       aliases=("GHSA-wj6h-64fc-37mp", "PYSEC-2026-1325"),
                       fingerprint=_fp.derive("ecdsa"))

    [finding] = _decided(ws, [advisory])

    assert finding.suppressed and "2027-09-14" in finding.suppressed
    assert "python-ecdsa" in finding.suppressed


def test_the_scan_s_suppress_stage_accepts_them(tmp_path):
    """Applied where `.security-scan.toml`'s suppressions are, so the ranking, the
    verdict and every artifact downstream see the same decision."""
    from valvur import pipeline

    ws = _project(tmp_path, "2026-10-01T00:00:00Z")
    ctx = pipeline.Context(workspace=ws, profile="offline", network=False, declaring=[])

    found = pipeline.suppress(pipeline.own_ignores([_osv()], ctx), ctx)

    assert [f.rule for f in found] == ["CVE-2019-11236", "valvur.suppression.expired"]
