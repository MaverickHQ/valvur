"""Task 23.3.5 — `valvur gate` and `valvur cache`.

`gate`: one exit code from `run.json` and `findings.json`, replacing the Python
heredoc that `ci.yml` and `release.yml` each carried a copy of — and the first thing
a team adopting valvur in CI asks for. `cache`: what is cached, how old, how large,
and `--clear`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import write_name_index

from valvur import cache, gate

# ------------------------------------------------------------------ fixtures


def _finding(severity="high", *, rule="CVE-2024-0001", suppressed=None, path="app.py",
             title="urllib3 1.24.1 is vulnerable"):
    return {"severity": severity, "rule": rule, "path": path, "title": title,
            "suppressed": suppressed, "fingerprint": "f" * 32}


def _results(tmp_path: Path, *, findings=(), status="findings", complete=True,
             status_reason="", failed_tool=None) -> Path:
    results = tmp_path / ".security-scan"
    results.mkdir(exist_ok=True)
    scanners = [{"tool": "gitleaks", "ok": True, "reason": ""}]
    if failed_tool:
        scanners.append({"tool": failed_tool, "ok": False, "reason": "exited 1 with no report"})
    (results / "run.json").write_text(json.dumps({
        "status": status, "complete": complete, "status_reason": status_reason,
        "scanners": scanners, "excluded_by_config": {"paths": [], "findings_dropped": 0},
    }))
    (results / "findings.json").write_text(json.dumps({"findings": list(findings)}))
    return results


# ---------------------------------------------------------------------- gate


def test_a_complete_clean_run_passes(tmp_path):
    _results(tmp_path, status="clean")

    verdict = gate.evaluate(tmp_path, fail_on="high", no_inconclusive=True)

    assert verdict.passed and verdict.failures == []
    assert verdict.exit_code == 0


def test_a_finding_at_or_above_the_threshold_fails_and_below_it_does_not(tmp_path):
    _results(tmp_path, findings=[_finding("high")])

    assert not gate.evaluate(tmp_path, fail_on="high").passed
    assert not gate.evaluate(tmp_path, fail_on="medium").passed
    assert gate.evaluate(tmp_path, fail_on="critical").passed

    [line] = gate.evaluate(tmp_path, fail_on="high").failures
    assert line == "high: CVE-2024-0001 in app.py — urllib3 1.24.1 is vulnerable"


def test_any_fails_on_the_lowest_severity(tmp_path):
    _results(tmp_path, findings=[_finding("low", rule="valvur.pinning.mutable-action-ref")])

    assert not gate.evaluate(tmp_path, fail_on="any").passed
    assert gate.evaluate(tmp_path, fail_on="low").passed is False
    assert gate.evaluate(tmp_path, fail_on="medium").passed


def test_a_suppressed_finding_never_fails_but_a_lapsed_suppression_always_does(tmp_path):
    """A suppression is a decision the project recorded; an expired one re-reports
    the finding, and if nothing fails the build then "mandatory expiry" is
    decoration — so it fails at every threshold, N2.5's own rule."""
    _results(tmp_path, findings=[
        _finding("critical", suppressed="accepted until 2026-12-01: test data"),
        _finding("medium", rule="valvur.suppression.expired",
                 title="suppression of CVE-2023-1 expired on 2026-01-01"),
    ])

    verdict = gate.evaluate(tmp_path, fail_on="critical")

    assert not verdict.passed
    assert verdict.failures == [
        "medium: valvur.suppression.expired in app.py — suppression of CVE-2023-1 expired "
        "on 2026-01-01 (a lapsed suppression fails at every threshold)"]


def test_a_coverage_note_is_not_a_finding_but_makes_the_run_inconclusive(tmp_path):
    """19.C.1: a coverage note is valvur's missing feature, not the user's problem,
    so `--fail-on any` ignores it — and `--no-inconclusive` is how a team says the
    gap itself must not pass."""
    _results(tmp_path, status="inconclusive",
             status_reason="nothing was found, and that is not evidence: not inspected — "
                           "npm dependencies: existence",
             findings=[_finding("info", rule="valvur.dependency.ecosystem-not-covered",
                                title="npm dependencies were not checked for existence")])

    assert gate.evaluate(tmp_path, fail_on="any").passed
    verdict = gate.evaluate(tmp_path, fail_on="any", no_inconclusive=True)
    assert not verdict.passed
    assert verdict.failures == ["inconclusive: nothing was found, and that is not evidence: "
                                "not inspected — npm dependencies: existence"]


def test_an_incomplete_run_fails_at_every_threshold_naming_the_scanner(tmp_path):
    _results(tmp_path, status="clean", complete=False, failed_tool="trivy")

    verdict = gate.evaluate(tmp_path, fail_on="critical")

    assert not verdict.passed
    assert verdict.failures == ["incomplete: trivy did not complete (exited 1 with no report), "
                                "so this result proves nothing"]


def test_no_results_is_its_own_exit_code(tmp_path):
    verdict = gate.evaluate(tmp_path, fail_on="high")

    assert verdict.exit_code == 2
    assert "valvur scan" in verdict.failures[0]


def test_the_report_counts_what_it_let_through(tmp_path):
    _results(tmp_path, findings=[_finding("high"), _finding("low"),
                                 _finding("critical", suppressed="accepted")])

    verdict = gate.evaluate(tmp_path, fail_on="high")

    assert verdict.summary == ("gate: 1 finding(s) at or above high; 1 below the threshold; "
                               "1 suppressed; 0 excluded by .security-scan.toml")


def test_the_cli_prints_the_failures_and_exits_with_the_verdict(tmp_path, capsys, monkeypatch):
    from valvur import cli

    _results(tmp_path, findings=[_finding("high")])
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    assert cli.main(["gate", str(tmp_path), "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "high: CVE-2024-0001 in app.py — urllib3 1.24.1 is vulnerable" in out
    assert "gate: FAILED" in out

    assert cli.main(["gate", str(tmp_path), "--fail-on", "critical"]) == 0
    assert "gate: passed" in capsys.readouterr().out

    assert cli.main(["gate", str(tmp_path / "nowhere")]) == 2


def test_under_github_actions_each_failure_is_an_annotation(tmp_path, capsys, monkeypatch):
    from valvur import cli

    _results(tmp_path, findings=[_finding("high")])
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    cli.main(["gate", str(tmp_path), "--fail-on", "high"])

    assert "::error::high: CVE-2024-0001 in app.py" in capsys.readouterr().out


def test_the_default_threshold_is_high_and_inconclusive_passes_unless_asked(tmp_path):
    _results(tmp_path, status="inconclusive", status_reason="stale", findings=[_finding("medium")])

    assert gate.evaluate(tmp_path).passed
    assert not gate.evaluate(tmp_path, no_inconclusive=True).passed


def test_the_workflows_use_the_gate_rather_than_a_heredoc():
    """The two copies of the gate that ci.yml and release.yml carried are gone;
    the self-scan step is one command, the same one a user runs."""
    for name in ("ci.yml", "release.yml"):
        text = Path(".github/workflows", name).read_text()
        assert "valvur gate . --fail-on any --no-inconclusive" in text, name
        selfscan = text.split("valvur gate")[0].rsplit("valvur scan . --profile full", 1)[-1]
        assert "json.loads" not in selfscan, f"{name} still gates by heredoc"


# --------------------------------------------------------------------- cache


@pytest.fixture
def host_cache(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    monkeypatch.setattr(cache, "root", lambda: root)
    monkeypatch.setattr(cache, "trivy_db", lambda: root / "trivy")
    monkeypatch.setattr(cache, "name_index", lambda: root / "names")
    return root


def _fill(root: Path) -> None:
    db = root / "trivy" / "db"
    db.mkdir(parents=True)
    (db / "trivy.db").write_bytes(b"x" * 3_000_000)
    now = datetime.now(UTC)
    (db / "metadata.json").write_text(json.dumps({
        "UpdatedAt": (now - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")}))
    write_name_index(root / "names", pip=["requests", "flask"], npm=["react"], gem=["rack"],
                     composer=["monolog/monolog"], cargo=["serde"])
    (root / "kev.json").write_text('{"entries": {}, "count": 1500}')
    (root / ".lock").write_bytes(b"")


def test_the_inventory_says_what_is_cached_how_old_and_how_large(host_cache):
    _fill(host_cache)

    entries = {e.name: e for e in cache.inventory()}

    assert entries["database"].present and entries["database"].size >= 3_000_000
    assert entries["database"].age_days is not None and 1.9 < entries["database"].age_days < 2.1
    assert entries["index"].present and "pip 2" in entries["index"].detail
    assert entries["index"].detail.endswith("cargo 1")
    assert entries["kev"].present and entries["kev"].size > 0
    assert [e.name for e in cache.inventory()] == ["database", "index", "kev"]


def test_an_empty_cache_is_described_not_invented(host_cache):
    entries = cache.inventory()

    assert all(not e.present and e.size == 0 and e.age_days is None for e in entries)


def test_clear_removes_the_data_and_keeps_the_directory_and_the_lock(host_cache):
    _fill(host_cache)

    removed = cache.clear()

    assert removed == ["database", "index", "kev"]
    assert sorted(p.name for p in host_cache.iterdir()) == [".lock"]
    assert cache.clear() == []


def test_clear_waits_for_readers_by_taking_the_exclusive_lock(host_cache, monkeypatch):
    """A scan holds the cache lock shared while it reads the database (16.3); a
    clear that ran underneath it would pull trivy.db out from under Trivy."""
    from valvur import locking

    _fill(host_cache)
    taken: list[tuple[bool, bool]] = []
    real = locking.held

    def recording(path, *, exclusive=True, wait=True, busy_message=""):
        taken.append((exclusive, wait))
        return real(path, exclusive=exclusive, wait=wait, busy_message=busy_message)

    monkeypatch.setattr(locking, "held", recording)

    cache.clear()

    assert taken == [(True, True)]


def test_the_cli_lists_the_cache_and_clears_it_on_request(host_cache, capsys):
    from valvur import cli

    _fill(host_cache)

    assert cli.main(["cache"]) == 0
    out = capsys.readouterr().out
    assert str(host_cache) in out
    assert "database" in out and "2.0 days old" in out and "MB" in out
    assert "index" in out and "pip 2" in out
    assert "kev" in out
    assert "total" in out

    assert cli.main(["cache", "--clear"]) == 0
    out = capsys.readouterr().out
    assert "cleared: database, index, kev" in out
    assert "valvur update" in out

    assert cli.main(["cache"]) == 0
    assert "absent" in capsys.readouterr().out


def test_sizes_are_human():
    assert cache.human_size(0) == "0 B"
    assert cache.human_size(900) == "900 B"
    assert cache.human_size(3_000_000) == "3.0 MB"
    assert cache.human_size(1_350_000_000) == "1.35 GB"
