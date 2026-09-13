"""Task 23.3.4 — the `scan_status` an agent reads when a scan is done.

Two defects from the Kiro run (22.G.1): a failure reason cut at 80 characters —
*"…no package-name index for PyPI, so"* — which is the one sentence the agent
needed whole; and a DONE response that named nothing to do next, so the agent
never called `explain_finding`, because nothing pointed at it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur.operations import scan_status


def _results(tmp_path: Path, *, scanners=None, findings=None, remediation=None,
             status="findings", active=None) -> Path:
    results = tmp_path / ".security-scan"
    results.mkdir(exist_ok=True)
    findings = findings if findings is not None else []
    from valvur.coverage import NOTE_RULES

    real = [f for f in findings if not f.get("suppressed") and f["rule"] not in NOTE_RULES]
    (results / "run.json").write_text(json.dumps({
        "status": status, "complete": all(s["ok"] for s in scanners or []),
        "profile": "offline",
        "findings": {"active": active if active is not None else len(real),
                     "suppressed": 0, "not_covered": 0},
        "scanners": scanners or [{"tool": "gitleaks", "ok": True, "reason": ""}],
        "network": {"what_left_the_machine": "nothing"},
    }))
    (results / "findings.json").write_text(json.dumps({"findings": findings}))
    if remediation is not None:
        (results / "REMEDIATION.md").write_text(remediation)
    return results


def _finding(rank: int, *, rule="valvur.ai-artifact.hidden-unicode", suppressed=None,
             fingerprint=None, title="Hidden Unicode in an agent instruction file"):
    return {"rank": rank, "status": "new", "path": "AGENTS.md", "line": 5, "title": title,
            "rule": rule, "fingerprint": fingerprint or f"{rank:032x}", "suppressed": suppressed}


REMEDIATION = """# Remediation proposal

> **This is a proposal, not a script.**

**3 action(s)** resolve **7 finding(s)**.

## 1. Review the agent instruction file `AGENTS.md` **[known exploited]**

Resolves 2 finding(s) in `AGENTS.md`:

## 2. Upgrade urllib3 to 2.5.0
"""


# --------------------------------------------------------- reasons stay whole


def test_a_failure_reason_is_never_cut_mid_sentence(tmp_path):
    reason = ("Package-name index not present, so dependency existence cannot be checked "
              "offline. There is no package-name index for PyPI, so nothing here can say "
              "whether 'reqeusts' exists.")
    _results(tmp_path, scanners=[{"tool": "dependency-reality", "ok": False, "reason": reason}])

    text = scan_status({"workspace": str(tmp_path)})

    assert reason in text
    assert "…" not in text.split("Scanners:")[1].split("\n\n")[0]


def test_a_multi_line_reason_is_shown_line_by_line_and_bounded_by_lines(tmp_path):
    """Bound the number of lines, never the sentence: eight lines of a runtime's
    stderr show six, and say where the rest is."""
    reason = "\n".join(f"line {n} of the runtime's own words" for n in range(1, 9))
    _results(tmp_path, scanners=[{"tool": "trivy", "ok": False, "reason": reason}])

    text = scan_status({"workspace": str(tmp_path)})

    assert "  trivy: FAILED — line 1 of the runtime's own words\n" in text
    assert "         line 6 of the runtime's own words\n" in text
    assert "line 7 of" not in text
    assert "         … 2 more line(s) in run.json" in text


def test_a_short_multi_line_reason_is_shown_whole(tmp_path):
    reason = "Trivy vulnerability database not present. Fetch it once with:\n  valvur update"
    _results(tmp_path, scanners=[{"tool": "trivy", "ok": False, "reason": reason}])

    text = scan_status({"workspace": str(tmp_path)})

    assert ("  trivy: FAILED — Trivy vulnerability database not present. Fetch it once "
            "with:\n") in text
    assert "           valvur update\n" in text
    assert "more line(s)" not in text


# ------------------------------------------------------- the next two moves


def test_a_finished_scan_names_the_next_two_moves(tmp_path):
    _results(tmp_path, findings=[_finding(1, fingerprint="e935cb10996c49025c111e34449e4a5d")],
             remediation=REMEDIATION)

    text = scan_status({"workspace": str(tmp_path)})

    assert "\nNext:\n" in text
    assert ("  explain_finding e935cb10996c49025c111e34449e4a5d — #1 AGENTS.md:5 Hidden "
            "Unicode in an agent instruction file") in text
    assert ("  REMEDIATION.md, action 1 of 3: Review the agent instruction file `AGENTS.md` "
            "[known exploited]") in text


def test_the_top_item_is_the_highest_ranked_active_finding(tmp_path):
    """Not a suppressed one (a decision already recorded) and not a coverage note
    (valvur's own gap): the same rule that makes a status `findings` (19.C.1)."""
    _results(tmp_path, findings=[
        _finding(1, suppressed="accepted: test data"),
        _finding(2, rule="valvur.dependency.ecosystem-not-covered",
                 title="Pipfile was not read"),
        _finding(3, fingerprint="c" * 32, title="'reqeusts' does not exist on PyPI"),
    ], remediation=REMEDIATION)

    text = scan_status({"workspace": str(tmp_path)})

    assert "explain_finding " + "c" * 32 + " — #3 AGENTS.md:5 'reqeusts' does not exist" in text
    assert "explain_finding " + f"{1:032x}" not in text


def test_the_top_item_is_the_best_rank_not_the_first_listed(tmp_path):
    _results(tmp_path, remediation=REMEDIATION,
             findings=[_finding(2, fingerprint="b" * 32), _finding(1, fingerprint="a" * 32)])

    text = scan_status({"workspace": str(tmp_path)})

    assert "explain_finding " + "a" * 32 + " — #1 " in text
    assert "b" * 32 not in text


def test_a_scan_with_nothing_active_names_no_move(tmp_path):
    _results(tmp_path, status="clean", findings=[], remediation="# Remediation proposal\n\n"
             "No findings. Nothing to remediate.\n")

    text = scan_status({"workspace": str(tmp_path)})

    assert "Next:" not in text
    assert "explain_finding" not in text


def test_results_from_an_older_valvur_name_what_they_can(tmp_path):
    """No REMEDIATION.md, or one without numbered actions: the finding is still
    named; the action line is not invented."""
    _results(tmp_path, findings=[_finding(1)])

    text = scan_status({"workspace": str(tmp_path)})

    assert "explain_finding " + f"{1:032x}" in text
    assert "REMEDIATION.md" not in text.split("Next:")[1]

    _results(tmp_path, findings=[_finding(1)],
             remediation="# Remediation proposal\n\nNo numbered actions here.\n")

    text = scan_status({"workspace": str(tmp_path)})

    assert "explain_finding " + f"{1:032x}" in text
    assert "REMEDIATION.md" not in text.split("Next:")[1]


def test_the_next_moves_sit_before_the_scanner_list_and_after_the_verdict(tmp_path):
    _results(tmp_path, findings=[_finding(1)], remediation=REMEDIATION)

    text = scan_status({"workspace": str(tmp_path)})

    assert text.index("findings: 1 active") < text.index("Next:") < text.index("Scanners:")


@pytest.mark.parametrize("state", ["done", "absent"])
def test_the_done_response_carries_the_moves_too(tmp_path, monkeypatch, state):
    """Through the job (DONE in Ns) and without one — the same operation, the same
    lines, so an agent polling and an agent asking later read the same thing."""
    import time

    from valvur.mcp import jobs

    _results(tmp_path, findings=[_finding(1)], remediation=REMEDIATION)
    if state == "done":
        monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)
        jobs.start(tmp_path, "offline", lambda workspace, profile, progress: "done")
        time.sleep(0.2)

    text = scan_status({"workspace": str(tmp_path)})
    jobs.reset()

    assert ("DONE in" in text) == (state == "done")
    assert "\nNext:\n  explain_finding " in text
