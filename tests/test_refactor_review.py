"""What the review of the three refactors changed (task 28.1.1).

PRs #78, #80 and #81 each moved code behind goldens that held the *output* still.
An adversarial pass over the diffs found what goldens cannot see: a predicate
copied rather than shared, a renderer left in the module it was being moved out
of, a badge format that had already drifted between two surfaces, a dead table,
and a "frozen" result that was a view of the mutable bag it was copied from. Each
fix here is small; each test names the seam it holds.
"""

from __future__ import annotations

import inspect
import json

import pytest

from valvur import findings as _findings
from valvur import operations, provenance, results, staleness, summary
from valvur.api import ScanRun
from valvur.findings import Exploit, Finding


def _finding(**kw) -> Finding:
    base = dict(rule="valvur.test.rule", severity="high", title="A planted finding",
                path="src/app.py", line=12, evidence="", fingerprint="f" * 16,
                status="new", sources=("trivy",), rank=1)
    base.update(kw)
    return Finding(**base)


# ------------------------------------------------ #78: one staleness predicate

def test_the_verdicts_doubts_come_from_the_shared_staleness_predicates(monkeypatch):
    """`ScanRun.doubts` carried its own copy of `age > threshold` for the database
    and the index — the comparison `staleness.py` was created to hold once. Two
    copies of a predicate agree until one is edited; then `run.json`'s `stale`
    flag and the verdict's `status_reason` describe the same run differently,
    which is the disagreement 22.D.4 removed. Held by patching the shared
    predicate: if `doubts` consulted its own copy, the patch would not reach it."""
    monkeypatch.setattr(staleness, "db_is_stale", lambda run: True)
    monkeypatch.setattr(staleness, "index_is_stale", lambda run: False)

    doubts = ScanRun(findings=[], profile="offline", db_age_days=1.0).doubts

    assert any("vulnerability database" in d for d in doubts), doubts
    assert not any("package-name index" in d for d in doubts)


def test_staleness_imports_the_cache_module_once_at_the_top():
    """Both predicates imported `cache` inside the function body, which reads as a
    cycle being dodged; `cache.py` imports nothing of valvur's, so there was none
    to dodge. A lazy import that guards nothing is one the next reader preserves."""
    assert "from . import cache" not in inspect.getsource(staleness.db_is_stale)
    assert "from . import cache" not in inspect.getsource(staleness.index_is_stale)


# ---------------------------------------------- #78: run.json is not a writer's job

def test_run_json_is_rendered_by_provenance_and_written_by_results():
    """27.3.3 moved `SUMMARY.md`'s renderer out of `results.py` so that module
    would be the atomic write and nothing else — and left `run.json`'s renderer,
    a hundred and twenty lines, inside it. `provenance.py` is where the record's
    shape lives (`ScannerRun`); its document renders there now."""
    run = ScanRun(findings=[_finding()], profile="offline", db_age_days=9.0)

    document = json.loads(provenance.render(run))

    assert document["schema"] == 1 and document["findings"]["active"] == 1
    assert not hasattr(results, "_provenance"), "the renderer is still in the writer"
    assert not hasattr(results, "_round_or_none")


# ------------------------------------------------- #78: one exploit badge, two marks

@pytest.mark.parametrize("exploit,badge", [
    (Exploit(kev=True, ransomware=True), "KEV·RANSOMWARE"),
    (Exploit(kev=True), "KEV"),
    (Exploit(epss=0.42), "EPSS 42%"),
    (Exploit(epss=0.09), ""),
    (Exploit(), ""),
])
def test_the_exploit_badge_is_one_decision_both_surfaces_render(exploit, badge):
    """`summary._one_line` (Markdown, for `SUMMARY.md`) and `operations._one_line`
    (plain text, for the CLI and MCP reply) each decided KEV / ransomware / EPSS
    on their own, and the EPSS threshold lived in both. The *mark* differs by
    surface on purpose — bold in Markdown, brackets in text — the decision does
    not, and it is `findings.exploit_badge` now."""
    assert _findings.exploit_badge(exploit) == badge

    finding = _finding(exploit=exploit)
    as_markdown = summary._one_line(finding)
    as_text = operations._one_line({
        "rank": 1, "status": "new", "path": "src/app.py", "line": 12,
        "title": "A planted finding", "rule": "valvur.test.rule", "fingerprint": "f" * 16,
        "exploit": {"kev": exploit.kev, "ransomware": exploit.ransomware, "epss": exploit.epss},
    })
    if badge:
        assert f"**[{badge}]**" in as_markdown
        assert f"[{badge}]" in as_text
    else:
        assert "[" not in as_markdown.split("_(")[0].replace("`", "")
        assert "[new]" in as_text and "KEV" not in as_text and "EPSS" not in as_text


# --------------------------------------------- #80: excluded paths are carried, not copied

def test_excluded_paths_are_carried_as_the_pipeline_recorded_them():
    """`api` rebuilt a list from the tuple the pipeline had already frozen, to
    satisfy an annotation; the one transformation on the way into `ScanRun` that
    meant nothing. It is a tuple end to end now."""
    assert ScanRun(findings=[], profile="offline").excluded_paths == ()
    run = ScanRun(findings=[], profile="offline", excluded_paths=("vendor", "tests/fixtures"))
    assert json.loads(provenance.render(run))["excluded_by_config"]["paths"] == [
        "vendor", "tests/fixtures",
    ]
