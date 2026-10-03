"""Typed messages inside (D53): the engine's events carry a kind and fields; prose
is rendered only at a surface, and the reply reads kinds, never a prefix.

Until R23.7 the engine emitted structured events, `api` turned them into prose, and
the reply parsed the prose back by its first words (the review of 2026-10-03, §3.4).
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

from valvur import events

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"


def test_a_scan_says_events_with_kinds_and_fields(tmp_path):
    from valvur import api
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    ws = tmp_path / "ws"
    shutil.copytree(FIXTURES / "clean-repo", ws)
    said: list = []

    api.scan(ws, runner=LocalRuntime(FIXTURES / "fake-tools"), adapters=[GitleaksAdapter()],
             on_progress=said.append)

    assert all(isinstance(event, events.Event) for event in said), said
    kinds = [event.kind for event in said]
    assert {events.Kind.WORKSPACE, events.Kind.FLEET, events.Kind.SCANNER_STARTED,
            events.Kind.SCANNER_ENDED} <= set(kinds)
    [ended] = [e for e in said if e.kind is events.Kind.SCANNER_ENDED]
    assert (ended.fields["name"], ended.fields["ok"]) == ("gitleaks", True)
    assert str(ended).startswith("gitleaks: ok (")


def test_the_reply_reads_kinds_not_words():
    """A fetch is `now` by its kind whatever its words, and a note that happens to
    read like a fetch is not one."""
    from valvur import reply
    from valvur.mcp import jobs

    job = jobs.Job(workspace=Path("/w"), profile="offline", started=0.0)
    job.note(events.note("fetching nothing at all, only words"))
    fields = reply._progress(job, 1.0)
    assert fields["now"] is None
    job.note(events.fetch_started("database", age_days=None, size_mb=None))
    assert reply._progress(job, 1.0)["now"] == (
        "fetching the vulnerability database — the first run only")


def test_no_surface_or_read_model_classifies_progress_by_its_words():
    """The prefixes the reply and the CLI matched on are gone, and nothing reads
    a progress message's first words."""
    from valvur import api, levers

    for gone in ("FETCH_STARTED", "FETCH_ENDED"):
        assert not hasattr(api, gone), gone
    assert not hasattr(levers, "WORKSPACE_PREFIX")
    for name in ("reply.py", "cli.py", "mcp/handlers.py"):
        tree = ast.parse((REPO / "src" / "valvur" / name).read_text(encoding="utf-8"))
        prefixed = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and ast.unparse(n.func).endswith(("message.startswith", "message.partition"))]
        assert prefixed == [], name


def test_each_kind_renders_the_words_every_surface_has_shown():
    rendered = {
        events.fleet(3, 2): "fleet: 3 Scanners, 2 at a time",
        events.scanner_started("trivy"): "trivy: started",
        events.scanner_ended("trivy", ok=False, seconds=1.25): "trivy: failed (1.2s)",
        events.fetch_started("image", name="valvur:dev", size_mb=700, age_days=None):
            "pulling valvur:dev (700MB) — the first run only; the runtime keeps it",
        events.fetch_started("index", age_days=3.4, size_mb=36):
            "refreshing the package-name index (3 days old) (36MB)",
        events.fetch_ended("database", ok=False, detail="x509"): "database not fetched: x509",
        events.fetch_ended("osv", name="npm", ok=True, seconds=2.2):
            "OSV database fetched for npm (2s)",
        events.workspace(1234, [("src", 1000), (".", 10)]):
            "workspace: 1,234 files to scan; largest: src 1,000, . 10",
        events.budget(30.4, ["trivy"], []): "budget spent after 30s: stopping trivy; "
                                             "not starting nothing",
    }
    for event, words in rendered.items():
        assert str(event) == words, event


# ----------------------------------------------------------- the budget's state

def test_the_budgets_state_is_a_field_not_a_reasons_first_words():
    """What the budget cut, and what it never started, is said by a field on each
    Scanner's record; the refusal and its fields read that, whatever the reason's
    words (they used to match `cut by the ` and `not started: `)."""
    from valvur import levers
    from valvur.scanner_run import BUDGET_CUT, BUDGET_NOT_STARTED, ScannerRun

    scanners = [ScannerRun("trivy", ok=False, reason="stopped", duration_s=30.0,
                           budget=BUDGET_CUT),
                ScannerRun("checkov", ok=False, reason="waited", budget=BUDGET_NOT_STARTED),
                ScannerRun("gitleaks", ok=False, reason="cut by the 5s budget, it says")]

    fields = levers.budget_fields(scanners, 30.0)

    assert fields["cut"] == {"trivy": 30.0} and fields["not_started"] == ["checkov"]


def test_a_budget_cut_scan_records_the_state_on_each_scanner(tmp_path):
    from test_budget import _Adapter, _Runner

    from valvur import api
    from valvur.scanner_run import BUDGET_CUT

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.py").write_text("x = 1\n")
    run = api.scan(ws, runner=_Runner(), adapters=[_Adapter("fast", 0.05),
                                                   _Adapter("slow", 30.0)], budget_s=1.5)

    by_tool = {s.tool: s for s in run.scanners}
    assert by_tool["slow"].budget == BUDGET_CUT and by_tool["fast"].budget == ""
