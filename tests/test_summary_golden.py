"""`SUMMARY.md`, byte for byte, across the move out of `results.py` (task 27.3.3).

The rendering was three hundred lines inside the module whose job is the atomic
write (26.0.3) — two responsibilities, one file, no boundary. Extracting it is
worth nothing if the document changes on the way, and `SUMMARY.md` is the one
artifact an agent is *instructed* to read first, so "looks the same" is not the
standard. These goldens were generated from `results._summary` before the move
and are committed; the same runs must render the same bytes after it.

Regenerate deliberately, never to make a red test green:

    UPDATE_SUMMARY_GOLDEN=1 uv run pytest tests/test_summary_golden.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from valvur.api import ScanRun
from valvur.findings import Finding
from valvur.provenance import ScannerRun

GOLDEN = Path(__file__).parent / "fixtures" / "summary"
UPDATE = "UPDATE_SUMMARY_GOLDEN"


def _finding(**kw) -> Finding:
    # `rank` is 1 by default, never the dataclass's 0: a real run ranks every
    # Finding after the `rank` stage, so a golden rendered at rank 0 pins a line
    # no user sees and cannot notice a change to how ranks render (28.1.1).
    base = dict(
        rule="valvur.test.rule", severity="high", title="A planted finding",
        path="src/app.py", line=12, evidence="token = 'AKIA...'",
        fingerprint="f" * 16, status="new", sources=("gitleaks",), rank=1,
    )
    base.update(kw)
    return Finding(**base)


#: The generation id is a fresh uuid4 per Scan Run (26.0.3) — correct, and fatal
#: for a golden, so each case pins one. That the id REACHES the document is held
#: by `test_tier4_polish.py`; what is pinned here is everything around it.
_GENERATION = "00000000-0000-4000-8000-00000000000%d"

#: One run per shape the document has to render. Named for what it exercises,
#: because a golden nobody can explain is a golden nobody will maintain.
CASES: dict[str, ScanRun] = {
    "clean": ScanRun(findings=[], scanners=[ScannerRun("gitleaks", ok=True)],
                     profile="offline"),
    "one-failure": ScanRun(
        findings=[],
        scanners=[ScannerRun("gitleaks", ok=True),
                  ScannerRun("trivy", ok=False, reason="report unreadable: JSONDecodeError")],
        profile="offline"),
    "findings": ScanRun(
        findings=[_finding(),
                  _finding(rule="valvur.test.other", severity="medium", line=44,
                           fingerprint="a" * 16, title="Another one", rank=2)],
        scanners=[ScannerRun("gitleaks", ok=True, duration_s=1.5),
                  ScannerRun("checkov", ok=True, duration_s=41.2)],
        profile="full"),
    "skipped-scanner": ScanRun(
        findings=[],
        scanners=[ScannerRun("gitleaks", ok=True),
                  ScannerRun("checkov", ok=True, skipped="no infrastructure to analyse")],
        profile="offline"),
    # Past the cap, so the truncation and its footer are pinned too. Without this
    # case, lowering LINE_CAP left every golden unchanged — measured: the cap set
    # to 60 passed all four. F7.5 is the reason the document is readable at all on
    # a real project, so a golden set that cannot see it is not covering the file.
    # 29.0.3: the three shapes a failure record takes now, each with its cause —
    # the budget's cut beside the levers, a timeout stopped, a runtime kill.
    "budget-cut": ScanRun(
        findings=[],
        scanners=[ScannerRun("gitleaks", ok=True, duration_s=1.5),
                  ScannerRun("trivy", ok=False, duration_s=300.0,
                             reason="cut by the 300s budget after 300s"),
                  ScannerRun("checkov", ok=False,
                             reason="not started: the 300s budget was spent before its turn")],
        profile="offline", budget_s=300.0, budget_cut=["trivy", "checkov"]),
    "timed-out": ScanRun(
        findings=[],
        scanners=[ScannerRun("gitleaks", ok=True, duration_s=1.5),
                  ScannerRun("opengrep", ok=False, duration_s=600.0,
                             reason="timed out after 600s and was stopped — last stderr: "
                                    "scanning 40,000 files")],
        profile="offline"),
    "runtime-killed": ScanRun(
        findings=[],
        scanners=[ScannerRun("gitleaks", ok=True, duration_s=1.5),
                  ScannerRun("checkov", ok=False, duration_s=48.3,
                             reason="exit 137: killed by the runtime — the container's "
                                    "memory ceiling (2g) or the VM's")],
        profile="offline"),
    "capped": ScanRun(
        findings=[_finding(rule=f"valvur.test.rule{n:03d}", line=n, rank=n + 1,
                           fingerprint=f"{n:016x}", title=f"Planted finding {n}")
                  for n in range(300)],
        scanners=[ScannerRun("gitleaks", ok=True)],
        profile="offline"),
}


for _i, _name in enumerate(sorted(CASES), start=1):
    CASES[_name].generation = _GENERATION % _i


def _render(run: ScanRun) -> str:
    from valvur import summary

    return summary.render(run)


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_summary_renders_what_it_rendered_before_the_move(name):
    run = CASES[name]
    path = GOLDEN / f"{name}.md"
    rendered = _render(run)

    if os.environ.get(UPDATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        pytest.skip(f"regenerated {path.name}")

    assert path.is_file(), (
        f"no golden for {name!r}. Generate deliberately: {UPDATE}=1 uv run pytest "
        f"{Path(__file__).name}"
    )
    assert rendered == path.read_text(encoding="utf-8"), (
        f"SUMMARY.md changed for {name!r}. If that is intended, regenerate with "
        f"{UPDATE}=1; if it is not, the refactor moved more than code."
    )


def test_every_golden_finding_carries_a_rank_a_real_run_would_give_it():
    """The goldens were rendered with every Finding at the dataclass default,
    rank 0 — a prefix no real run produces — so a regression in how the leading
    number renders was invisible to all five. Each case ranks its Findings the
    way the `rank` stage does: from 1, distinct, dense."""
    for name, run in CASES.items():
        ranks = [f.rank for f in run.findings]
        assert ranks == list(range(1, len(ranks) + 1)), f"{name}: {ranks[:5]}"
    for path in GOLDEN.glob("*.md"):
        assert not any(line.startswith("0. ") for line in path.read_text().splitlines()), (
            f"{path.name} renders a rank-0 line"
        )
