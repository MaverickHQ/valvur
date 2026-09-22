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
    base = dict(
        rule="valvur.test.rule", severity="high", title="A planted finding",
        path="src/app.py", line=12, evidence="token = 'AKIA...'",
        fingerprint="f" * 16, status="new", sources=("gitleaks",),
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
                           fingerprint="a" * 16, title="Another one")],
        scanners=[ScannerRun("gitleaks", ok=True, duration_s=1.5),
                  ScannerRun("checkov", ok=True, duration_s=41.2)],
        profile="full"),
    "skipped-scanner": ScanRun(
        findings=[],
        scanners=[ScannerRun("gitleaks", ok=True),
                  ScannerRun("checkov", ok=True, skipped="no infrastructure to analyse")],
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
