"""R29.3 (D65b): `docs/RULES.md` gives every shipped rule its precision, measured.

`scripts/eval.py --rules-measured` records each rule's true and false positives on
tracks 1 and 2 and the corpus in `tests/eval/rules-measured.json`, and
`scripts/rules_doc.py` renders the page from it. A test holds the page current, so it
can never cite a measurement the repository does not hold.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "rules_doc.py"
MEASURED = REPO / "tests" / "eval" / "rules-measured.json"
PAGE = REPO / "docs" / "RULES.md"


def _doc():
    spec = importlib.util.spec_from_file_location("rules_doc", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["rules_doc"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _row(tp=0, fp=0, new=0, *, vendored=False, inventory=False, demoted="",
         unjudged=0) -> dict:
    places = {"sast-python": {"tp": tp, "fp": 0, "outside": 0, "new": new, "unjudged": 0},
              "sast-js": {"tp": 0, "fp": 0, "outside": 0, "new": 0, "unjudged": 0},
              "corpus": {"tp": 0, "fp": fp, "outside": 0, "new": 0, "unjudged": unjudged}}
    return {"file": "rules/x.yaml", "vendored": vendored, "inventory": inventory,
            "demoted": demoted, "cwe": [22], "places": places, "tp": tp, "fp": fp,
            "new": new, "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0}


def _measured(**rows: dict) -> dict:
    return {"measured": "2026-10-08", "image": "sha256:abc", "corpus_projects": 48,
            "rules": {name.replace("_", "."): row for name, row in rows.items()}}


def _line(page: str, rule: str) -> str:
    return next(line for line in page.splitlines() if line.startswith(f"| `{rule}` |"))


def test_each_rule_has_its_counts_its_precision_and_its_state():
    page = _doc().render(_measured(
        valvur_a=_row(tp=9, fp=3),
        valvur_b=_row(),
        valvur_c=_row(tp=1, fp=2, inventory=True, unjudged=4,
                      demoted="R29.3: precision 0.333 over tracks 1, 2 and the corpus"),
        valvur_d=_row(inventory=True, unjudged=5),
        vendored_e=_row(tp=2, new=0, vendored=True)))

    assert _line(page, "valvur.a").endswith("| 9 / 0 | 0 / 0 | 0 / 3 | 0.75 | active |")
    # Nothing in the three places to measure it on: said so, never shown as perfect.
    assert _line(page, "valvur.b").endswith("| 0 / 0 | 0 / 0 | 0 / 0 | - | active, unmeasured |")
    assert "| 0 / 2, 4 unjudged | 0.333 | inventory: R29.3: precision 0.333" in \
        _line(page, "valvur.c")
    assert _line(page, "valvur.d").endswith("| inventory: a sink to review (D47a) |")
    # A vendored rule whose every true positive repeats one of valvur's own lines.
    assert _line(page, "vendored.e").endswith("| **under the bar** |")
    assert "48 real projects" in page and "sha256:abc" in page



def test_the_page_is_current_with_the_measurement():
    """Regenerate with `uv run python scripts/rules_doc.py` after `scripts/eval.py
    --tracks sast-python,sast-js,real-code-precision --rules-measured
    tests/eval/rules-measured.json`."""
    assert MEASURED.is_file(), "no measurement; run scripts/eval.py --rules-measured"
    assert PAGE.read_text(encoding="utf-8") == _doc().render(json.loads(MEASURED.read_text()))


def test_the_measurement_is_of_every_rule_as_it_ships():
    """A rule added, or moved to the inventory, after the measurement is not on the page
    as it ships: measure again."""
    import rule_precision  # type: ignore[import-not-found]  # rules_doc put it on the path

    _doc()
    measured = json.loads(MEASURED.read_text())["rules"]
    shipped = rule_precision.shipped(REPO / "rules")

    assert sorted(measured) == sorted(shipped)
    assert {rule: (row["inventory"], row["demoted"]) for rule, row in measured.items()} == \
        {rule: (meta["inventory"], meta["demoted"]) for rule, meta in shipped.items()}


def test_no_active_rule_is_under_the_bar():
    """D65b: a rule under D29's bar is moved to the inventory with its reason, as
    `demoted: "..."` beside `inventory: true` in its metadata, never dropped silently."""
    import rule_precision  # type: ignore[import-not-found]

    _doc()
    measured = json.loads(MEASURED.read_text())["rules"]

    assert [rule for rule, row in measured.items()
            if rule_precision.state(row) == "**under the bar**"] == []
