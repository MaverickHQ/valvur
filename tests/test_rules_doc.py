"""R29.3 (D65b): `docs/RULES.md` gives every shipped rule its precision, measured.

`scripts/eval.py --rules-measured` records each rule's true and false positives on
tracks 1 and 2 and the corpus in `tests/eval/rules-measured.json`, and
`scripts/rules_doc.py` renders the page from it. A test holds the page current, so it
can never cite a measurement the repository does not hold.
"""

from __future__ import annotations

import importlib.util
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

