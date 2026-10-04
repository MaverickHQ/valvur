"""The tenth of the corpus's labels the owner audits (R29.2, D65a).

    python3 scripts/audit_sample.py

A random tenth, rounded up, of `tests/eval/labels/corpus.toml`, drawn with a fixed seed
so the owner and the executor read the same list. A disagreement changes the label,
and the change is recorded in the label's reason. Standard library only.
"""

from __future__ import annotations

import math
import random
import tomllib
from pathlib import Path

LABELS = Path(__file__).resolve().parent.parent / "tests" / "eval" / "labels" / "corpus.toml"
#: The day the corpus widened; the same seed always draws the same tenth.
SEED = 20261004


def sample(labels: list[dict], seed: int = SEED) -> list[dict]:
    ordered = sorted(labels, key=lambda label: (label["repo"], label["fingerprint"]))
    # Reproducible on purpose: the owner and the executor must draw the same tenth.
    return random.Random(seed).sample(ordered, math.ceil(len(ordered) / 10))  # noqa: S311


def main() -> int:
    for label in sample(tomllib.loads(LABELS.read_text(encoding="utf-8"))["label"]):
        print(f"{label['repo']}\t{label['rule']}\t{label['path']}\t{label['verdict']}\t"
              f"{label['fingerprint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
