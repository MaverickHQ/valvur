"""A finding's CWE, for the Score's static-analysis tracks (ADR-0026, D21).

From the finding itself when it carries `cwe` (F5.10), else from the metadata of
its rule under `rules/`, else from its Scanner's class: a secret found in code is a
hard-coded credential, CWE-798. A child CWE also counts as its parent, so an eval
injection (95) answers a benchmark category named for code injection (94).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

#: CWE children the tracks' categories name by their parent.
PARENTS = {95: 94}
#: Scanners whose every finding is one class of weakness.
BY_SOURCE = {"gitleaks": 798}

_ID = re.compile(r"^  - id: (\S+)", re.M)
_CWE = re.compile(r"CWE-(\d+)")


def _numbers(values: object) -> set[int]:
    items = values if isinstance(values, list | tuple) else [values]
    return {int(n) for item in items for n in _CWE.findall(str(item))}


def rule_cwes(rules_dir: Path) -> dict[str, set[int]]:
    """Each rule's declared CWEs, read from its `metadata: cwe:` line."""
    found: dict[str, set[int]] = {}
    for path in sorted(rules_dir.rglob("*.yaml")):
        blocks = _ID.split(path.read_text(encoding="utf-8"))[1:]
        for rule, body in zip(blocks[::2], blocks[1::2], strict=True):
            line = re.search(r"^\s+cwe:(.*)$", body, re.M)
            if line:
                found[rule] = _numbers(line.group(1))
    return found


def lookup(rules_dir: Path) -> Callable[[dict], set[int]]:
    by_rule = rule_cwes(rules_dir)

    def cwe_of(finding: dict) -> set[int]:
        numbers = _numbers(finding["cwe"]) if finding.get("cwe") else \
            set(by_rule.get(str(finding.get("rule")), set()))
        if not numbers:
            numbers = {BY_SOURCE[s] for s in finding.get("sources") or () if s in BY_SOURCE}
        return numbers | {PARENTS[n] for n in numbers if n in PARENTS}

    return cwe_of
