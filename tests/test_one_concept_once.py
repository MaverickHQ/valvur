"""Every other concept, once (D52b to e): the active predicate, the network grant,
the project file and the File Set per scan, and the container's flags.

The review of 2026-10-03 (§3.3) found each modelled more than once: whether a
Finding counts in six places, whether a tool may use the network in four, the
project file parsed at seven call sites of one scan, and two flag builders.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "valvur"

#: The six places that decided, each its own way, whether a Finding counts.
ACTIVE_SITES = ("api", "summary", "remediation", "gate", "reply", "grouping")


def _calls(module: str) -> set[str]:
    tree = ast.parse((SRC / f"{module}.py").read_text(encoding="utf-8"))
    return {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}


def test_one_predicate_decides_that_a_finding_counts():
    from valvur import verdict
    from valvur.findings import Finding

    def finding(**kw) -> Finding:
        return Finding(**{"rule": "valvur.test.rule", "severity": "high", "title": "t", "line": 1,
                          "path": "a.py", "fingerprint": "f" * 16, **kw})

    assert verdict.active(finding())
    assert not verdict.active(finding(suppressed="accepted until 2099"))
    assert not verdict.active(finding(rule="valvur.dependency.ecosystem-not-covered"))
    # The same answer for a record read back from findings.json.
    assert verdict.active({"rule": "valvur.test.rule", "suppressed": None})
    assert not verdict.active({"rule": "valvur.test.rule", "suppressed": "until 2099"})
    assert not verdict.active({"rule": "valvur.licence.unidentified"})


def test_the_six_sites_call_it_and_none_decides_for_itself():
    """`remediation` asks the other half, whether a Finding is a note: a note is not
    an action, and its proposals have always covered every other Finding."""
    for module in ACTIVE_SITES:
        assert {"verdict.active", "verdict.note"} & _calls(module), module
    deciding = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name in ("verdict.py", "coverage.py"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Compare) and any(
                    isinstance(op, ast.In | ast.NotIn) for op in node.ops) and any(
                    ast.unparse(c).endswith("NOTE_RULES") for c in node.comparators):
                deciding.append(f"{path.relative_to(REPO)}:{node.lineno}")

    assert deciding == []
