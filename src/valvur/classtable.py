"""What a path's class changes about a Finding (D56; D47b, c): one table.

A secret where tests, fixtures, docs and examples live ranks `low` and stays active:
a real key in a test is still a key, and it is never suppressed. `weak-hash` and the
vendored `random` rule are not reported there: an MD5 cache key or a random sample in
a test is not a weakness. Each removal is counted by class and rule, and `run.json`
carries the count, so nothing disappears without a number. A class with no row
changes nothing; `source`, `vendored` and `generated` have none.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .findings import Finding, Severity
from .pathclass import DOCS, EXAMPLE, FIXTURE, TEST

#: Where tests, fixtures, docs and examples live (D47b).
WHERE_EXAMPLES_LIVE = frozenset({TEST, FIXTURE, DOCS, EXAMPLE})
LOWER, REMOVE = "lower", "remove"


@dataclass(frozen=True)
class Row:
    """In these classes, a Finding of one of these sources or rules is lowered to
    `low` or removed."""

    classes: frozenset[str]
    action: str
    sources: frozenset[str] = frozenset()
    rules: frozenset[str] = frozenset()

    def applies(self, finding: Finding) -> bool:
        return finding.context in self.classes and (
            finding.rule in self.rules or bool(self.sources.intersection(finding.sources)))


ROWS: tuple[Row, ...] = (
    Row(WHERE_EXAMPLES_LIVE, LOWER, sources=frozenset({"gitleaks"})),
    Row(WHERE_EXAMPLES_LIVE, REMOVE,
        rules=frozenset({"valvur.python.weak-hash", "python_random_rule-random"})),
)


def apply(findings: list[Finding]) -> tuple[list[Finding], dict[str, dict[str, int]]]:
    """The Findings the table keeps, each lowered where a row says, and what it
    removed, as {class: {rule: count}}."""
    kept: list[Finding] = []
    removed: dict[str, dict[str, int]] = {}
    for finding in findings:
        row = next((r for r in ROWS if r.applies(finding)), None)
        if row is None:
            kept.append(finding)
        elif row.action == REMOVE:
            by_rule = removed.setdefault(finding.context, {})
            by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
        else:
            kept.append(replace(finding, severity=Severity.LOW))
    return kept, removed
