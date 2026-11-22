"""What a path's class changes about a Finding (D56; D47b, c): one table.

A secret where tests, fixtures, docs and examples live ranks `low` and stays active:
a real key in a test is still a key, and it is never suppressed. A class with no row
changes nothing; `source`, `vendored` and `generated` have none.

`weak-hash` and the vendored `random` rule were removed there, and counted in
`run.json`. Since R49.3 they are in the tier table (`tiers.py`), inventory everywhere,
so they are in `findings.json` under a test path too. The table removes nothing now;
`run.json` keeps `removed_by_class`, empty, for whoever reads it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .findings import Finding, Severity
from .pathclass import DOCS, EXAMPLE, FIXTURE, TEST

#: Where tests, fixtures, docs and examples live (D47b).
WHERE_EXAMPLES_LIVE = frozenset({TEST, FIXTURE, DOCS, EXAMPLE})
LOWER = "lower"


@dataclass(frozen=True)
class Row:
    """In these classes, a Finding of one of these sources or rules is lowered to
    `low`."""

    classes: frozenset[str]
    action: str
    sources: frozenset[str] = frozenset()
    rules: frozenset[str] = frozenset()

    def applies(self, finding: Finding) -> bool:
        return finding.context in self.classes and (
            finding.rule in self.rules or bool(self.sources.intersection(finding.sources)))


ROWS: tuple[Row, ...] = (
    Row(WHERE_EXAMPLES_LIVE, LOWER, sources=frozenset({"gitleaks"})),
)


def apply(findings: list[Finding]) -> tuple[list[Finding], dict[str, dict[str, int]]]:
    """The Findings, each lowered where a row says, and what the table removed, as
    {class: {rule: count}}: nothing, since R49.3."""
    kept = [replace(finding, severity=Severity.LOW)
            if any(row.applies(finding) for row in ROWS) else finding
            for finding in findings]
    return kept, {}
