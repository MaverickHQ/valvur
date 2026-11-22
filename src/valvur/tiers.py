"""The tier table: which rules' Findings are inventory (D82c, D82d, ADR-0033).

Opengrep's adapter marks a Finding `inventory` from the rule's own YAML, which serves the
four sink rules (D47a). A vendored rule may not be edited, and Gitleaks', Checkov's and
zizmor's rules are not valvur's files. So a rule measured on maintained code and under the
bar there is named in one table, `data/tiers.toml`, by its Scanner and its ID, and its
Findings are inventory: in `findings.json`, never active, never counted by the verdict or
the gate. The table is package data, read once; nothing in a project changes it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from functools import cache
from pathlib import Path

from . import toml_input
from .classtable import WHERE_EXAMPLES_LIVE
from .findings import Finding
from .pathclass import DOCS, EXAMPLE, FIXTURE, TEST

PATH = Path(__file__).parent / "data" / "tiers.toml"
#: Where a row applies. `test material` is the path classes test, fixture, docs and
#: example: a rule that matches a shape, such as a PEM block, is a fixture there in every
#: case measured, and the same rule in `config/` stays active (Requirement 2.5's repair).
EVERYWHERE, TEST_MATERIAL = "everywhere", "test material"
#: What a Finding's title gains when the table makes it inventory (Requirement 3.4): the
#: reader of one Finding sees why it is not active. The sentences are a contract.
WHY = "a rule under the bar on maintained code: listed for review"
_UNDER = {TEST: "under a test path", FIXTURE: "under a fixture path",
          DOCS: "under a documentation path", EXAMPLE: "under an example path"}


@dataclass(frozen=True)
class Row:
    """One rule of one Scanner, with the measurement that put it here."""

    scanner: str
    id: str
    where: str
    tp: int
    fp: int
    reason: str

    def applies(self, finding: Finding) -> bool:
        return (finding.rule == self.id and self.scanner in finding.sources
                and (self.where == EVERYWHERE or finding.context in WHERE_EXAMPLES_LIVE))

    def why(self, finding: Finding) -> str:
        """The clause the Finding's title gains: for test material, the path that decided."""
        if self.where == EVERYWHERE:
            return WHY
        directory = finding.path.rpartition("/")[0]
        return f"{_UNDER[finding.context]} (`{directory}/`): listed for review"


@cache
def rows() -> tuple[Row, ...]:
    """The table. A row it cannot read is an error here, never a rule left active in
    silence."""
    found = []
    for entry in toml_input.loads(PATH.read_text(encoding="utf-8")).get("rule", []):
        if entry["tier"] != "inventory" or entry["where"] not in (EVERYWHERE, TEST_MATERIAL):
            raise ValueError(f"{PATH.name}: {entry['id']}: tier {entry['tier']!r} "
                             f"where {entry['where']!r} is not one this version reads")
        found.append(Row(scanner=entry["scanner"], id=entry["id"], where=entry["where"],
                         tp=int(entry["corpus"]["tp"]), fp=int(entry["corpus"]["fp"]),
                         reason=entry["reason"]))
    return tuple(found)


def row_for(finding: Finding) -> Row | None:
    """The row that names this Finding's rule, if one does."""
    return next((row for row in rows() if row.applies(finding)), None)


def apply(findings: list[Finding]) -> list[Finding]:
    """Each Finding, made inventory where a row names its rule, with the reason in its
    title."""
    kept = []
    for finding in findings:
        row = row_for(finding)
        kept.append(finding if row is None else replace(
            finding, inventory=True, title=f"{finding.title}, {row.why(finding)}"))
    return kept
