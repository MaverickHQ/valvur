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
from .findings import Finding

PATH = Path(__file__).parent / "data" / "tiers.toml"
EVERYWHERE = "everywhere"
#: What a Finding's title gains when the table makes it inventory (Requirement 3.4): the
#: reader of one Finding sees why it is not active. The sentence is a contract.
WHY = {EVERYWHERE: "a rule under the bar on maintained code: listed for review"}


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
        return finding.rule == self.id and self.scanner in finding.sources


@cache
def rows() -> tuple[Row, ...]:
    """The table. A row it cannot read is an error here, never a rule left active in
    silence."""
    found = []
    for entry in toml_input.loads(PATH.read_text(encoding="utf-8")).get("rule", []):
        if entry["tier"] != "inventory" or entry["where"] != EVERYWHERE:
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
            finding, inventory=True, title=f"{finding.title}, {WHY[row.where]}"))
    return kept
