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


def apply(findings: list[Finding]) -> list[Finding]:
    """Each Finding, marked `inventory` where a row names its rule."""
    table = rows()
    return [replace(finding, inventory=True)
            if any(row.applies(finding) for row in table) else finding
            for finding in findings]
