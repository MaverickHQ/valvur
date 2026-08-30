"""The Finding model. Every Scanner and Check normalises into this."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    title: str
    evidence: str = ""
