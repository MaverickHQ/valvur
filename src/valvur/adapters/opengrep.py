"""Opengrep — static analysis against valvur's own bundled rules.

Opengrep rather than Semgrep (ADR-0004), and our own rules rather than the community
registry, so nothing under a competing-use restriction is redistributed.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

VERSION = "1.29.0"


class OpengrepAdapter(ScannerAdapter):
    kind = "scanner"
    name = "opengrep"
    version = VERSION

    def command(self, workspace: Path) -> Invocation:
        # Our own bundled rules only (ADR-0004). No registry fetch, so no network
        # and no licence question.
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("opengrep", "scan", "--config", "/opt/valvur-rules",
                  "--json", "--output", "/results/opengrep.json",
                  "--quiet", "--no-git-ignore", "/workspace"),
            report="opengrep.json", timeout=600, empty_when=NOTHING_TO_SCAN,
            # Opengrep unpacks and execs opengrep-core. Granted only here: the root
            # filesystem stays read-only, the container stays non-root and
            # capability-less, and the exec surface is in-memory and non-persistent.
            allow_exec=True,
        )

    def parse(self, output: ScannerOutput) -> list[Finding]:
        report = json.loads(output.stdout or "{}")
        findings: list[Finding] = []

        # The SAST class is the only one needing a content hash, so it is the only
        # one that can collide. Identical matches in one file are separated by
        # ordinal, assigned in file order so it is stable across runs (design 3.1).
        seen: Counter[tuple[str, str, str]] = Counter()

        for item in sorted(
            report.get("results") or [],
            key=lambda r: (r.get("path", ""), r.get("start", {}).get("line", 0)),
        ):
            rule = _short_rule(item.get("check_id", ""))
            path = container_relative(str(item.get("path", "")))
            matched = str(item.get("extra", {}).get("lines", "")).strip()

            key = (rule, path, matched)
            ordinal = seen[key]
            seen[key] += 1

            findings.append(
                Finding(
                    rule=rule,
                    path=path,
                    line=item.get("start", {}).get("line", 0),
                    title=str(item.get("extra", {}).get("message", "")).strip(),
                    evidence=matched,
                    fingerprint=_fp.for_sast(rule, path, matched, ordinal),
                    sources=(output.tool,),
                    severity=_severity(item),
                )
            )
        return findings


def _short_rule(check_id: str) -> str:
    """Opengrep prefixes rule ids with the config path. Strip it, or the identity
    would change whenever the rules directory moved."""
    marker = "valvur."
    index = check_id.find(marker)
    return check_id[index:] if index >= 0 else check_id


_OPENGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _severity(item: dict) -> str:
    raw = str(item.get("extra", {}).get("severity", "")).upper()
    return _OPENGREP_SEVERITY.get(raw, "medium")
