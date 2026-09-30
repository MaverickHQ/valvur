"""Opengrep — static analysis against valvur's own bundled rules.

Opengrep rather than Semgrep (ADR-0004), and our own rules rather than the community
registry, so nothing under a competing-use restriction is redistributed.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .. import fingerprint as _fp
from ..findings import Finding, Severity
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

VERSION = "1.29.0"


#: A `.semgrepignore` that ignores nothing, so Opengrep's own default list is off.
_IGNORE_NOTHING = ("# valvur: the File Set decides what a scan reads (ADR-0021); this file\n"
                   "# turns Opengrep's default ignore list off.\n")


#: The rule sets the image carries beside valvur's own, each at its source's commit
#: (R13.3, D29): `run.json` names them, so a finding can be traced to the rule's text.
#: A test holds this to `rules/vendor/gitlab/manifest.json` and `sources.toml`.
RULE_SETS: dict[str, str] = {
    "gitlab-sast-rules": "53bf5cf6df3c51b6c02110f5a638b5e6213666cd",
}


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
                  "--quiet", "--no-git-ignore",
                  "/workspace"),
            report="opengrep.json", timeout=600, empty_when=NOTHING_TO_SCAN,
            # Opengrep unpacks and execs opengrep-core. Granted only here: the root
            # filesystem stays read-only, the container stays non-root and
            # capability-less, and the exec surface is in-memory and non-persistent.
            allow_exec=True,
            # With no `.semgrepignore` where it starts, Opengrep skips `build/`,
            # `dist/`, `vendor/`, `test/` and `tests/` of its own accord: measured
            # inside the image, a flaw in `mypkg/build/` and one in `tests/` were
            # both unread (R3.9). The File Set decides what is read (ADR-0021).
            files=((".semgrepignore", _IGNORE_NOTHING),),
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
    would change whenever the rules directory moved. valvur's own ids are dotted and
    begin `valvur.`; a vendored rule's (R13.3) has no dot, so it is the last part."""
    marker = "valvur."
    index = check_id.find(marker)
    return check_id[index:] if index >= 0 else check_id.rsplit(".", 1)[-1]


_OPENGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _severity(item: dict) -> Severity:
    raw = str(item.get("extra", {}).get("severity", "")).upper()
    return Severity.parse(_OPENGREP_SEVERITY.get(raw, "medium"))
