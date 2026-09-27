"""Gitleaks — secrets, including git history."""

from __future__ import annotations

import json
from pathlib import Path

from .. import fingerprint as _fp
from .. import redact as _redact
from ..exclusions import PROJECT_GITLEAKS_CONFIG
from ..findings import Finding, Severity
from ..invocation import Invocation, ScannerOutput
from .base import ScannerAdapter, container_relative

VERSION = "8.30.1"


class GitleaksAdapter(ScannerAdapter):
    kind = "scanner"
    name = "gitleaks"
    version = VERSION

    def command(self, workspace: Path) -> Invocation:
        from .. import exclusions

        # `--exit-code 0`: gitleaks exits 1 when it finds something, which is a
        # successful run (F2.4); the report says what it found.
        prefixes = exclusions.excluded_prefixes(workspace)
        return Invocation(
            tool=self.name, version=VERSION,
            argv=("gitleaks", "dir", "/workspace",
                  "--report-format", "json",
                  "--report-path", "/results/gitleaks.json",
                  "--no-banner", "--exit-code", "0",
                  # What not to read (29.0.1): a generated config in the scratch
                  # mount, since Gitleaks has no path flag. Measured before this:
                  # 3,892 hits inside an excluded archive, produced then dropped.
                  "--config", f"/results/{exclusions.GITLEAKS_CONFIG}"),
            report="gitleaks.json", timeout=300,
            files=((exclusions.GITLEAKS_CONFIG, exclusions.gitleaks_config(
                prefixes,
                project_config=(workspace / exclusions.PROJECT_GITLEAKS_CONFIG).is_file())),),
        )

    def parse(self, output: ScannerOutput) -> list[Finding]:
        return [_finding(item, container_relative(item["File"]), item["StartLine"],
                         self.name)
                for item in json.loads(output.stdout or "[]")]

    def history_command(self, *, project_config: bool) -> Invocation:
        """The second pass (R3.7): the history file the host wrote into the scratch
        directory. The project's own `.gitleaks.toml`, when the File Set carries
        it, keeps its rules and content allowlists; its path allowlists are
        applied by `parse_history`, because every hit here is in one file."""
        config = ("--config", f"/workspace/{PROJECT_GITLEAKS_CONFIG}") if project_config else ()
        return Invocation(
            tool=HISTORY_TOOL, version=VERSION,
            argv=("gitleaks", "dir", f"/results/{HISTORY_FILE}",
                  "--report-format", "json",
                  "--report-path", f"/results/{HISTORY_REPORT}",
                  "--no-banner", "--exit-code", "0", *config),
            report=HISTORY_REPORT, timeout=300)

    def parse_history(self, output: ScannerOutput, written, workspace: Path,
                      excluded: tuple[str, ...]) -> list[Finding]:
        """Each hit at the path and commit it came from; one under an excluded
        path or a path the project allowlists is dropped, as in the tree."""
        from ..exclusions import is_configured_out

        allowed = project_path_allowlist(workspace)
        findings = []
        for item in json.loads(output.stdout or "[]"):
            where = written.locate(int(item.get("StartLine", 0)))
            if where is None:
                continue
            commit, path = where
            if is_configured_out(path, excluded) or any(p.search(path) for p in allowed):
                continue
            findings.append(_finding(item, path, 0, self.name, commit=commit))
        return findings


#: The history pass's name in the plan and its files in the scratch directory.
HISTORY_TOOL = "gitleaks-history"
HISTORY_FILE = "history.txt"
HISTORY_REPORT = "gitleaks-history.json"


def _finding(item: dict, path: str, line: int, tool: str, *,
             commit: str | None = None) -> Finding:
    secret = item.get("Secret", "")
    title = item["Description"]
    if commit:
        title = f"{title}, in git history (commit {commit[:12]})"
    return Finding(
        rule=item["RuleID"],
        path=path,
        line=line,
        title=title,
        # Redact at the boundary — the raw secret never enters the model.
        evidence=_redact.redact(item.get("Match", ""), secret),
        fingerprint=_fp.for_secret(item["RuleID"], path, secret),
        sources=(tool,),
        # A live credential in a repository is not a matter of degree.
        severity=Severity.CRITICAL,
        commit=commit,
    )


def project_path_allowlist(workspace: Path) -> list:
    """The path patterns of the project's `.gitleaks.toml`, both spellings Gitleaks
    reads (`[allowlist]` and `[[allowlists]]`). A pattern Python cannot compile
    is skipped: an allowlist that drops nothing is the safe direction."""
    import re
    import tomllib

    try:
        raw = tomllib.loads((workspace / PROJECT_GITLEAKS_CONFIG).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    tables = [raw.get("allowlist") or {}, *(raw.get("allowlists") or [])]
    patterns = []
    for table in tables:
        for text in table.get("paths", []) if isinstance(table, dict) else []:
            try:
                patterns.append(re.compile(str(text)))
            except re.error:
                continue
    return patterns
