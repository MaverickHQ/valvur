"""What a project's own ignores would hide (R38.3, D77b).

Every Scanner runs with the project's ignores off (R38.2), so what one would have
hidden is reported. This reads the ignores themselves, host-side, from the Workspace,
and names on each Finding the one that matches it: an Opengrep `nosem` comment, a
`gitleaks:allow` comment, a `.gitleaksignore` entry, a `.gitleaks.toml` allowlist, a
`checkov:skip` comment, a `.trivyignore` entry or an `osv-scanner.toml` ignore. Each
applies only to its own Scanner's findings, as the Scanner itself would apply it.
Whether one counts as a suppression is `accept`'s to decide (D77c): only one that
states a reason and an expiry, as a suppression in `.security-scan.toml` must.

A `.gitleaks.toml` allowlist's `regexes` and `stopwords` match the secret, which no
Finding carries: they are matched against the line the secret was found on, read from
the Workspace, which holds it. That can name a Finding whose line, not its secret,
matches, never miss one; and the name only explains, since such an allowlist has no
reason or expiry to make it a suppression. A Finding from history has no line in the
Workspace, so only an allowlist's paths and commits name it.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path

from .findings import Finding, IgnoredBy, Severity
from .fingerprint import derive

#: Opengrep 1.29.0's inline ignores, measured from its help: `nosem`, `nosemgrep`,
#: `noopengrep`, on the finding's line or the line above.
_NOSEM = re.compile(r"\bno(?:sem(?:grep)?|opengrep)\b")
_ALLOW = "gitleaks:allow"
#: Checkov's inline skip: `checkov:skip=CKV_AWS_18:a reason`.
_SKIP = re.compile(r"(?:checkov|bridgecrew|cortex):skip=([A-Za-z0-9_]+)(?::(.*))?")
#: `.trivyignore`'s expiry, Trivy's own syntax: `CVE-2023-1234 exp:2026-01-31`.
_TRIVY_EXP = re.compile(r"\bexp:(\d{4}-\d{2}-\d{2})\b")


def mark(workspace: Path, findings: list[Finding]) -> list[Finding]:
    """Each Finding, with `ignored_by` set where one of the project's ignores names it."""
    ignores = _Ignores(workspace)
    return [replace(f, ignored_by=by) if (by := ignores.match(f)) else f for f in findings]


def accept(findings: list[Finding], *, today: date | None = None) -> list[Finding]:
    """Each Finding an ignore with a reason and an unlapsed expiry names, suppressed by
    it; one whose expiry has passed reported again, with a Finding that fails the gate
    as a lapsed suppression does (D77c). An ignore that lacks either leaves its Finding
    active, named by `ignored_by`. A Finding `.security-scan.toml` already suppresses
    keeps that suppression, which says more.

    Expiry is inclusive and UTC, as a suppression's is, so two machines agree."""
    today = today or datetime.now(UTC).date()
    out: list[Finding] = []
    lapsed: list[Finding] = []
    for finding in findings:
        by = finding.ignored_by
        expires = _day(by.expires) if by is not None else None
        if finding.suppressed or by is None or not by.reason or expires is None:
            out.append(finding)
        elif expires >= today:
            out.append(replace(finding, suppressed=(
                f"{by.ignore} at {by.where}: {by.reason} (expires {by.expires})")))
        else:
            out.append(finding)
            lapsed.append(_lapsed(finding, by))
    return out + lapsed


def _lapsed(finding: Finding, by: IgnoredBy) -> Finding:
    return Finding(
        rule="valvur.suppression.expired",
        path=re.sub(r":\d+$", "", by.where),
        line=0,
        title=(f"The project's {by.ignore} for {finding.rule} expired on {by.expires} "
               "— the finding is reported again"),
        evidence=f"reason given: {by.reason}",
        fingerprint=derive("ignore", "expired", by.ignore, finding.fingerprint),
        severity=Severity.MEDIUM,
        sources=("valvur",),
    )


class _Ignores:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self._lines: dict[str, list[str]] = {}
        self.gitleaksignore = self._entries(".gitleaksignore")
        self.allowlists = _gitleaks_allowlists(workspace / ".gitleaks.toml")
        self.trivyignore = self._entries(".trivyignore")
        self._osv: dict[str, list[dict]] = {}

    def match(self, finding: Finding) -> IgnoredBy | None:
        sources = set(finding.sources)
        if "opengrep" in sources and (by := self._comment(finding, _NOSEM, "nosemgrep")):
            return by
        if "gitleaks" in sources:
            if not finding.commit and (by := self._allow_comment(finding)):
                return by
            if by := self._gitleaksignore(finding):
                return by
            if by := self._gitleaks_toml(finding):
                return by
        if "checkov" in sources and (by := self._checkov_skip(finding)):
            return by
        if "trivy" in sources and (by := self._trivyignore(finding)):
            return by
        if "osv-scanner" in sources and (by := self._osv_ignore(finding)):
            return by
        return None

    # ---------------------------------------------------------------- comments

    def lines(self, path: str) -> list[str]:
        if path not in self._lines:
            try:
                text = (self.workspace / path).read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                text = ""
            self._lines[path] = text.splitlines()
        return self._lines[path]

    def _comment(self, finding: Finding, pattern: re.Pattern, ignore: str) -> IgnoredBy | None:
        lines = self.lines(finding.path)
        for number in (finding.line, finding.line - 1):
            if 1 <= number <= len(lines) and pattern.search(lines[number - 1]):
                return IgnoredBy(ignore, f"{finding.path}:{number}",
                                 lines[number - 1].strip(), "inSource")
        return None

    def _allow_comment(self, finding: Finding) -> IgnoredBy | None:
        lines = self.lines(finding.path)
        number = finding.line
        if 1 <= number <= len(lines) and _ALLOW in lines[number - 1]:
            # The line holds the secret itself: only the comment is evidence.
            comment = lines[number - 1][lines[number - 1].index(_ALLOW):]
            return IgnoredBy("gitleaks:allow", f"{finding.path}:{number}", comment, "inSource")
        return None

    def _checkov_skip(self, finding: Finding) -> IgnoredBy | None:
        lines = self.lines(finding.path)
        # The skip sits inside the resource, from its first line on.
        for number in range(max(finding.line, 1), len(lines) + 1):
            skip = _SKIP.search(lines[number - 1])
            if skip and skip.group(1) == finding.rule:
                return IgnoredBy("checkov:skip", f"{finding.path}:{number}",
                                 lines[number - 1].strip(), "inSource",
                                 reason=(skip.group(2) or "").strip())
        return None

    # ---------------------------------------------------------------- files

    def _entries(self, name: str) -> list[tuple[int, str]]:
        """A line-per-entry ignore file's entries, by line number, comments aside."""
        return [(n, line.split("#", 1)[0].strip()) for n, line in enumerate(self.lines(name), 1)
                if line.split("#", 1)[0].strip()]

    def _gitleaksignore(self, finding: Finding) -> IgnoredBy | None:
        """An entry is a Gitleaks fingerprint: `path:rule:line`, or `commit:path:rule:line`
        for history. A path written from the project's root or the container's matches."""
        for number, entry in self.gitleaksignore:
            parts = entry.split(":")
            if len(parts) == 4:
                commit, path, rule, line = parts
                if not (finding.commit and finding.commit.startswith(commit)):
                    continue
            elif len(parts) == 3:
                commit, (path, rule, line) = "", parts
                if finding.commit:
                    continue
            else:
                continue
            path = path.removeprefix("/workspace/").removeprefix("./")
            if path == finding.path and rule == finding.rule and \
                    (finding.commit or line == str(finding.line)):
                return IgnoredBy(".gitleaksignore", f".gitleaksignore:{number}", entry,
                                 "external")
        return None

    def _gitleaks_toml(self, finding: Finding) -> IgnoredBy | None:
        """Any of an allowlist's criteria, Gitleaks's default condition (`OR`). Its text
        names the criterion, never the pattern, which may be the secret itself."""
        line = "" if finding.commit or not 1 <= finding.line <= len(
            self.lines(finding.path)) else self.lines(finding.path)[finding.line - 1]
        for allowlist in self.allowlists:
            if allowlist.scope and allowlist.scope != finding.rule:
                continue
            if criterion := allowlist.matches(finding, line):
                scope = f" of rule {allowlist.scope}" if allowlist.scope else ""
                return IgnoredBy(".gitleaks.toml", ".gitleaks.toml",
                                 f"an allowlist{scope} whose {criterion} match this finding",
                                 "external")
        return None

    def _trivyignore(self, finding: Finding) -> IgnoredBy | None:
        names = {finding.rule, *finding.aliases}
        for number, entry in self.trivyignore:
            identifier = entry.split()[0]
            if identifier in names:
                expiry = _TRIVY_EXP.search(entry)
                return IgnoredBy(".trivyignore", f".trivyignore:{number}", entry, "external",
                                 expires=expiry.group(1) if expiry else "")
        return None

    def _osv_ignore(self, finding: Finding) -> IgnoredBy | None:
        """OSV-Scanner reads the `osv-scanner.toml` beside each manifest, else the
        nearest one above it within the Workspace."""
        names = {finding.rule, *finding.aliases}
        directory = Path(finding.path).parent
        for folder in (directory, *directory.parents):
            config = (folder / "osv-scanner.toml").as_posix()
            entries = self._osv_entries(config)
            if entries is None:
                continue
            for entry in entries:
                if str(entry.get("id", "")) in names:
                    until = entry.get("ignoreUntil")
                    return IgnoredBy("osv-scanner.toml", config,
                                     f"[[IgnoredVulns]] id = {entry.get('id')}", "external",
                                     reason=str(entry.get("reason") or ""),
                                     expires=_iso(until))
            return None
        return None

    def _osv_entries(self, config: str) -> list[dict] | None:
        if config not in self._osv:
            path = self.workspace / config
            if not path.is_file():
                return None
            try:
                raw = tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raw = {}
            vulns = raw.get("IgnoredVulns")
            self._osv[config] = [v for v in vulns if isinstance(v, dict)] \
                if isinstance(vulns, list) else []
        return self._osv[config]


@dataclass(frozen=True)
class _Allowlist:
    scope: str
    paths: list[re.Pattern]
    commits: list[str]
    regexes: list[re.Pattern]
    stopwords: list[str]

    def matches(self, finding: Finding, line: str) -> str:
        """Which of the allowlist's criteria matches, by its key; "" when none does."""
        if any(p.search(finding.path) for p in self.paths):
            return "paths"
        if finding.commit and any(finding.commit.startswith(c) for c in self.commits):
            return "commits"
        if line and any(r.search(line) for r in self.regexes):
            return "regexes"
        if line and any(w in line.lower() for w in self.stopwords):
            return "stopwords"
        return ""


def _gitleaks_allowlists(path: Path) -> list[_Allowlist]:
    """Each allowlist's scope (a rule ID, or "" for every rule) and its criteria, both
    spellings Gitleaks reads (`[allowlist]`, `[[allowlists]]`). A pattern Python cannot
    compile (RE2 is not `re`) is passed over."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    found = []
    tables = [("", raw.get("allowlist")), *(("", t) for t in _list(raw.get("allowlists")))]
    for rule in _list(raw.get("rules")):
        if isinstance(rule, dict):
            tables += [(str(rule.get("id", "")), rule.get("allowlist")),
                       *((str(rule.get("id", "")), t) for t in _list(rule.get("allowlists")))]
    for scope, table in tables:
        if not isinstance(table, dict):
            continue
        found.append(_Allowlist(
            scope, _patterns(table.get("paths")), [str(c) for c in _list(table.get("commits"))],
            _patterns(table.get("regexes")),
            [str(w).lower() for w in _list(table.get("stopwords")) if str(w)]))
    return found


def _patterns(value) -> list[re.Pattern]:
    patterns = []
    for text in _list(value):
        try:
            patterns.append(re.compile(str(text)))
        except re.error:
            continue
    return patterns


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _day(text: str) -> date | None:
    """An expiry as a day; None when there is none, or it is no date (`exp:2026-13-45`)."""
    try:
        return date.fromisoformat(text) if text else None
    except ValueError:
        return None


def _iso(value) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return ""
