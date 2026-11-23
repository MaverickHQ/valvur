"""Standard identifiers for a Finding, mapped in one file (R51.2, D82o, ADR-0037).

`data/identifiers.toml` maps a rule to its CWE and to OWASP's lists, each at the edition
read on the day the file names. It is looked up by the rule's ID, then the longest prefix
of it, then its Scanner, then its Finding Class. An entry may say `none`, and must then
say why: no honest mapping is a fact worth stating.

The word is *mapped to*. A mapping says where a Finding sorts in someone else's taxonomy;
it is not a claim that valvur covers a category, and no output says so.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field, replace
from functools import cache
from pathlib import Path

from . import toml_input
from .findings import Finding

PATH = Path(__file__).parent / "data" / "identifiers.toml"
_CWE = re.compile(r"CWE-\d+")
#: The four levels, in the order they are asked, and the key each entry is named by.
LEVELS = (("rule", "id"), ("prefix", "prefix"), ("scanner", "scanner"), ("class", "class"))


@dataclass(frozen=True)
class Identifiers:
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    #: Why there is no OWASP category, when the entry says `none`.
    reason: str = ""


@dataclass(frozen=True)
class OwaspList:
    name: str
    edition: str
    read: datetime.date
    source: str
    categories: dict[str, str]
    #: False for a publication that was read and is not mapped to, with `reason`.
    mapped: bool = True
    reason: str = ""


@dataclass(frozen=True)
class Table:
    lists: dict[str, OwaspList]
    rules: dict[str, Identifiers] = field(default_factory=dict)
    prefixes: dict[str, Identifiers] = field(default_factory=dict)
    scanners: dict[str, Identifiers] = field(default_factory=dict)
    classes: dict[str, Identifiers] = field(default_factory=dict)
    #: A CWE to the OWASP Top 10 category whose own list holds it.
    by_cwe: dict[str, str] = field(default_factory=dict)

    def of(self, scanner: str, rule: str, finding_class: str) -> Identifiers:
        """The entry for a rule of a Scanner: its own, else its longest prefix's, else
        its Scanner's, else its Finding Class's, else nothing."""
        if rule in self.rules:
            return self.rules[rule]
        prefixes = [p for p in self.prefixes if rule.startswith(p)]
        if prefixes:
            return self.prefixes[max(prefixes, key=len)]
        return self.scanners.get(scanner) or self.classes.get(finding_class) \
            or Identifiers((), ())

    def list_of(self, identifier: str) -> OwaspList:
        """The list a category's ID belongs to."""
        for one in self.lists.values():
            if identifier in one.categories:
                return one
        raise KeyError(identifier)

    def category(self, identifier: str) -> str:
        """A category's name, for an ID in any list."""
        return self.list_of(identifier).categories[identifier]


def _entry(raw: dict[str, object], name: str, known: set[str]) -> Identifiers:
    given = raw.get("cwe")
    cwe = tuple(str(c) for c in given) if isinstance(given, list) else ()
    for one in cwe:
        if not _CWE.fullmatch(one):
            raise ValueError(f"{PATH.name}: {name}: `{one}` is not a CWE, as CWE-89 is")
    owasp, reason = raw.get("owasp"), str(raw.get("reason") or "")
    if owasp == "none":
        if not reason.strip():
            raise ValueError(f"{PATH.name}: {name} says `none` and not why")
        return Identifiers(cwe, (), reason)
    if not isinstance(owasp, list):
        raise ValueError(f"{PATH.name}: {name}: `owasp` is a list of categories, or \"none\"")
    for one in owasp:
        if one not in known:
            raise ValueError(f"{PATH.name}: {name}: {one} is in no list this file holds")
    return Identifiers(cwe, tuple(str(o) for o in owasp), reason)


def read(text: str) -> Table:
    """The table in `text`. A file that cannot be trusted is refused here, whole: a
    `none` with no reason, a category in no list, a list with no edition or no date."""
    raw = toml_input.loads(text)
    lists = {}
    for key, one in (raw.get("list") or {}).items():
        if not str(one.get("edition") or "").strip():
            raise ValueError(f"{PATH.name}: the list `{key}` names no edition")
        if not isinstance(one.get("read"), datetime.date):
            raise ValueError(f"{PATH.name}: the list `{key}` does not say the day it was read")
        mapped = bool(one.get("mapped", True))
        if not mapped and not str(one.get("reason") or "").strip():
            raise ValueError(f"{PATH.name}: the list `{key}` is not mapped to and not why")
        lists[key] = OwaspList(str(one["name"]), str(one["edition"]), one["read"],
                               str(one["source"]), dict(one.get("categories") or {}),
                               mapped, str(one.get("reason") or ""))
    known = {identifier for one in lists.values() if one.mapped for identifier in one.categories}
    levels: dict[str, dict[str, Identifiers]] = {}
    for level, key in LEVELS:
        levels[level] = {str(entry[key]): _entry(entry, f"{level} `{entry[key]}`", known)
                         for entry in raw.get(level) or []}
    by_cwe = {str(c): str(category) for c, category in (raw.get("cwe") or {}).items()}
    for c, category in by_cwe.items():
        if not _CWE.fullmatch(c) or category not in known:
            raise ValueError(f"{PATH.name}: cwe: {c} = {category} is not a CWE and a category")
    return Table(lists, levels["rule"], levels["prefix"], levels["scanner"], levels["class"],
                 by_cwe)


@cache
def table() -> Table:
    """The table valvur ships."""
    return read(PATH.read_text(encoding="utf-8"))


def of(scanner: str, rule: str, finding_class: str) -> Identifiers:
    return table().of(scanner, rule, finding_class)


#: The Finding Class of a Scanner's Findings, by CONTEXT.md's names.
_CLASS_OF = {"gitleaks": "secret", "checkov": "IaC misconfiguration",
             "zizmor": "IaC misconfiguration", "opengrep": "static analysis",
             "trivy": "dependency vulnerability", "osv-scanner": "dependency vulnerability"}
_OWN_CLASS = (("valvur.dependency.", "dependency reality"), ("valvur.licence.", "licence"))


def class_of(finding: Finding) -> str:
    """A Finding's class, for the table's last level."""
    for prefix, name in _OWN_CLASS:
        if finding.rule.startswith(prefix):
            return name
    for source in finding.sources:
        if source in _CLASS_OF:
            return _CLASS_OF[source]
    return "static analysis"


def for_finding(finding: Finding, known: Table | None = None) -> Identifiers:
    """A Finding's entry: by its rule, and by the first of its Scanners the table names."""
    known = known or table()
    scanner = next((s for s in finding.sources if s in known.scanners), "")
    return known.of(scanner, finding.rule, class_of(finding))


def apply(findings: list[Finding]) -> list[Finding]:
    """Each Finding with the categories its rule is mapped to, and with its entry's CWE
    where its Scanner gave none. A CWE a Scanner reported is kept: an advisory's, or a
    rule's own. Neither field is identity, and no Fingerprint is read or written here."""
    marked = []
    for finding in findings:
        entry = for_finding(finding)
        cwe = finding.cwe or entry.cwe
        if (cwe, entry.owasp) != (finding.cwe, finding.owasp):
            finding = replace(finding, cwe=cwe, owasp=entry.owasp)
        marked.append(finding)
    return marked
