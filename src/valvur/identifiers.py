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
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

from . import toml_input

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

    def category(self, identifier: str) -> str:
        """A category's name, for an ID in any list."""
        for one in self.lists.values():
            if identifier in one.categories:
                return one.categories[identifier]
        raise KeyError(identifier)


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
