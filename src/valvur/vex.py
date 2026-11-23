"""A project's own VEX, honoured only where the project says so (R50.5, D82m, ADR-0035).

A VEX statement says a product is not affected by a vulnerability, or has it fixed. A
project may keep such statements, in OpenVEX, about its own dependencies. valvur honours
one only through a `[[vex]]` entry in `.security-scan.toml` that names the document and a
date it is accepted until: OpenVEX has no expiry, and nothing here is accepted for ever.
valvur never searches the tree for a document, and never writes one.

A statement is honoured when its status is `not_affected` or `fixed`, its vulnerability is
the Finding's ID or an alias, and its product is the Finding's package at its version, as
package URLs. `not_affected` must say why. The Finding is then suppressed, and says so with
the document's author and time. Only a dependency vulnerability can be: no other Finding
has a product and a vulnerability ID.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path

from .exclusions import PROJECT_FILE
from .findings import Finding, Severity
from .fingerprint import derive
from .refusal import Refusal

HONOURED = ("not_affected", "fixed")
STATUSES = (*HONOURED, "affected", "under_investigation")
UNUSED_RULE = "valvur.vex.unused"
NOT_HONOURED_RULE = "valvur.vex.not-honoured"
#: As `suppressions.py` gives a lapsed Suppression: it fails the gate at every threshold.
EXPIRED_RULE = "valvur.suppression.expired"
_CONTEXT = "https://openvex.dev/ns"
_TYPES = {"pip": "pypi", "gomod": "golang", "go": "golang"}


@dataclass(frozen=True)
class Statement:
    names: frozenset[str]
    #: Each product as (package URL without its version, version or "").
    products: tuple[tuple[str, str], ...]
    status: str
    why: str


@dataclass(frozen=True)
class Document:
    path: str
    expires: date
    author: str
    timestamp: str
    statements: tuple[Statement, ...]

    def lapsed(self, today: date | None = None) -> bool:
        return (today or datetime.now(UTC).date()) > self.expires


def _purl(text: str) -> tuple[str, str]:
    """A package URL as (type and name, version), compared without qualifiers."""
    core = str(text).split("?", 1)[0].split("#", 1)[0].strip()
    if not core.startswith("pkg:"):
        return "", ""
    body, _, version = core.partition("@")
    kind, _, name = body[4:].partition("/")
    name = name.lower()
    if kind.lower() == "pypi":
        name = name.replace("_", "-").replace(".", "-")
    return f"pkg:{kind.lower()}/{name}", version


def of_finding(finding: Finding) -> tuple[str, str]:
    """The Finding's package at its version, as a package URL's two parts."""
    dependency = finding.dependency
    if dependency is None:
        return "", ""
    if dependency.purl:
        return _purl(dependency.purl)
    kind = _TYPES.get(dependency.ecosystem, dependency.ecosystem)
    return _purl(f"pkg:{kind}/{dependency.package.replace(':', '/')}@{dependency.version}")


def _statement(raw: dict, inherited: list) -> Statement:
    vulnerability = raw.get("vulnerability") or {}
    if isinstance(vulnerability, str):
        vulnerability = {"name": vulnerability}
    names = {str(vulnerability.get("name") or ""), *map(str, vulnerability.get("aliases") or [])}
    products = []
    for product in raw.get("products") or inherited or []:
        if isinstance(product, str):
            product = {"@id": product}
        named = (product.get("identifiers") or {}).get("purl") or product.get("@id") or ""
        if _purl(named)[0]:
            products.append(_purl(named))
    return Statement(frozenset(n.upper() for n in names if n), tuple(products),
                     str(raw.get("status") or ""),
                     str(raw.get("justification") or raw.get("impact_statement") or ""))


def _read(workspace: Path, entry: dict) -> Document:
    named = str(entry.get("path") or "")
    expires = entry.get("expires")
    if isinstance(expires, datetime):
        expires = expires.date()
    if not named or not isinstance(expires, date):
        raise Refusal(f"A [[vex]] entry in {PROJECT_FILE} needs a `path` and a date, "
                      f"`expires`; got {entry!r}.")
    root = workspace.resolve()
    target = (root / named).resolve()
    if Path(named).is_absolute() or root not in target.parents:
        raise Refusal(f"The VEX document `{named}` in {PROJECT_FILE} is outside the "
                      "project, or reached through a link that leaves it. valvur reads a "
                      "document only inside the tree it scans.")
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Refusal(f"The VEX document `{named}` in {PROJECT_FILE} could not be read as "
                      f"JSON ({type(error).__name__}), so the scan did not go on without "
                      "it.") from error
    if not isinstance(document, dict) \
            or not str(document.get("@context", "")).startswith(_CONTEXT) \
            or not isinstance(document.get("statements"), list):
        raise Refusal(f"`{named}`, named by a [[vex]] entry in {PROJECT_FILE}, is not an "
                      f"OpenVEX document: it needs `@context` under {_CONTEXT} and a list "
                      "of `statements`. The scan did not go on without it.")
    statements = tuple(_statement(raw, document.get("products") or [])
                       for raw in document["statements"] if isinstance(raw, dict))
    return Document(named, expires, str(document.get("author") or "no author given"),
                    str(document.get("timestamp") or "no time given"), statements)


def load(workspace: Path, project: dict | None) -> list[Document]:
    """Each document a `[[vex]]` entry names, read. Raises `Refusal`, before any Scanner
    runs, for an entry that is not one, a path that leaves the project, and a file that is
    not OpenVEX: a document asked for and not read must never pass in silence."""
    entries = (project or {}).get("vex") or []
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise Refusal(f"`vex` in {PROJECT_FILE} must be an array of tables, [[vex]].")
    return [_read(workspace, entry) for entry in entries]


def _note(rule: str, path: str, title: str, key: str, severity=Severity.LOW) -> Finding:
    return Finding(rule=rule, path=path, line=0, title=title, severity=severity,
                   fingerprint=derive("vex", rule, path, key), sources=("valvur",))


def apply(findings: list[Finding], documents: list[Document], *,
          today: date | None = None) -> list[Finding]:
    """The Findings, each dependency vulnerability suppressed where an accepted document
    says so, and what the documents themselves need said: one lapsed, a statement that
    would have applied and was not honoured, and statements that match nothing here."""
    out, said = list(findings), []
    for document in documents:
        if document.lapsed(today):
            said.append(_note(
                EXPIRED_RULE, PROJECT_FILE,
                f"The VEX document `{document.path}` was accepted until "
                f"{document.expires.isoformat()}, which has passed: its statements are "
                "not honoured until someone accepts it again", document.path,
                Severity.MEDIUM))
            continue
        used: set[int] = set()
        for index, finding in enumerate(out):
            package, version = of_finding(finding)
            if not package:
                continue
            ids = {finding.rule.upper(), *(alias.upper() for alias in finding.aliases)}
            for number, statement in enumerate(document.statements):
                versions = [v for p, v in statement.products if p == package]
                if not ids & statement.names or (version not in versions
                                                 and "" not in versions):
                    continue            # another vulnerability, or another product
                used.add(number)
                if statement.status not in HONOURED or out[index].suppressed:
                    continue            # it says the Finding stands, or one already spoke
                why = ("names no version of the package" if version not in versions else
                       "gives neither a justification nor an impact statement"
                       if statement.status == "not_affected" and not statement.why else "")
                if why:
                    said.append(_note(
                        NOT_HONOURED_RULE, document.path,
                        f"A VEX statement for {finding.rule} in `{document.path}` {why}, "
                        "and was not honoured", f"{finding.rule} {package} {why}"))
                    continue
                reason = f": {statement.why}" if statement.status == "not_affected" else ""
                out[index] = replace(finding, suppressed=(
                    f"VEX {statement.status}{reason} ({document.author}, "
                    f"{document.timestamp}), accepted until {document.expires.isoformat()}"))
        unused = len(document.statements) - len(used)
        if unused:
            said.append(_note(
                UNUSED_RULE, document.path,
                f"{unused} statement(s) in `{document.path}` match nothing here",
                str(unused)))
    return out + said
