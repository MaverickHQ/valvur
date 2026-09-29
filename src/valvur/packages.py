"""`check_package`: what a package is, asked before it is installed (D28, F3.16, ADR-0028).

A scan reports a hallucinated dependency after it has been written into a manifest,
and often after the install that ran a squatted name's code. The same answers the
dependency-reality Check gives are offered here beforehand, for an agent about to add
a dependency and for the CLI: whether the name is on its registry, whether it is one
edit from a far more popular one, whether it was published as malicious, and whether
this project's registry configuration exposes it to confusion (D27).

Host-side, from the host cache alone, and **never from a registry**: asking one about
a hallucinated name tells it, and anyone watching it, what to register. So JVM and Go,
which have no offline index (ADR-0018), are `unknown` rather than looked up.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from . import cache as _cache
from . import ecosystems as _ecosystems
from .ecosystems import registries as _registries

#: The most one call answers, on every surface: the MCP tool's bound (D28).
MOST = 50
#: The verdicts that should stop an install until a human has looked.
FLAGGED = frozenset({"nonexistent", "near-miss", "malicious", "confusion"})

Package = tuple[str, str, str | None]

_EXACT_PIN = re.compile(r"(?P<name>[^=<>!~\s]+)\s*===?\s*(?P<version>\S+)")


@dataclass(frozen=True)
class Answer:
    ecosystem: str
    name: str
    version: str | None
    #: exists, nonexistent, near-miss, malicious, confusion, not-public or unknown.
    verdict: str
    #: One sentence saying why, and what was consulted.
    reason: str
    #: The popular name a near-miss is one edit from.
    near: str | None = None
    #: The `MAL-` identifiers that name a malicious package.
    ids: tuple[str, ...] = ()
    #: The private registry a confusion or not-public answer is about.
    source: str | None = None
    #: The day the index answering it was built, `YYYY-MM-DD`; empty when none did.
    index_built: str = ""
    #: Whether the index holds the name; None when no index was asked.
    exists: bool | None = None

    @property
    def flagged(self) -> bool:
        return self.verdict in FLAGGED

    def as_dict(self) -> dict:
        found = asdict(self)
        found["ids"] = list(self.ids)
        found["flagged"] = self.flagged
        return found


def parse(ecosystem: str, spec: str) -> Package:
    """`name`, `name@version` (`@scope/name@version` for npm) or `name==version`."""
    spec = spec.strip()
    pinned = _EXACT_PIN.fullmatch(spec)
    if pinned:
        return ecosystem, pinned.group("name"), pinned.group("version")
    at = spec.find("@", 1)
    if at > 0:
        return ecosystem, spec[:at], spec[at + 1:] or None
    return ecosystem, spec, None


def _built(names: Path) -> dict[str, str]:
    try:
        entries = json.loads((names / "metadata.json").read_text(encoding="utf-8"))
        entries = entries.get("ecosystems") or {}
    except (OSError, ValueError, AttributeError):
        return {}
    return {eco: str((entry or {}).get("built_at") or "")[:10] for eco, entry in entries.items()}


#: Where a project states each ecosystem's registries, in the order they are read.
_CONFIGURED_BY = {"npm": ("package.json",),
                  "pip": ("pyproject.toml", "Pipfile", "requirements.txt"),
                  "composer": ("composer.json",)}


def _configured(workspace: Path | None, ecosystem: str) -> _registries.Registries:
    """The project's registry configuration for `ecosystem`, from the first of its
    manifests at the root that states any, as the Check reads it (D27)."""
    if workspace is None or ecosystem not in _CONFIGURED_BY:
        return _registries.Registries()
    candidates = _CONFIGURED_BY[ecosystem]
    for filename in candidates:
        configured = _registries.for_manifest(workspace, ecosystem, workspace / filename)
        if configured != _registries.Registries():
            return configured
    return _registries.Registries()


def check(asked: Iterable[Package], *, workspace: Path | None = None) -> list[Answer]:
    """An answer for each package, in the order asked, from the host cache. At most
    `MOST` at once: a caller with more asks again."""
    from .checks import dependency_reality as _reality
    from .name_index import malicious as _malicious
    from .name_index import reader as _reader

    wanted = [(_ecosystems.normalise(eco), name.strip(), (version or "").strip() or None)
              for eco, name, version in asked]
    if len(wanted) > MOST:
        raise ValueError(f"{len(wanted)} packages asked; at most {MOST} at once")
    names = _cache.name_index()
    built = _built(names)
    popular = _reality._popular()
    indexes: dict[str, _reader.NameIndex | None] = {}
    lists: dict[str, _malicious.MaliciousList | None] = {}
    configured: dict[str, _registries.Registries] = {}
    answers: list[Answer] = []
    try:
        for ecosystem, name, version in wanted:
            if ecosystem not in indexes:
                indexes[ecosystem] = _reader.open_index(names, ecosystem)
                lists[ecosystem] = _malicious.open_list(names, ecosystem)
                configured[ecosystem] = _configured(workspace, ecosystem)
            answers.append(_answer(ecosystem, name, version, indexes[ecosystem],
                                   lists[ecosystem], configured[ecosystem],
                                   built.get(ecosystem, ""), popular))
    finally:
        for opened in [*indexes.values(), *lists.values()]:
            if opened is not None:
                opened.close()
    return answers


def _answer(ecosystem, name, version, index, listed, configured, built, popular) -> Answer:
    from .checks import dependency_reality as _reality

    def said(verdict: str, reason: str, **extra) -> Answer:
        return Answer(ecosystem, name, version, verdict, reason, index_built=built, **extra)

    if ecosystem not in _ecosystems.INDEX_FILES:
        known = ecosystem in {e.key for e in _ecosystems.ECOSYSTEMS}
        return said("unknown", (f"{_reality._REGISTRY_NAME[ecosystem]} publishes no name "
                                "list, so there is no offline index to answer from"
                                if known else f"valvur has no index for {ecosystem}"))
    registry = _reality._REGISTRY_NAME[ecosystem]
    key = _ecosystems.index_form(ecosystem, name)
    entry = listed.lookup(key) if listed is not None else None
    if entry is not None and entry.names(version):
        ids = ", ".join(entry.ids)
        return said("malicious", f"published to {registry} as malicious ({ids}); never "
                                 "install it", ids=entry.ids)
    private = _reality._private_source(configured, name)
    if private is not None:
        return said("unknown", f"this project takes it from {private[1]}, which valvur "
                               "does not ask", source=private[1])
    if index is None:
        return said("unknown", f"no package-name index for {registry}; run `valvur update`")
    exists = index.contains(key)
    near = (_reality._near_miss(name, popular)
            if _ecosystems.get(ecosystem).near_miss else None)
    on = f"per the index built {built or 'on an unrecorded date'}"
    if not exists and configured.supplemental:
        source = configured.supplemental[0]
        return said("confusion", f"not on {registry}, and this project also installs from "
                                 f"{source}: whoever registers it on {registry} is installed "
                                 f"next ({on})", source=source, exists=False)
    if not exists and configured.replaced:
        return said("not-public", f"not on {registry}; this project installs from "
                                  f"{configured.replaced}. Reserve the name on {registry} "
                                  f"({on})", source=configured.replaced, exists=False)
    if near:
        return said("near-miss", f"one character from the far more popular '{near}'"
                                 + ("" if exists else f", and not on {registry}")
                                 + f" ({on})", near=near, exists=exists)
    if not exists:
        return said("nonexistent", f"not on {registry} ({on}): almost certainly "
                                   "hallucinated, and whoever registers it is installed "
                                   "next", exists=False)
    return said("exists", f"on {registry} ({on})", exists=True)
