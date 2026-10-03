"""Adapter for valvur's own Checks.

Because Checks run in the container and emit JSON (ADR-0013), they fit the *existing*
adapter contract exactly: `run` invokes the container, `parse` reads the JSON. The
orchestrator needed no change — Checks inherit failure isolation, Profile selection,
concurrency and Provenance from the fleet.

`kind` is what separates them, and it is not cosmetic: we credit **Scanners** by name
and licence (P4), and must never imply that detection we perform ourselves came from
a third-party tool, nor the reverse.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .. import fingerprint as _fp
from ..coverage import Coverage
from ..findings import Dependency, Finding, Severity
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from ..version import __version__ as _VERSION
from .base import ScannerAdapter

if TYPE_CHECKING:
    from ..scancontext import ScanContext

INDEX_REFUSAL = (
    "Package-name index not present, so dependency existence cannot be checked "
    "offline. Fetch it once with:\n"
    "  valvur update\n"
    "Scans then verify package names against the cached index (ADR-0018)."
)


def _refuses_offline(name: str, network: bool) -> bool:
    """dependency-reality without an index and without a network has nothing to
    answer from. Decided here, before a container starts, so the message leads
    with the fix rather than arriving as the Check's stderr; the Check refuses
    too, in case the mount is empty or partial — this is the version a
    first-time user actually reads."""
    from .. import cache

    return name == "dependency-reality" and not network and not cache.name_index_present()


def single_command(name: str, workspace: Path, *, network: bool) -> Invocation:
    from ..checks.dependency_reality import INDEX_ENV, INDEX_MOUNT

    # The index's path by variable, as OSV-Scanner's database is named, so an engine
    # running in the image itself can point it at the job's cache (R8.1).
    env = ((INDEX_ENV, INDEX_MOUNT),) if name == "dependency-reality" else ()
    return Invocation(
        tool=name, version=_VERSION,
        argv=("python", "-m", "valvur.checks", name, "/workspace"),
        report=None, network=network, timeout=600, empty_when=NOTHING_TO_SCAN, env=env,
    )


class CheckAdapter(ScannerAdapter):
    kind = "check"

    def __init__(self, name: str, *, uses_network: bool = False, network: bool = False):
        self.name = name
        #: Whether this Check does more WITH a network — not whether it needs one.
        #: dependency-reality answers existence from the local index either way and
        #: asks a registry for first-publish age only when allowed (ADR-0018).
        self.uses_network = uses_network
        #: What this instance was actually granted. False until `for_profile` says
        #: otherwise, so an adapter taken straight from the registry never reaches out.
        self.network = network

    def for_profile(self, *, network: bool) -> CheckAdapter:
        if not self.uses_network:
            return self
        return CheckAdapter(self.name, uses_network=True, network=network)

    def command(self, workspace: Path) -> Invocation:
        if _refuses_offline(self.name, self.network):
            raise RuntimeError(INDEX_REFUSAL)
        return single_command(self.name, workspace, network=self.network)

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = (),
                 context: ScanContext | None = None) -> Coverage:
        """Forwarded to the Check, which is the only thing that knows (22.D.3). The
        adapter used to answer this itself by testing `self.name` — ADR-0013's
        boundary crossed the wrong way, and a second place a Check's limits could
        be stated and drift from the first."""
        from ..checks import REGISTRY

        check = REGISTRY.get(self.name)
        if check is None:
            return Coverage()
        return check.coverage(workspace, exclude, network=self.network,
                              files=context.files if context is not None else None)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        findings = []
        for item in json.loads(output.stdout or "[]"):
            identity = tuple(item.get("identity") or (item.get("rule", ""), item.get("path", "")))
            findings.append(
                Finding(
                    rule=item.get("rule", ""),
                    path=item.get("path", ""),
                    line=item.get("line", 0),
                    title=item.get("title", ""),
                    evidence=item.get("evidence", ""),
                    fingerprint=_fp.derive(*identity),
                    sources=(output.tool,),
                    # Checks may state their own severity. Without this every Check
                    # finding ranked identically, so a coverage note and a
                    # hallucinated dependency arrived at the same weight.
                    severity=Severity.parse(item.get("severity")),
                    # A package the Check names (D26): what lets OSV-Scanner's
                    # finding for it fold into this one (`findings.merge`).
                    dependency=Dependency(**item["dependency"]) if item.get("dependency")
                    else None,
                )
            )
        return findings
