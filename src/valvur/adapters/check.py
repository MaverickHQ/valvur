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

from .. import fingerprint as _fp
from ..coverage import Coverage
from ..findings import Finding
from ..invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput
from ..version import __version__ as _VERSION
from .base import ScannerAdapter

INDEX_REFUSAL = (
    "Package-name index not present, so dependency existence cannot be checked "
    "offline. Fetch it once with:\n"
    "  valvur update\n"
    "Scans then verify package names against the cached index (ADR-0018)."
)


class BatchUnsupported(RuntimeError):
    """The image predates the Checks batch (23.4.2): its entry point knows one
    Check at a time, and says so with `usage:` and exit 2. Not a failure — the
    Checks run one by one, as they did."""


def _refuses_offline(name: str, network: bool) -> bool:
    """dependency-reality without an index and without a network has nothing to
    answer from. Decided here, before a container starts, so the message leads
    with the fix rather than arriving as the Check's stderr; the Check refuses
    too, in case the mount is empty or partial — this is the version a
    first-time user actually reads."""
    from .. import cache

    return name == "dependency-reality" and not network and not cache.name_index_present()


def single_command(name: str, *, network: bool) -> Invocation:
    return Invocation(
        tool=name, version=_VERSION,
        argv=("python", "-m", "valvur.checks", name, "/workspace"),
        report=None, network=network, timeout=600, empty_when=NOTHING_TO_SCAN,
    )


def batch_command(names, *, network: bool) -> tuple[Invocation | None, dict[str, ScannerOutput]]:
    """One container for several Checks (23.4.2): the Invocation for the ones
    that can run, and the outputs of the ones refused before launching. The
    container carries the Profile's grant — `network` is True only when a Check
    in the batch was granted one, which is dependency-reality on `full` — and
    the batch runs that Check last."""
    refused = {
        name: ScannerOutput(name, _VERSION, "", INDEX_REFUSAL, 1)
        for name in names if _refuses_offline(name, network)
    }
    remaining = [name for name in names if name not in refused]
    if not remaining:
        return None, refused
    return Invocation(
        tool="checks", version=_VERSION,
        argv=("python", "-m", "valvur.checks", "batch", "/workspace", *remaining),
        report=None, network=network, timeout=600, empty_when=NOTHING_TO_SCAN,
    ), refused


def split_batch(batch: ScannerOutput, names) -> dict[str, ScannerOutput]:
    """Each Check's output out of the batch report, under its own name, as the
    single command would have given it."""
    if batch.exit_code == 2 and "usage:" in batch.stderr:
        raise BatchUnsupported("the image predates the Checks batch; running the Checks one by one")
    try:
        report = json.loads(batch.stdout) if batch.exit_code == 0 else None
        if not isinstance(report, dict):
            report = None
    except ValueError:
        report = None
    outputs: dict[str, ScannerOutput] = {}
    for name in names:
        if report is None:
            detail = batch.stderr.strip()[:300] or f"exit {batch.exit_code}"
            outputs[name] = ScannerOutput(
                name, _VERSION, "",
                f"the Checks container produced no batch report ({detail})",
                batch.exit_code or 99, argv=batch.argv
            )
            continue
        entry = report.get(name) or {"ok": False, "findings": [],
                                     "error": "missing from the batch report"}
        if not entry.get("ok"):
            # No report, so the fleet records the failure with the Check's own
            # error as the reason. Until 26.2.1 this carried `"[]"` as stdout —
            # and a non-empty report with a non-zero exit is how a Scanner that
            # found nothing looks, so a Check that raised inside the batch was
            # recorded ok with zero findings and its error dropped. Found by the
            # fakes' bridge reproducing the real report shape; a latent defect
            # since 23.4.2, never reached by a test because the fakes answered
            # per Check with empty stdout.
            outputs[name] = ScannerOutput(
                name, _VERSION, "", entry.get("error") or "the Check reported a failure", 1,
                argv=batch.argv)
            continue
        outputs[name] = ScannerOutput(
            name, _VERSION, json.dumps(entry.get("findings") or []), entry.get("error") or "", 0,
            argv=batch.argv)
    return outputs


def run_batch(runner, names, workspace: Path, *, network: bool) -> dict[str, ScannerOutput]:
    """Several Checks, one container, each output under its own name — the
    composition the fleet uses. Raises BatchUnsupported for an image that knows
    one Check at a time."""
    names = list(names)
    invocation, outputs = batch_command(names, network=network)
    if invocation is None:
        return outputs
    remaining = [name for name in names if name not in outputs]
    outputs.update(split_batch(runner.run(invocation, workspace), remaining))
    return outputs


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
        return single_command(self.name, network=self.network)

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = ()) -> Coverage:
        """Forwarded to the Check, which is the only thing that knows (22.D.3). The
        adapter used to answer this itself by testing `self.name` — ADR-0013's
        boundary crossed the wrong way, and a second place a Check's limits could
        be stated and drift from the first."""
        from ..checks import REGISTRY

        check = REGISTRY.get(self.name)
        if check is None:
            return Coverage()
        return check.coverage(workspace, exclude, network=self.network)

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
                    **({"severity": item["severity"]} if item.get("severity") else {}),
                )
            )
        return findings
