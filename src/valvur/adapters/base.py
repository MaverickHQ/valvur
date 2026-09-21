"""What every Scanner adapter must provide.

An adapter owns everything tool-specific: how to invoke it, how to parse its output,
how to turn its paths into Workspace-relative ones, and which Finding Class identity
its results carry. The orchestrator owns none of that — it only sequences adapters,
merges, diffs and writes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from ..coverage import Coverage
from ..findings import Finding
from ..invocation import Invocation, ScannerOutput

CONTAINER_WORKSPACE = "/workspace"


def container_relative(path: str) -> str:
    """Scanners see /workspace; users and Fingerprints need repo-relative paths (F5.4).

    Shared because every Scanner sees the same mount, but adapters may need more:
    Trivy reports target names, Checkov file paths, OSV lockfile paths.
    """
    if path.startswith(CONTAINER_WORKSPACE + "/"):
        return path[len(CONTAINER_WORKSPACE) + 1 :]
    # lstrip takes a CHARACTER SET, not a prefix: "./" ate the leading dot of every
    # dotfile, so Checkov's "/.github/workflows/ci.yml" was reported as
    # "github/workflows/ci.yml" — a path that does not exist, and a Fingerprint
    # keyed on it that no suppression could ever match.
    if path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _undeclared(name: str) -> Invocation:
    """The default until every adapter declares its command (26.2.1 lands in
    three PRs); an adapter that still overrides `run` never reaches it."""
    raise NotImplementedError(f"{name} declares no command")


@runtime_checkable
class ScannerAdapter(Protocol):
    name: str

    def command(self, workspace: Path) -> Invocation:
        """How to invoke this Scanner: its argv, report file, timeout and grants
        (26.2.1). The adapter's, because the adapter is the one thing that knows
        the tool; the runner adds the container and nothing else. An adapter that
        must refuse before launching — Trivy without its database — raises here,
        with the message that leads with the fix."""
        return _undeclared(self.name)

    def run(self, runner, workspace: Path) -> ScannerOutput:
        """Invoke this Scanner through the container-runtime boundary: one call,
        with what `command` describes."""
        return runner.run(self.command(workspace), workspace)

    def parse(self, output: ScannerOutput) -> list[Finding]:
        """Normalise this Scanner's output into Findings."""
        ...

    def applies_to(self, workspace: Path) -> tuple[bool, str]:
        """Whether this Scanner has anything to look at, and the evidence either way.

        Part of the protocol rather than a `getattr` the orchestrator hopes for
        (task 17.3). Introduced for Checkov in 12a.3, it decides whether a Scanner
        runs at all, so the orchestrator calling it unconditionally is what matters:
        an adapter cannot forget to be asked.

        A **misspelled** override still falls back to this default silently — mypy
        accepts an extra method — so `test_applicability.py` covers that case. The
        protocol removes one failure mode, not both.

        The default applies: most Scanners always have something to look at, and a
        Scanner that never declares otherwise should not have to say so.
        """
        return True, ""

    def for_profile(self, *, network: bool) -> ScannerAdapter:
        """This adapter, configured with what the Profile permits (ADR-0018).

        The Profile decides whether anything leaves the machine; an adapter must not
        decide that for itself. Most have no use for the answer and return
        themselves. An adapter that behaves differently with a network returns a
        configured copy, so the registry entry stays one immutable declaration and
        the selection step is the only place a permission is granted.
        """
        return self

    def coverage(self, workspace: Path, exclude: tuple[str, ...] = ()) -> Coverage:
        """What this Scanner reads, what it deliberately does not, and where that
        bites in *this* Workspace (task 19.E.1).

        Distinct from `applies_to`, which answers whether to run at all. This answers
        the question a reader actually has after a clean result: *what did you look
        at?* Adapters are the only place that knows, and the orchestrator asks every
        one of them — including those the Profile did not select, because a limit does
        not stop being true because a Scanner was skipped.

        The default is **empty, not "covers everything"**. An adapter that has not
        declared its limits is recorded as having declared nothing, which is honest;
        recording it as unlimited would be the silent-narrowing failure this method
        exists to remove.
        """
        return Coverage()
