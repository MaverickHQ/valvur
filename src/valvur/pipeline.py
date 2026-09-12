"""The post-fleet pipeline: what happens to Findings after the Scanners return.

Named stages in a declared order (task 22.D.1). For three days blocks added stages
to `api._scan_locked` by inserting them inline, and the ordering bug that produces
was already met once: Block 2 loaded the configured exclusions *after* the coverage
gap that needed them. Inline code has no place to say why one step precedes another.
This does — each Stage carries its constraint, and `tests/test_pipeline.py` pins the
sequence so a stage that moves fails a test rather than a user.

A stage is a pure function of the Findings and the run's Context. It may read the
Context, and may record what it dropped or decided into it; it never touches the
Workspace beyond reading files, and it never writes the Results Folder — that is
`results.write`, after the last stage, and not a stage.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import coverage as _coverage
from . import enrichment as _enrichment
from . import exclusions as _exclusions
from . import gitcontext as _gitcontext
from . import licence_policy as _licence
from . import ranking as _ranking
from . import results as _results
from . import state as _state
from . import suppressions as _suppressions
from .findings import Finding, merge


@dataclass
class Context:
    """Everything a stage may need, and everything it may leave behind."""

    workspace: Path
    profile: str
    network: bool
    #: The adapters whose coverage contract is collected — every one in the
    #: registry, each already told what this Profile permits.
    declaring: list
    #: (artifact name, body) pairs the fleet produced — the SBOM, for the licence stage.
    artifacts: list[tuple[str, str]] = field(default_factory=list)

    # ---- recorded by stages, read when the ScanRun is assembled
    configured: tuple[str, ...] = ()
    coverage: dict = field(default_factory=dict)
    vendored_dropped: int = 0
    config_dropped: int = 0
    provider: _enrichment.LocalProvider | None = None
    previous: dict[str, str] = field(default_factory=dict)
    previously_fixed: set[str] = field(default_factory=set)
    identity_reset: tuple[object, int] | None = None


StageFn = Callable[[list[Finding], Context], list[Finding]]


@dataclass(frozen=True)
class Stage:
    name: str
    apply: StageFn
    #: Why this stage sits where it does — the constraint the order encodes. Kept
    #: beside the code, because a constraint stated only in a commit message is one
    #: the next insertion does not see.
    why_here: str


# ----------------------------------------------------------------------- stages

def coverage(findings: list[Finding], ctx: Context) -> list[Finding]:
    """Coverage gaps from the whole registry, not this Profile's selection (19.E.1).

    Outside the fleet on purpose: a coverage limit is a static fact about the
    Workspace, needs no container and no socket, and stays true on every Profile.
    It used to live inside the dependency-reality Check, which the default Profile
    did not run — so the one message saying "this scan could not help you" was
    missing exactly where it mattered.
    """
    ctx.configured = tuple(_exclusions.load_configured(ctx.workspace))
    ctx.coverage = _coverage.collect(ctx.declaring, ctx.workspace, ctx.configured)
    gaps = [g for a in ctx.declaring for g in a.coverage(ctx.workspace, ctx.configured).gaps]
    return findings + gaps


def licence(findings: list[Finding], ctx: Context) -> list[Finding]:
    """Dependency licence policy, read from the SBOM the fleet just produced (F4.4-F4.6)."""
    sbom = next((body for name, body in ctx.artifacts if name == "sbom.cdx.json"), "")
    if not sbom:
        return findings
    return findings + _licence.evaluate(_licence.project_licence(ctx.workspace), sbom)


def vendored(findings: list[Finding], ctx: Context) -> list[Finding]:
    """Vendored and generated code is not the developer's to fix."""
    kept, ctx.vendored_dropped = _exclusions.filter_findings(findings)
    return kept


def configured(findings: list[Finding], ctx: Context) -> list[Finding]:
    """Paths this project chose not to scan, from its committed config. Never a
    built-in default: silently skipping a project's tests would hide real code."""
    kept, ctx.config_dropped = _exclusions.filter_configured(findings, ctx.configured)
    return kept


def merged(findings: list[Finding], ctx: Context) -> list[Finding]:
    """One Finding per identity, whichever Scanners reported it."""
    return merge(findings)


def gitcontext(findings: list[Finding], ctx: Context) -> list[Finding]:
    """A secret git is not carrying is a local credential, not a leak."""
    return _gitcontext.apply(ctx.workspace, findings)


def enrich(findings: list[Finding], ctx: Context) -> list[Finding]:
    """Exploit intelligence: what the world reports, as opposed to what a Scanner
    asserts. Network use is Profile-gated (F6.3, F6.4)."""
    ctx.provider = _enrichment.LocalProvider()
    return ctx.provider.enrich(findings, network=ctx.network)


def suppress(findings: list[Finding], ctx: Context) -> list[Finding]:
    """Suppressions are policy, applied after detection and enrichment and before
    ranking. They never touch the Fingerprint or the Status diff: a suppressed
    Finding is still present, and un-suppressing it must not read as new."""
    policy = _suppressions.load(ctx.workspace)
    findings = _suppressions.apply(findings, policy)
    return findings + _suppressions.policy_findings(policy, findings)


def rank(findings: list[Finding], ctx: Context) -> list[Finding]:
    return _ranking.apply(findings)


def diff(findings: list[Finding], ctx: Context) -> list[Finding]:
    """new / persisting / fixed / regressed against the previous run (F5.6)."""
    results_dir = ctx.workspace / _results.RESULTS_DIR
    ctx.previous, ctx.previously_fixed = _state.load(results_dir)
    ctx.identity_reset = _state.take_reset()
    return [
        replace(f, status=_state.status_for(f.fingerprint, ctx.previous, ctx.previously_fixed))
        for f in findings
    ]


# -------------------------------------------------------------------- the order

PIPELINE: tuple[Stage, ...] = (
    Stage("coverage", coverage,
          "First, because it loads the configured exclusions every later filter "
          "reads — Block 2 had it after `configured` and the gap was computed "
          "against exclusions that had not been loaded yet."),
    Stage("licence", licence,
          "Before the filters, so a vendored or excluded dependency's licence "
          "Finding is dropped with everything else from that path."),
    Stage("vendored", vendored,
          "Before `merged`: a vendored copy of a finding must not survive by merging "
          "into a real one, and the dropped count must be of raw Findings."),
    Stage("configured", configured,
          "Same as `vendored`, and after it so `config_dropped` counts only what "
          "the project's own config removed."),
    Stage("merged", merged,
          "After every filter and every source of Findings, so identity is settled "
          "once over the final set."),
    Stage("gitcontext", gitcontext,
          "After `merged`, so a secret's git status is decided once per identity "
          "rather than once per Scanner that saw it."),
    Stage("enrich", enrich,
          "After `merged`: one lookup per CVE, not one per duplicate — and before "
          "`rank`, which reads what enrichment attached."),
    Stage("suppress", suppress,
          "After `enrich` and before `rank`: a suppression is a decision about an "
          "enriched Finding, and suppressed Findings rank last."),
    Stage("rank", rank,
          "After everything that changes what a Finding is, and before `diff`, which "
          "does not reorder."),
    Stage("diff", diff,
          "Last. The Status diff is against the FINAL fingerprint set — a Finding "
          "added or removed by any later stage would read as regressed or fixed."),
)


def run(findings: list[Finding], ctx: Context) -> list[Finding]:
    for stage in PIPELINE:
        findings = stage.apply(findings, ctx)
    return findings
