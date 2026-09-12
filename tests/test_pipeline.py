"""22.D.1 — the post-fleet pipeline has named stages in a pinned order.

The order is a contract with reasons, and Block 2 already broke it once by
inserting a stage inline (`configured` loaded after the coverage gap that read it).
The first test pins the sequence outright; the rest pin the reasons, so a reorder
fails with the consequence named rather than with "the list changed".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from valvur import pipeline
from valvur.adapters import DEFAULT_ADAPTERS
from valvur.findings import Finding

ORDER = [
    "coverage", "licence", "vendored", "configured", "merged",
    "gitcontext", "enrich", "suppress", "rank", "diff",
]


def test_the_stages_run_in_exactly_this_order():
    """Any change here is a change to what a scan means. Make it on purpose, and
    update `why_here` on the stages whose reason moved with them."""
    assert [s.name for s in pipeline.PIPELINE] == ORDER


def test_every_stage_says_why_it_sits_where_it_does():
    for stage in pipeline.PIPELINE:
        assert len(stage.why_here) > 40, f"{stage.name} has no stated ordering reason"


def _ctx(workspace: Path, **overrides) -> pipeline.Context:
    return pipeline.Context(
        workspace=workspace, profile="offline", network=False,
        declaring=[a.for_profile(network=False) for a in DEFAULT_ADAPTERS], **overrides,
    )


def _finding(path: str, rule: str = "CVE-2020-1", source: str = "trivy") -> Finding:
    return Finding(rule=rule, path=path, line=1, title=f"{rule} in {path}", evidence="",
                   fingerprint=f"fp-{rule}-{path}", severity="high", sources=(source,))


# ------------------------------------------------------------------ the reasons

def test_configured_exclusions_are_loaded_before_anything_reads_them(tmp_path):
    """The Block 2 bug. `coverage` loads them; `configured` filters by them; the
    coverage gap itself must respect them. All three need `coverage` first."""
    (tmp_path / ".security-scan.toml").write_text('[scan]\nexclude = ["vendor-ish"]\n')
    (tmp_path / "vendor-ish" / "Cargo.toml").parent.mkdir()
    (tmp_path / "vendor-ish" / "Cargo.toml").write_text("[package]\n")
    ctx = _ctx(tmp_path)

    out = pipeline.run([_finding("vendor-ish/lib.rs"), _finding("src/app.py")], ctx)

    assert ctx.configured == ("vendor-ish",)
    assert [f.path for f in out] == ["src/app.py"], "the excluded path survived"
    assert ctx.config_dropped == 1
    assert not any("Cargo" in f.title for f in out), "the gap ignored the exclusion"


def test_filters_run_before_merge_so_a_vendored_duplicate_cannot_survive_by_merging(tmp_path):
    """Two Scanners report the same identity, one of them at a vendored path. If
    `merged` ran first the pair would collapse into one Finding, and which path it
    kept would decide whether the developer sees it. Filtering first settles it."""
    ctx = _ctx(tmp_path)
    same_identity = "fp-shared"
    real = Finding(rule="r", path="src/a.py", line=1, title="t", evidence="",
                   fingerprint=same_identity, severity="high", sources=("trivy",))
    copy = Finding(rule="r", path="node_modules/x/a.py", line=1, title="t", evidence="",
                   fingerprint=same_identity, severity="high", sources=("osv-scanner",))

    out = pipeline.run([copy, real], ctx)

    assert [f.path for f in out] == ["src/a.py"]
    assert ctx.vendored_dropped == 1
    assert out[0].sources == ("trivy",), "the vendored copy's source merged in"


def test_diff_is_last_so_status_is_computed_over_the_final_set(tmp_path, monkeypatch):
    """A previous run knew `fp-old`. If `diff` ran before `suppress` appended its
    policy Findings, or before `rank` reordered, `fixed` and `new` would be judged
    against an intermediate set. Every Finding leaving the pipeline carries a status
    computed against the previous state, and nothing appended after it lacks one."""
    from valvur import state

    results_dir = tmp_path / ".security-scan"
    results_dir.mkdir()
    state.save(results_dir, {"fp-CVE-2020-1-src/app.py": "old title"}, set())
    ctx = _ctx(tmp_path)

    out = pipeline.run([_finding("src/app.py"), _finding("src/new.py")], ctx)

    statuses = {f.path: f.status for f in out}
    assert statuses == {"src/app.py": "persisting", "src/new.py": "new"}
    assert ctx.previous == {"fp-CVE-2020-1-src/app.py": "old title"}


def test_a_stage_that_is_not_a_pure_function_of_its_inputs_is_caught(tmp_path):
    """Running the pipeline twice over equal inputs gives equal outputs. A stage that
    kept state between runs — the way `state.take_reset()` once did across tests —
    would show up here as drift."""
    findings = [_finding("src/app.py"), _finding("src/b.py", rule="CVE-2020-2")]

    first = pipeline.run(list(findings), _ctx(tmp_path))
    second = pipeline.run(list(findings), _ctx(tmp_path))

    assert first == second


@pytest.mark.parametrize("earlier,later", [
    ("coverage", "configured"), ("vendored", "merged"), ("configured", "merged"),
    ("merged", "enrich"), ("enrich", "suppress"), ("suppress", "rank"), ("rank", "diff"),
])
def test_the_pairwise_constraints_the_reasons_name(earlier, later):
    """Each `why_here` names a stage it must precede or follow. Spelled out so the
    reason and the order cannot drift apart."""
    assert ORDER.index(earlier) < ORDER.index(later)
