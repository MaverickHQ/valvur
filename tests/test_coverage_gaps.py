"""Coverage contracts — a Check that cannot help must say so (19.D.3, 19.D.1, 19.E.1).

Measured 2026-09-10, before any of this existed: an npm project containing a
deliberately non-existent package returned **zero findings**. The Dependency Reality
Check read `requirements*.txt` against PyPI and nothing else, and a repository without
one exited early with nothing at all — indistinguishable from a repository that was
checked and found clean. That is the most distinctive Check in the product (§5.3)
silently absent for the majority of repositories.

19.D.3 added the reporting. A local corpus then found three defects in it, and each
one is pinned below by name, because every one of them made the notice *look* present
while being absent or wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from valvur import coverage
from valvur.adapters import DEFAULT_ADAPTERS, CheckAdapter

REALITY = next(a for a in DEFAULT_ADAPTERS if a.name == "dependency-reality")


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _labels(gaps) -> list[str]:
    return sorted(g.title for g in gaps)


# --------------------------------------------------------------- what is uncovered

@pytest.mark.parametrize("manifest,label", [
    ("Cargo.toml", "Rust (Cargo)"),
    ("go.mod", "Go"),
    ("Gemfile", "Ruby (Bundler)"),
    ("pom.xml", "JVM (Maven/Gradle)"),
    ("composer.json", "PHP (Composer)"),
])
def test_an_ecosystem_with_no_existence_check_says_so(tmp_path, manifest, label):
    gaps = coverage.dependency_gaps(_repo(tmp_path, {manifest: "x"}))

    assert len(gaps) == 1
    assert label in gaps[0].title
    assert "missing coverage rather than a clean result" in gaps[0].evidence


@pytest.mark.parametrize("manifest", [
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json",
])
def test_an_ecosystem_we_now_read_reports_no_gap(tmp_path, manifest):
    """The pair, and the one that had to change when 19.D.1 landed. A gap reported on
    every scan is one nobody reads; it has to mean something."""
    assert coverage.dependency_gaps(_repo(tmp_path, {manifest: "{}"})) == []


def test_a_lockfile_beside_a_manifest_we_read_is_not_a_gap(tmp_path):
    """`poetry.lock` and `pnpm-lock.yaml` carry resolved transitive trees, which are
    not where hallucinated names appear — the invented package is written into the
    file a human or an agent edited. Skipping them is deliberate, not a hole."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {
        "pyproject.toml": "[project]\nname='x'\n", "poetry.lock": "",
        "package.json": "{}", "pnpm-lock.yaml": "",
    }))

    assert gaps == []


def test_a_lockfile_with_no_manifest_we_read_is_a_gap(tmp_path):
    """The pair to the above, and the reason it cannot simply ignore lockfiles: with
    no `package.json` beside it, nothing here inspected a single npm name."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"pnpm-lock.yaml": ""}))

    assert _labels(gaps) == ["npm dependencies were not checked for existence"]


# ------------------------------------------------------- the three corpus defects

def test_the_gap_does_not_depend_on_the_network_profile(tmp_path):
    """**C1**, found by the local corpus. 19.D.3 put this reporting inside the
    Dependency Reality Check, which is registered `needs_network=True` and is therefore
    excluded from the default `offline` Profile. The gap is a static fact about files
    on disk, so the one message saying *this scan could not help you* was absent from
    the Profile almost everyone runs.

    Pinned as a property of the module rather than of the Check: this function must
    never need a runner, a container or a socket.
    """
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.toml": "[package]\n"}))

    assert len(gaps) == 1
    assert not hasattr(coverage.dependency_gaps, "needs_network")


def test_npm_and_pnpm_are_one_ecosystem_not_two(tmp_path):
    """**C2**, and a repeat of a bug this codebase had already fixed once. A monorepo
    reported `npm`, `npm (pnpm)` and `Python` — three gaps for two ecosystems — because
    the table was keyed on *display labels* and "npm" != "npm (pnpm)".

    `ecosystems.py` exists precisely to stop that, and its own docstring describes the
    same failure: 24 CVEs reported twice because Trivy said "pnpm" where osv-scanner
    said "npm". The gap table is keyed on the canonical name now.
    """
    gaps = coverage.dependency_gaps(_repo(tmp_path, {
        "pnpm-lock.yaml": "", "yarn.lock": "", "package-lock.json": "{}",
    }))

    assert len(gaps) == 1, f"expected one npm gap, got {_labels(gaps)}"


def test_the_reported_path_is_the_shallowest_not_an_arbitrary_one(tmp_path):
    """**C3**. The npm gap pointed at `infra/package.json` rather than the root, by
    `rglob` order. Cosmetic, but it is the path a reader opens first."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {
        "infra/Cargo.toml": "", "Cargo.toml": "", "a/b/c/Cargo.toml": "",
    }))

    assert gaps[0].path == "Cargo.toml"


def test_the_manifest_is_reported_before_its_lockfile(tmp_path):
    """Same depth, and `Cargo.lock` sorts first alphabetically — so a plain
    depth-then-name rule sent the reader to the generated file instead of the one they
    wrote. Measured on a real Rust project before this: the gap pointed at
    `Cargo.lock`."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.lock": "", "Cargo.toml": ""}))

    assert gaps[0].path == "Cargo.toml"


# ------------------------------------------------------------------ the old rules

def test_one_gap_per_ecosystem_not_per_file(tmp_path):
    """A monorepo with forty `Cargo.toml` files has one gap, not forty — the lesson the
    licence Check learned when 618 undeclared dependencies buried two dozen CVEs."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {
        f"{d}/Cargo.toml": "" for d in "abcd"
    }))

    assert len(gaps) == 1
    assert "and 1 more" in gaps[0].evidence


def test_a_vendored_manifest_is_not_our_gap(tmp_path):
    """`node_modules` is full of other people's manifests. Reporting them would make
    the notice worthless on any repository that has ever installed anything."""
    assert coverage.dependency_gaps(_repo(tmp_path, {
        "node_modules/left-pad/Cargo.toml": "",
        "vendor/github.com/x/go.mod": "",
    })) == []


def test_a_repository_with_no_manifests_at_all_has_no_gap(tmp_path):
    """Nothing to declare. A gap here would fire on every repository in existence."""
    assert coverage.dependency_gaps(_repo(tmp_path, {"main.py": "print(1)\n"})) == []


def test_the_gap_is_low_severity_not_a_defect_in_your_code(tmp_path):
    """It is our missing coverage, not the user's bug. Ranking it alongside a
    hallucinated dependency would be dishonest in the other direction."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.toml": "[package]\n"}))

    assert gaps[0].severity == "low"


def test_the_identity_is_the_ecosystem_so_the_finding_is_stable(tmp_path):
    """A gap moving fingerprint between scans would make it unsuppressible and would
    read as fixed-then-regressed forever (ADR-0003)."""
    one = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.toml": ""}))
    two = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.toml": "", "x/Cargo.toml": ""}))

    assert one[0].fingerprint == two[0].fingerprint


def test_rewording_a_label_does_not_move_the_fingerprint(tmp_path, monkeypatch):
    """The identity is the canonical ecosystem key, never the display label.

    Added after a mutation that keyed it on the label passed every other test in this
    file: the table has one entry per ecosystem, so the *count* assertions could not
    tell the difference. The property they missed is this one — a label is prose, and
    prose gets edited. "Rust (Cargo)" becoming "Rust" would silently invalidate every
    committed suppression on that gap, in every repository using valvur, for a wording
    change (ADR-0003).
    """
    from valvur import ecosystems as _ecosystems

    before = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.toml": ""}))[0].fingerprint

    reworded = dict(_ecosystems.MANIFESTS)
    reworded["cargo"] = _ecosystems.Manifests("Rust, the language", sees=("Cargo.toml",))
    monkeypatch.setattr(_ecosystems, "MANIFESTS", reworded)

    after = coverage.dependency_gaps(tmp_path)[0]

    assert after.title != before, "the mutation did not change what a reader sees"
    assert after.fingerprint == before


# --------------------------------------------------------- declared coverage (19.E.1)

def test_an_adapter_declares_what_it_reads_and_what_it_ignores(tmp_path):
    declared = REALITY.coverage(tmp_path)

    assert any("requirements*.txt" in line for line in declared.inspects)
    assert any("package.json" in line for line in declared.inspects)
    assert any("Rust" in line for line in declared.ignores)
    # Stated rather than left for a reader to infer from silence: npm names are
    # checked for existence but not compared against a popular-name corpus, because
    # only PyPI's ships in the image.
    assert any("near-miss" in line for line in declared.ignores)


def test_an_adapter_that_has_not_declared_its_limits_claims_nothing(tmp_path):
    """The default is empty, never "covers everything". Recording an undeclared
    adapter as unlimited would be the silent-narrowing failure this exists to remove."""
    quiet = CheckAdapter("licence-file").coverage(tmp_path)

    assert not quiet.declared()
    assert quiet.inspects == () and quiet.ignores == ()


def test_provenance_carries_the_contract(tmp_path):
    collected = coverage.collect(DEFAULT_ADAPTERS, tmp_path)

    assert "dependency-reality" in collected
    assert collected["dependency-reality"]["inspects"]
    # Adapters that declared nothing are absent rather than present-and-empty: an
    # empty declaration and no declaration are different claims.
    assert "licence-file" not in collected


# ------------------------------------------------ an open question, pinned for now

def test_a_coverage_gap_currently_makes_the_run_report_findings(tmp_path, monkeypatch):
    """**Recorded, not endorsed.** A coverage gap is a Finding — ranked, fingerprinted
    and suppressible like any other — so a Workspace with an uncovered ecosystem can no
    longer report `clean`. Any repository with a `Cargo.toml` now reads `findings`.

    That is arguably wrong: `findings` means *we found problems in your code*, and a
    coverage gap is our limitation, not the user's defect. §7 already has the right
    vocabulary for it — `inconclusive` means *we looked, found nothing, and could not
    support the claim* — and that is the same shape.

    Deciding it here would pre-empt **19.C.2 and 19.E.2**, which own the status model
    and run next. This test pins today's behaviour so that changing it has to be
    deliberate rather than incidental, and fails loudly when Block 3 does change it.
    """
    from valvur.api import ScanRun

    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Cargo.toml": ""}))

    assert ScanRun(findings=list(gaps)).status == "findings"
