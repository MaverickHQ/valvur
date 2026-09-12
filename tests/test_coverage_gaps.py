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

#: An ecosystem valvur recognises and does not read at all. There is none left in
#: `MANIFESTS` since 23.2.2 and 23.2.3 read Ruby, PHP and Rust, so the wording for one is
#: pinned against a hypothetical entry — the next ecosystem someone adds to `sees`
#: before writing its parser gets this sentence, not silence.
def _with_unread_ecosystem(monkeypatch):
    from valvur import ecosystems as _ecosystems

    extended = dict(_ecosystems.MANIFESTS)
    extended["nuget"] = _ecosystems.Manifests("NuGet", sees=("*.csproj", "packages.lock.json"))
    monkeypatch.setattr(_ecosystems, "MANIFESTS", extended)


def test_an_ecosystem_with_no_existence_check_says_so(tmp_path, monkeypatch):
    _with_unread_ecosystem(monkeypatch)

    gaps = coverage.dependency_gaps(_repo(tmp_path, {"app.csproj": "<Project/>"}))

    assert len(gaps) == 1
    assert "NuGet" in gaps[0].title
    assert "no existence check for NuGet at all" in gaps[0].evidence
    assert "missing coverage rather than a clean result" in gaps[0].evidence


@pytest.mark.parametrize("manifest,label", [
    # `sees` only: the ecosystem is read, but not through this file. A Pipenv
    # project with no requirements file or pyproject, a Rust tree with only its
    # lockfile — each is a real gap and the note names what would close it.
    ("Pipfile", "Python"),
    ("setup.py", "Python"),
    ("Cargo.lock", "Rust (Cargo)"),
    ("Gemfile.lock", "Ruby (Bundler)"),
    ("composer.lock", "PHP (Composer)"),
])
def test_a_manifest_we_see_but_do_not_read_is_a_gap_when_alone(tmp_path, manifest, label):
    gaps = coverage.dependency_gaps(_repo(tmp_path, {manifest: "x"}))

    assert len(gaps) == 1
    assert label in gaps[0].title
    assert "It reads " in gaps[0].evidence and "none is present here" in gaps[0].evidence
    assert "missing coverage rather than a clean result" in gaps[0].evidence


@pytest.mark.parametrize("manifest", [
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json",
    # Read since 22.A.4, on `full` only. On `offline` that is a Profile omission
    # stated in the Coverage contract and the Summary's caveat (F7.16), not a gap
    # Finding — the same rule osv-scanner follows.
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle/libs.versions.toml", "go.mod",
    # Read since 23.2.2 and 23.2.3, offline, from the index.
    "Gemfile", "app.gemspec", "composer.json", "Cargo.toml",
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
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": "[packages]\n"}))

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
        "infra/Pipfile": "", "Pipfile": "", "a/b/c/Pipfile": "",
    }))

    assert gaps[0].path == "Pipfile"


def test_the_manifest_is_reported_before_its_lockfile(tmp_path):
    """Same depth, and the lockfile sorts first alphabetically — so a plain
    depth-then-name rule sent the reader to the generated file instead of the one they
    wrote. Measured on a real Rust project before 23.2.3 read `Cargo.toml`: the gap
    pointed at `Cargo.lock`. Every `sees` tuple lists its manifests before its
    lockfiles; `setup.py` is declared before `poetry.lock` and sorts after it."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"poetry.lock": "", "setup.py": ""}))

    assert gaps[0].path == "setup.py"


# ------------------------------------------------------------------ the old rules

def test_one_gap_per_ecosystem_not_per_file(tmp_path):
    """A monorepo with forty `Pipfile`s has one gap, not forty — the lesson the
    licence Check learned when 618 undeclared dependencies buried two dozen CVEs."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {
        f"{d}/Pipfile": "" for d in "abcd"
    }))

    assert len(gaps) == 1
    assert "and 1 more" in gaps[0].evidence


def test_a_vendored_manifest_is_not_our_gap(tmp_path):
    """`node_modules` is full of other people's manifests. Reporting them would make
    the notice worthless on any repository that has ever installed anything."""
    assert coverage.dependency_gaps(_repo(tmp_path, {
        "node_modules/left-pad/Pipfile": "",
        "vendor/github.com/x/go.mod": "",
    })) == []


def test_a_repository_with_no_manifests_at_all_has_no_gap(tmp_path):
    """Nothing to declare. A gap here would fire on every repository in existence."""
    assert coverage.dependency_gaps(_repo(tmp_path, {"main.py": "print(1)\n"})) == []


def test_the_gap_is_low_severity_not_a_defect_in_your_code(tmp_path):
    """It is our missing coverage, not the user's bug. Ranking it alongside a
    hallucinated dependency would be dishonest in the other direction."""
    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": "[packages]\n"}))

    assert gaps[0].severity == "low"


def test_the_identity_is_the_ecosystem_so_the_finding_is_stable(tmp_path):
    """A gap moving fingerprint between scans would make it unsuppressible and would
    read as fixed-then-regressed forever (ADR-0003)."""
    one = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": ""}))
    two = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": "", "x/Pipfile": ""}))

    assert one[0].fingerprint == two[0].fingerprint


def test_rewording_a_label_does_not_move_the_fingerprint(tmp_path, monkeypatch):
    """The identity is the canonical ecosystem key, never the display label.

    Added after a mutation that keyed it on the label passed every other test in this
    file: the table has one entry per ecosystem, so the *count* assertions could not
    tell the difference. The property they missed is this one — a label is prose, and
    prose gets edited. "Python" becoming "Python (pip)" would silently invalidate every
    committed suppression on that gap, in every repository using valvur, for a wording
    change (ADR-0003).
    """
    from valvur import ecosystems as _ecosystems

    before = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": ""}))[0].fingerprint

    reworded = dict(_ecosystems.MANIFESTS)
    reworded["pip"] = _ecosystems.Manifests("Python (pip)", reads=("requirements*.txt",),
                                            sees=("Pipfile",))
    monkeypatch.setattr(_ecosystems, "MANIFESTS", reworded)

    after = coverage.dependency_gaps(tmp_path)[0]

    assert after.title != before, "the mutation did not change what a reader sees"
    assert after.fingerprint == before


# --------------------------------------------------------- declared coverage (19.E.1)

def test_an_adapter_declares_what_it_reads_and_what_it_ignores(tmp_path):
    declared = REALITY.coverage(tmp_path)

    assert any("requirements*.txt" in line for line in declared.inspects)
    assert any("package.json" in line for line in declared.inspects)
    assert any("Gemfile" in line for line in declared.inspects)
    assert any("composer.json" in line for line in declared.inspects)
    assert any("Cargo.toml" in line for line in declared.inspects)
    assert any("JVM" in line and "`full` only" in line for line in declared.ignores)
    # Stated rather than left for a reader to infer from silence: names are checked
    # for existence in every indexed ecosystem but compared against a popular-name
    # corpus only for PyPI, because only PyPI's ships in the image.
    assert any("near-miss" in line and "PyPI only" in line for line in declared.ignores)


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

def test_a_coverage_gap_does_not_read_as_a_problem_in_your_code(tmp_path):
    """**Decided in Block 3 (19.C.2, 19.E.2).** This test previously pinned the
    opposite, so that changing it had to be deliberate. It is now deliberate.

    A coverage gap made `status` read `findings`, so any repository containing a
    `Cargo.toml` (unread until 23.2.3) could never report `clean` — a permanently
    negative verdict about something the user cannot fix. `findings` means *we found
    problems in your code*, and this is our limitation.

    `inconclusive` is the honest answer, and it is the same claim the word already
    carries for a stale database: **we did not look, so "clean" is not ours to
    claim.**
    """
    from valvur.api import ScanRun

    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": ""}))
    run = ScanRun(findings=list(gaps))

    assert run.status == "inconclusive"
    assert run.active == []
    assert len(run.coverage_notes) == 1


def test_a_gap_never_fails_someone_else_s_build(tmp_path):
    """The consequence that decided it. A release gate keyed on active findings must
    not go red because valvur does not read a Pipfile — the user cannot fix that, and
    a gate nobody can turn green is a gate that gets deleted."""
    from valvur.api import ScanRun

    gaps = coverage.dependency_gaps(_repo(tmp_path, {"Pipfile": "[packages]\n"}))

    assert ScanRun(findings=list(gaps)).active == []
    # But it is still reported, never hidden — that is the whole point of 19.D.3.
    assert ScanRun(findings=list(gaps)).coverage_notes


# ------------------------------------ 22.E.1: the corpus's first finding, pinned

def _vuln_gaps(tmp_path, files):
    return [g.title for g in coverage.vulnerability_gaps(_repo(tmp_path, files))]


@pytest.mark.parametrize("files,label", [
    ({"package.json": "{}"}, "npm"),
    ({"pyproject.toml": "[project]\nname='x'\n"}, "Python"),
    ({"Gemfile": "gem 'rack'\n"}, "Ruby (Bundler)"),
    ({"Cargo.toml": "[package]\n"}, "Rust (Cargo)"),
    ({"composer.json": "{}"}, "PHP (Composer)"),
    ({"build.gradle": "dependencies {}\n"}, "JVM (Maven/Gradle)"),
])
def test_a_manifest_with_no_lockfile_is_a_vulnerability_gap(tmp_path, files, label):
    """Measured 2026-09-12 with the image's Trivy: each of these alone produces NO
    RESULTS — not zero vulnerabilities, no scan. Express, which commits no lockfile,
    read `clean` with thirty dependencies never checked; the public corpus found it
    on its first run. Now it is a coverage note, and the run is `inconclusive`."""
    titles = _vuln_gaps(tmp_path, files)

    assert titles == [f"{label} dependencies were not checked for known vulnerabilities"]


@pytest.mark.parametrize("files", [
    {"package.json": "{}", "package-lock.json": "{}"},
    {"package.json": "{}", "yarn.lock": ""},
    {"package.json": "{}", "pnpm-lock.yaml": ""},
    {"pyproject.toml": "", "requirements.txt": "x==1\n"},
    {"pyproject.toml": "", "uv.lock": ""},
    {"pyproject.toml": "", "poetry.lock": ""},
    {"Gemfile": "", "Gemfile.lock": ""},
    {"Cargo.toml": "", "Cargo.lock": ""},
    {"go.mod": "module x\n"},
    {"pom.xml": "<project/>"},
    {"composer.json": "{}", "composer.lock": "{}"},
])
def test_what_trivy_reads_is_not_a_gap(tmp_path, files):
    """The pair, from the same measurement: `package-lock.json`, `requirements.txt`,
    `go.mod` and `pom.xml` each produced findings on their own."""
    assert _vuln_gaps(tmp_path, files) == []


def test_a_vendored_manifest_without_a_lockfile_is_not_our_gap(tmp_path):
    assert _vuln_gaps(tmp_path, {"node_modules/x/package.json": "{}"}) == []


def test_the_vulnerability_gap_is_a_note_that_makes_a_nil_result_inconclusive(tmp_path):
    """Same rule as the existence gap (19.E.2): not active, not the user's defect,
    and `clean` is not ours to claim over it."""
    from valvur.api import ScanRun

    gaps = coverage.vulnerability_gaps(_repo(tmp_path, {"package.json": "{}"}))
    run = ScanRun(findings=list(gaps))

    assert run.active == []
    assert run.coverage_notes == gaps
    assert run.status == "inconclusive"
    assert "npm dependencies: known vulnerabilities" in run.status_reason


def test_the_trivy_adapter_declares_the_gap_through_the_contract(tmp_path):
    from valvur.adapters import TrivyAdapter

    declared = TrivyAdapter().coverage(_repo(tmp_path, {"package.json": "{}"}))

    assert any("npm: package-lock.json" in line for line in declared.inspects)
    assert [g.rule for g in declared.gaps] == [coverage.VULNERABILITY_RULE]
    assert declared.gaps[0].sources == ("trivy",)


def test_both_gaps_can_stand_on_one_repository(tmp_path):
    """A Pipenv project without a lockfile has two different things nobody checked:
    existence (nothing reads a Pipfile) and known vulnerabilities (no Pipfile.lock).
    Two notes, two identities, both named in the reason."""
    from valvur.api import ScanRun

    ws = _repo(tmp_path, {"Pipfile": "[packages]\nrequests = '*'\n"})
    notes = coverage.dependency_gaps(ws) + coverage.vulnerability_gaps(ws)
    run = ScanRun(findings=list(notes))

    assert len({n.fingerprint for n in notes}) == 2
    assert run.status_reason.count("Python dependencies:") == 2
