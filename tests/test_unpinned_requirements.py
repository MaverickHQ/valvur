"""Task 25.3 — unpinned requirements are not a check.

Found by Block A's corpus dispatch (2026-09-18) on smolagents'
`examples/open_deep_research/requirements.txt`: 39 lines, none pinned. Two defects in
one file. On `offline`, Trivy reads the file and reports nothing — correct, a range is
not a version — and valvur's lockfile coverage note stays silent because a
`requirements*.txt` is present, so the dependencies read as *checked* when nothing
was: a silent clean. On `full`, OSV-Scanner evaluates each range at its lower bound
and reports every advisory since — 110 there, against versions nobody installs.

So: a requirements file with no pins is the lockfile gap (22.E.1's treatment — a
coverage note in `DOUBT_RULES`, the run `inconclusive`), a mixed file is *partly*
checked and the note says which, and OSV-Scanner's lower-bound findings are dropped
with the count on every surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import coverage, pipeline, requirements
from valvur.api import ScanRun
from valvur.findings import Dependency, Finding

UNPINNED = "anthropic>=0.37.1\nbeautifulsoup4>=4.12.3\ntransformers>=4.46.0\ntorch>=2.2.2\n"
PINNED = "urllib3==1.24.1\nPyYAML==5.1\nPillow==10.0.0\n"


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


# ------------------------------------------------------------ reading a line

@pytest.mark.parametrize("line,expected", [
    ("transformers>=4.46.0", ("transformers", False)),
    ("torch>=2.2.2,<3", ("torch", False)),
    ("numpy", ("numpy", False)),                       # any version at all
    ("pypdf~=3.1", ("pypdf", False)),
    ("pillow==10.*", ("pillow", False)),               # a wildcard is a range
    ("urllib3==1.24.1", ("urllib3", True)),
    ("PyYAML == 5.1", ("pyyaml", True)),
    ("Pillow===10.0.0", ("pillow", True)),
    ("requests[security]==2.31.0", ("requests", True)),
    ("zope.interface==5.4", ("zope-interface", True)),
    ('markdown_it-py==3.0 ; python_version >= "3.9"', ("markdown-it-py", True)),
    ("audioop-lts<1.0; python_version >= '3.13'  # comment", ("audioop-lts", False)),
])
def test_a_dependency_line_is_a_version_or_a_range(line, expected):
    assert requirements.classify(line) == expected


@pytest.mark.parametrize("line", [
    "", "   ", "# a comment", "-r base.txt", "--index-url https://x/simple",
    "-e .", "some-tool @ git+https://github.com/example/some-tool.git@main",
    "https://example.com/pkg-1.0.tar.gz", "./local/path",
])
def test_lines_that_are_not_registry_dependencies_are_not_counted(line):
    """Options, comments, editable and direct references: neither pinned nor a
    range. The mutable-ref rule covers the git reference; nothing here does."""
    assert requirements.classify(line) is None


def test_a_hash_locked_file_is_pins_all_the_way_down(tmp_path):
    """pip-compile's `pkg==1.0 \\` with the hashes on continuation lines. Found by
    valvur's own self-scan on the first CI run of 25.3: 95 of 97 pins in the
    hash-locked Checkov requirements read as ranges, OSV's one Finding there was
    dropped, and the committed suppression on it lapsed — the gate failed at every
    threshold, as it should."""
    path = tmp_path / "requirements-checkov.txt"
    path.write_text(
        "ecdsa==0.19.2 \\\n"
        "    --hash=sha256:aaaa \\\n"
        "    --hash=sha256:bbbb\n"
        "    # via python-jose\n"
        "asteval==1.0.10 \\\n"
        "    --hash=sha256:cccc\n"
    )

    assert requirements.pins(path) == (2, 0)
    assert requirements.read(path) == {"ecdsa": True, "asteval": True}


def test_the_repositorys_own_hash_locked_requirements_are_pins():
    from conftest import FIXTURES

    pinned, loose = requirements.pins(FIXTURES.parent.parent / "requirements-checkov.txt")

    assert loose == 0 and pinned > 90


def test_a_file_is_summarised_by_its_pins(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("# header\n" + PINNED + UNPINNED + "-r other.txt\n")

    assert requirements.pins(path) == (3, 4)
    assert requirements.read(path) == {
        "urllib3": True, "pyyaml": True, "pillow": True,
        "anthropic": False, "beautifulsoup4": False, "transformers": False, "torch": False,
    }


# ---------------------------------------------- (1) the coverage note, offline

def test_a_requirements_file_with_no_pins_is_a_vulnerability_gap(tmp_path):
    """The smolagents shape. Trivy read the file and found nothing; the note has to
    say why that is not a clean result."""
    ws = _repo(tmp_path, {"examples/deep/requirements.txt": UNPINNED})

    [gap] = coverage.vulnerability_gaps(ws)

    assert gap.rule == coverage.VULNERABILITY_RULE
    assert gap.title == "Python dependencies were not checked for known vulnerabilities"
    assert "examples/deep/requirements.txt" in gap.evidence
    assert "4 of 4" in gap.evidence and "range" in gap.evidence
    assert "pin" in gap.evidence.lower() and "lockfile" in gap.evidence
    assert ScanRun(findings=[gap]).status == "inconclusive"


def test_a_fully_pinned_requirements_file_is_a_check(tmp_path):
    ws = _repo(tmp_path, {"requirements.txt": PINNED})

    assert coverage.vulnerability_gaps(ws) == []


def test_a_mixed_file_is_partly_checked_and_the_note_says_which(tmp_path):
    ws = _repo(tmp_path, {"requirements.txt": PINNED + UNPINNED})

    [gap] = coverage.vulnerability_gaps(ws)

    assert "4 of 7" in gap.evidence
    assert "requirements.txt" in gap.evidence
    assert ScanRun(findings=[gap]).status == "inconclusive"


def test_a_lockfile_beside_an_unpinned_file_is_the_check(tmp_path):
    """The lockfile is the resolved truth; a loose requirements file beside it —
    an example, a docs build — does not undo it."""
    ws = _repo(tmp_path, {"uv.lock": "version = 1\n", "docs/requirements.txt": UNPINNED})

    assert coverage.vulnerability_gaps(ws) == []


def test_one_pinned_file_does_not_cover_an_unpinned_one(tmp_path):
    """Two files, one checked: the unpinned one's dependencies were still never
    inspected, and the note names it and only it."""
    ws = _repo(tmp_path, {"requirements.txt": PINNED, "examples/requirements.txt": UNPINNED})

    [gap] = coverage.vulnerability_gaps(ws)

    assert "examples/requirements.txt" in gap.evidence
    assert "4 of 4" in gap.evidence


def test_the_broken_repo_fixture_is_still_fully_checked():
    """Its three requirements files are pins and one git reference: no note, so
    every golden and canary count stands."""
    from conftest import FIXTURES

    assert coverage.vulnerability_gaps(FIXTURES / "broken-repo") == []


def test_the_gap_keeps_the_ecosystem_identity_so_a_suppression_travels(tmp_path):
    unpinned = coverage.vulnerability_gaps(_repo(tmp_path / "a", {"requirements.txt": UNPINNED}))
    no_lock = coverage.vulnerability_gaps(
        _repo(tmp_path / "b", {"pyproject.toml": "[project]\nname='x'\n"}))

    assert unpinned[0].fingerprint == no_lock[0].fingerprint


# ------------------------------------- (2) OSV-Scanner's lower bounds, on full

def _osv(package: str, path: str = "requirements.txt", version: str = "4.46.0") -> Finding:
    return Finding(
        rule=f"CVE-{package}", path=path, line=0, title=f"{package} {version}", evidence="",
        fingerprint=f"fp-{package}-{path}", severity="high", sources=("osv-scanner",),
        dependency=Dependency(ecosystem="pip", package=package, version=version),
    )


def _ctx(workspace: Path) -> pipeline.Context:
    from valvur.adapters import DEFAULT_ADAPTERS

    return pipeline.Context(
        workspace=workspace, profile="full", network=True,
        declaring=[a.for_profile(network=True) for a in DEFAULT_ADAPTERS],
    )


def test_an_osv_finding_against_an_unpinned_range_is_dropped_and_counted(tmp_path):
    ws = _repo(tmp_path, {"requirements.txt": PINNED + UNPINNED})
    ctx = _ctx(ws)

    kept = pipeline.unpinned(
        [_osv("transformers"), _osv("torch"), _osv("urllib3", version="1.24.1")], ctx)

    assert [f.dependency.package for f in kept] == ["urllib3"]
    assert ctx.unpinned_dropped == 2
    assert ctx.unpinned_files == ("requirements.txt",)


def test_a_trivy_finding_on_the_same_file_is_never_touched(tmp_path):
    """Trivy reports pinned lines only; what it reports is a version. Only
    OSV-Scanner evaluates a range, so only its Findings are in question."""
    ws = _repo(tmp_path, {"requirements.txt": UNPINNED})
    trivy = Finding(rule="CVE-x", path="requirements.txt", line=0, title="t", evidence="",
                    fingerprint="fp-t", severity="high", sources=("trivy",),
                    dependency=Dependency(ecosystem="pip", package="transformers",
                                          version="4.46.0"))
    ctx = _ctx(ws)

    assert pipeline.unpinned([trivy], ctx) == [trivy]
    assert ctx.unpinned_dropped == 0


def test_a_package_the_file_does_not_name_is_kept(tmp_path):
    """Unknown is not unpinned: a finding whose package the file does not list —
    a transitive one, a name the parser did not resolve — stays."""
    ws = _repo(tmp_path, {"requirements.txt": UNPINNED})
    ctx = _ctx(ws)

    kept = pipeline.unpinned([_osv("some-transitive")], ctx)

    assert len(kept) == 1 and ctx.unpinned_dropped == 0


def test_the_stage_runs_after_the_filters_and_before_merge():
    names = [s.name for s in pipeline.PIPELINE]

    assert names.index("configured") < names.index("unpinned") < names.index("merged")


def test_the_dropped_count_reaches_run_json_and_summary(tmp_path):
    from valvur import results

    run = ScanRun(findings=[], unpinned_dropped=110,
                  unpinned_files=("examples/open_deep_research/requirements.txt",))
    results.write(tmp_path, run)

    data = json.loads((tmp_path / ".security-scan" / "run.json").read_text())
    assert data["excluded_unpinned"] == {
        "advisories_dropped": 110, "files": ["examples/open_deep_research/requirements.txt"]}
    summary = (tmp_path / ".security-scan" / "SUMMARY.md").read_text()
    assert "110" in summary and "lower bound" in summary
    assert "examples/open_deep_research/requirements.txt" in summary


def test_nothing_dropped_writes_nothing_loud(tmp_path):
    from valvur import results

    results.write(tmp_path, ScanRun(findings=[]))

    data = json.loads((tmp_path / ".security-scan" / "run.json").read_text())
    assert data["excluded_unpinned"] == {"advisories_dropped": 0, "files": []}
    assert "lower bound" not in (tmp_path / ".security-scan" / "SUMMARY.md").read_text()


def test_end_to_end_the_smolagents_shape_reads_inconclusive_with_the_count(tmp_path, monkeypatch):
    """Through `api.scan` with a fake fleet: an unpinned file, OSV's lower-bound
    findings arriving, nothing else. Before 25.3 this read `findings` with 110 of
    them on `full` and `clean` on `offline`; now it is `inconclusive` on both, the
    note names the file, and the count is on the surfaces."""
    from conftest import FakeRunner

    from valvur import api, cache
    from valvur.adapters import OsvAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = _repo(tmp_path / "ws", {"examples/requirements.txt": UNPINNED})

    class Osv(OsvAdapter):
        def parse(self, output):
            return [_osv("transformers", "examples/requirements.txt"),
                    _osv("torch", "examples/requirements.txt")]

    run = api.scan(ws, runner=FakeRunner(), adapters=[Osv().for_profile(network=True)],
                   profile="full")

    assert run.status == "inconclusive"
    assert "Python dependencies: known vulnerabilities" in run.status_reason
    assert run.active == []
    assert run.unpinned_dropped == 2
