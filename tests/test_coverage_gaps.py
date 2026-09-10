"""Task 19.D.3 — a Check that cannot help must say so, not stay quiet.

Measured 2026-09-10, before this existed: an npm project containing a deliberately
non-existent package returned **zero findings** from the Dependency Reality Check. It
reads `requirements*.txt` against PyPI and nothing else, and a repository without one
exited early with nothing at all — indistinguishable from a repository that was
checked and found clean.

That is the most distinctive Check in the product (§5.3) being silently absent for the
majority of repositories, which is the failure class this project exists to remove.
Widening the Check is 19.D.1; this is the half that stays true afterwards, because
something is always uncovered.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur.checks import REGISTRY

CHECK = REGISTRY["dependency-reality"]


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _gaps(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["rule"] == "valvur.dependency.ecosystem-not-covered"]


@pytest.mark.parametrize("manifest,ecosystem", [
    ("package.json", "npm"),
    ("pnpm-lock.yaml", "npm (pnpm)"),
    ("Cargo.toml", "Rust (Cargo)"),
    ("go.mod", "Go"),
    ("pyproject.toml", "Python (PEP 621 / Poetry)"),
])
def test_an_uninspected_manifest_is_reported_rather_than_ignored(
    tmp_path, manifest, ecosystem
):
    """Including `pyproject.toml`: the Check reads `requirements*.txt`, so even a
    Python project using the modern standard gets no coverage."""
    gaps = _gaps(CHECK.run(_repo(tmp_path, {manifest: "{}"})))

    assert len(gaps) == 1
    assert ecosystem in gaps[0]["title"]
    assert "not a clean result" in gaps[0]["evidence"]


def test_a_covered_project_reports_no_gap(tmp_path):
    """The pair. A gap reported on every scan is one nobody reads, and this one has to
    mean something the day the widening in 19.D.1 lands."""
    gaps = _gaps(CHECK.run(_repo(tmp_path, {"requirements.txt": "flask==3.0.0\n"})))

    assert gaps == []


def test_one_gap_per_ecosystem_not_per_file(tmp_path):
    """A monorepo with forty `package.json` files has one gap, not forty — the lesson
    the licence Check learned when 618 undeclared dependencies buried two dozen CVEs."""
    gaps = _gaps(CHECK.run(_repo(tmp_path, {
        "a/package.json": "{}", "b/package.json": "{}", "c/package.json": "{}",
        "d/package.json": "{}",
    })))

    assert len(gaps) == 1
    assert "and 1 more" in gaps[0]["evidence"]


def test_a_vendored_manifest_is_not_our_gap(tmp_path):
    """`node_modules` is full of other people's `package.json`. Reporting them would
    make the notice worthless on any repository that has ever run an install."""
    gaps = _gaps(CHECK.run(_repo(tmp_path, {
        "node_modules/left-pad/package.json": "{}",
        "requirements.txt": "flask==3.0.0\n",
    })))

    assert gaps == []


def test_the_gap_is_reported_even_when_nothing_else_runs(tmp_path):
    """The case that mattered. Without a `requirements.txt` the Check used to return
    early with an empty list, so the one repository shape that most needs the warning
    was the one guaranteed not to get it."""
    findings = CHECK.run(_repo(tmp_path, {"package.json": json.dumps(
        {"dependencies": {"totally-not-real-pkg-9931": "1.0.0"}}
    )}))

    assert findings, "an npm project produced no output at all"
    assert _gaps(findings)


def test_the_gap_is_low_severity_not_a_defect_in_your_code(tmp_path):
    """It is our missing coverage, not the user's bug. Ranking it alongside a
    hallucinated dependency would be dishonest in the other direction."""
    gaps = _gaps(CHECK.run(_repo(tmp_path, {"Cargo.toml": "[package]\n"})))

    assert gaps[0]["severity"] == "low"
