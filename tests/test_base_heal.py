"""R44.9: a base image whose tag has died is replaced (D81u, Requirement 17).

Dependabot follows a tag's digest. It cannot see that the tag itself has stopped moving
while a newer Alpine suffix carries the fixes: `python:3.12-alpine3.22` last moved on
2026-04-19, and 1.5.3 shipped six months of unpatched OpenSSL, musl, xz and zlib.
`scripts/base_heal.py plan` reads each `FROM` tag's last update from Docker Hub, which the
tests answer from `tests/fake_registry.py`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fake_registry import HUB, FakePackageRegistry

REPO = Path(__file__).resolve().parent.parent
BASE_HEAL = REPO / "scripts" / "base_heal.py"
NOW = "2026-10-24T08:00:00Z"
D22, D23, D24 = ("sha256:" + c * 64 for c in "234")
GO = "sha256:" + "a" * 64
DOCKERFILE = f"""\
FROM python:3.12-alpine3.22@{D22} AS opengrep
FROM golang:1.27.4-alpine3.24@{GO} AS trivy
FROM python:3.12-alpine3.22@{D22}
"""
BOTH = [{"os": "linux", "architecture": "amd64"}, {"os": "linux", "architecture": "arm64"},
        {"os": "unknown", "architecture": "unknown"}]


def _tag(name: str, moved: str, digest: str, images: list[dict] | None = None) -> dict:
    return {"name": name, "last_updated": moved, "digest": digest,
            "images": BOTH if images is None else images}


def _hub(repository: str, prefix: str, *tags: dict) -> dict[str, object]:
    return {f"{HUB}/{repository}/tags?page_size=100&name={prefix}":
            {"next": None, "results": list(tags)}}


GOLANG = _hub("golang", "1.27.4-alpine", _tag("1.27.4-alpine3.24", "2026-10-20T07:00:00Z", GO))


def _plan(tmp_path: Path, monkeypatch, answers: dict[str, object], *,
          dockerfile: str = DOCKERFILE) -> tuple[subprocess.CompletedProcess[str], dict]:
    FakePackageRegistry(tmp_path / "registry", answers).install(monkeypatch)
    (tmp_path / "Dockerfile").write_text(dockerfile)
    out = tmp_path / "plan.json"
    run = subprocess.run([sys.executable, str(BASE_HEAL), "plan", "--dockerfile",
                          str(tmp_path / "Dockerfile"), "--now", NOW, "--out", str(out)],
                         capture_output=True, text=True, check=False)
    return run, json.loads(out.read_text()) if out.is_file() else {}


def test_the_incident_of_2026_10_24_replayed(tmp_path, monkeypatch):
    """A regression test, with Docker Hub's real dates for the first two tags as read on
    2026-11-22: 3.22 last moved on 2026-04-19. 3.24 is the newest suffix that still moves."""
    python = _hub("python", "3.12-alpine",
                  _tag("3.12-alpine3.21", "2025-10-13T21:07:25.073005Z", "sha256:" + "1" * 64),
                  _tag("3.12-alpine3.22", "2026-04-19T11:07:20.90466Z", D22),
                  _tag("3.12-alpine3.23", "2026-10-21T08:00:00Z", D23),
                  _tag("3.12-alpine3.24", "2026-10-21T08:00:00Z", D24),
                  _tag("3.12-alpine", "2026-10-21T08:00:00Z", D24))

    run, plan = _plan(tmp_path, monkeypatch, {**python, **GOLANG})

    assert run.returncode == 0, run.stderr
    assert plan["moves"] == [{
        "from": f"python:3.12-alpine3.22@{D22}", "to": f"python:3.12-alpine3.24@{D24}",
        "last_moved": "2026-04-19T11:07:20Z", "days": 187,
        "rule": "unmoved for 30 days, and a newer Alpine suffix moved within 30"}]


def test_a_tag_that_still_moves_is_left_to_dependabot(tmp_path, monkeypatch):
    python = _hub("python", "3.12-alpine",
                  _tag("3.12-alpine3.22", "2026-10-01T00:00:00Z", D22),
                  _tag("3.12-alpine3.24", "2026-10-21T08:00:00Z", D24))

    _run, plan = _plan(tmp_path, monkeypatch, {**python, **GOLANG})

    assert plan["moves"] == []


def test_a_dead_tag_with_no_newer_suffix_that_moves_is_no_move(tmp_path, monkeypatch):
    python = _hub("python", "3.12-alpine",
                  _tag("3.12-alpine3.21", "2026-10-21T08:00:00Z", "sha256:" + "1" * 64),
                  _tag("3.12-alpine3.22", "2026-04-19T11:07:20Z", D22),
                  _tag("3.12-alpine3.24", "2026-09-01T00:00:00Z", D24))

    _run, plan = _plan(tmp_path, monkeypatch, {**python, **GOLANG})

    assert plan["moves"] == []


def test_a_newer_python_minor_is_never_proposed(tmp_path, monkeypatch):
    python = _hub("python", "3.12-alpine",
                  _tag("3.12-alpine3.22", "2026-04-19T11:07:20Z", D22),
                  _tag("3.12-alpine3.24", "2026-10-21T08:00:00Z", D24))
    newer = _hub("python", "3.13-alpine", _tag("3.13-alpine3.25", "2026-10-22T00:00:00Z", D23))

    _run, plan = _plan(tmp_path, monkeypatch, {**python, **newer, **GOLANG})

    assert [m["to"] for m in plan["moves"]] == [f"python:3.12-alpine3.24@{D24}"]
    assert all("3.13" not in url
               for url in (tmp_path / "registry" / "asked.log").read_text().split())


@pytest.mark.parametrize("images", [
    [{"os": "linux", "architecture": "amd64"}],
    [{"os": "linux", "architecture": "arm64"}, {"os": "windows", "architecture": "amd64"}],
    [],
])
def test_an_index_without_both_architectures_is_refused_and_plans_no_move(
        tmp_path, monkeypatch, images):
    python = _hub("python", "3.12-alpine",
                  _tag("3.12-alpine3.22", "2026-04-19T11:07:20Z", D22),
                  _tag("3.12-alpine3.24", "2026-10-21T08:00:00Z", D24, images))

    run, plan = _plan(tmp_path, monkeypatch, {**python, **GOLANG})

    assert run.returncode == 1
    assert "linux/amd64 and linux/arm64" in run.stderr and plan == {}


NAMED = ("Dockerfile", ".github/workflows/release.yml")
CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n"


def _tree(tmp_path: Path) -> tuple[Path, str]:
    """A copy of the real files that may name the base, and the base as they name it."""
    tree = tmp_path / "tree"
    for name in NAMED:
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text((REPO / name).read_text())
    (tree / "CHANGELOG.md").write_text(CHANGELOG)
    pinned = next(line.split()[1] for line in (REPO / "Dockerfile").read_text().splitlines()
                  if line.startswith("FROM python:"))
    return tree, pinned


def _apply(tmp_path: Path, tree: Path, moves: list[dict]
           ) -> tuple[subprocess.CompletedProcess[str], Path]:
    (tmp_path / "plan.json").write_text(json.dumps({"schema": 1, "made": NOW, "moves": moves}))
    out = tmp_path / "out"
    run = subprocess.run([sys.executable, str(BASE_HEAL), "apply", "--plan",
                          str(tmp_path / "plan.json"), "--tree", str(tree), "--out", str(out),
                          "--run", "https://example.invalid/9"],
                         capture_output=True, text=True, check=False)
    return run, out


def test_apply_rewrites_every_place_the_base_is_named(tmp_path):
    tree, pinned = _tree(tmp_path)
    old_tag = pinned.split("@")[0]
    new = "python:3.12-alpine3.99@sha256:" + "9" * 64
    move = {"from": pinned, "to": new, "last_moved": "2026-04-19T11:07:20Z", "days": 187,
            "rule": "unmoved for 30 days, and a newer Alpine suffix moved within 30"}

    run, out = _apply(tmp_path, tree, [move])

    assert run.returncode == 0, run.stderr
    naming = [name for name in NAMED if old_tag in (tree / name).read_text()]
    assert "Dockerfile" in naming
    assert sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()) == sorted(
        [*naming, "CHANGELOG.md"])
    for name in naming:
        text = (out / name).read_text()
        assert old_tag not in text, name
        assert "python:3.12-alpine3.99" in text, name
        before, after = (tree / name).read_text().splitlines(), text.splitlines()
        assert len(before) == len(after), name
        assert all(old_tag in b for b, a in zip(before, after, strict=True) if b != a), name
    dockerfile = (out / "Dockerfile").read_text()
    assert dockerfile.count(f"FROM {new}") == 2 and pinned not in dockerfile
    assert (tree / "Dockerfile").read_text() == (REPO / "Dockerfile").read_text()
    assert run.stdout.splitlines()[0] == (
        "fix: the image's base moves to python:3.12-alpine3.99, from a tag that stopped moving")
    assert f"Heal-Base-Tag: {old_tag} {new}" in run.stdout
    changelog = (out / "CHANGELOG.md").read_text()
    assert "- **The image's base on `python:3.12-alpine3.99`,**" in changelog


def test_a_plan_with_no_move_writes_nothing(tmp_path):
    tree, _pinned = _tree(tmp_path)

    run, out = _apply(tmp_path, tree, [])

    assert run.returncode == 0 and run.stdout == "" and not out.exists()


def test_a_move_from_a_base_the_dockerfile_does_not_pin_is_refused(tmp_path):
    tree, _pinned = _tree(tmp_path)
    move = {"from": "python:3.12-alpine3.01@sha256:" + "0" * 64,
            "to": "python:3.12-alpine3.99@sha256:" + "9" * 64, "last_moved": "", "days": 40,
            "rule": ""}

    run, out = _apply(tmp_path, tree, [move])

    assert run.returncode == 1 and "python:3.12-alpine3.01" in run.stderr and not out.exists()
