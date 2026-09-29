"""R9.3: the Score's own tracks are written from a seed (ADR-0026, D21).

Two runs with one seed write the same trees, commits included, so a score measured
today is measured on the same cases tomorrow. Each track holds at least twenty
vulnerable and twenty safe cases, listed in its `cases.json`.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parent.parent / "scripts" / "eval"


def _twins():
    sys.path.insert(0, str(EVAL))
    try:
        spec = importlib.util.spec_from_file_location("twins", EVAL / "twins.py")
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        sys.modules["twins"] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module
    finally:
        sys.path.remove(str(EVAL))


def _tree(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and ".git" not in p.parts}


def _head(root: Path) -> str:
    if not (root / ".git").exists():
        return ""
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                          text=True, check=True).stdout.strip()


TRACKS = ["sast-js", "secrets", "dependencies", "package-reality", "agent-configuration",
          "infrastructure"]


@pytest.mark.parametrize("track", TRACKS)
def test_one_seed_writes_the_same_tree_twice(tmp_path, track):
    twins = _twins()

    twins.build(track, tmp_path / "a" / track, seed=7)
    twins.build(track, tmp_path / "b" / track, seed=7)

    assert _tree(tmp_path / "a" / track) == _tree(tmp_path / "b" / track)
    assert _head(tmp_path / "a" / track) == _head(tmp_path / "b" / track)
    assert (tmp_path / "a" / f"{track}.cases.json").read_text() == \
        (tmp_path / "b" / f"{track}.cases.json").read_text()


@pytest.mark.parametrize("track", TRACKS)
def test_each_track_holds_twenty_vulnerable_and_twenty_safe_cases(tmp_path, track):
    twins = _twins()
    root = tmp_path / track

    twins.build(track, root)
    listed = json.loads((tmp_path / f"{track}.cases.json").read_text())

    assert sum(case["vulnerable"] for case in listed) >= 20
    assert sum(not case["vulnerable"] for case in listed) >= 20
    assert len({case["id"] for case in listed}) == len(listed)
    for case in listed:
        path = case["path"]
        in_history = subprocess.run(
            ["git", "log", "--all", "--format=%H", "--", path], cwd=root,
            capture_output=True, text=True, check=False).stdout if (root / ".git").exists() else ""
        assert (root / path).exists() or in_history, f"{track}: {path} is nowhere"


@pytest.mark.parametrize("track", TRACKS)
def test_every_generated_config_file_parses(tmp_path, track):
    """A case whose file does not parse is read by no Scanner, so its vulnerable half
    is a miss and its safe half a free pass: the first run's template-injection
    workflow was invalid YAML, a plain scalar holding `: `."""
    import re

    twins = _twins()
    root = tmp_path / track
    twins.build(track, root)
    plain = re.compile(r"^\s*(?:- )?[\w.-]+: (?![\"'|>{\[&*!])(.*)$")
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            json.loads(text)
        elif path.suffix in (".yml", ".yaml"):
            for n, line in enumerate(text.splitlines(), 1):
                value = plain.match(line)
                assert not (value and ": " in value.group(1)), \
                    f"{path.relative_to(root)}:{n} is not a YAML plain scalar: {line!r}"


def test_a_package_case_whose_premise_broke_is_named_and_set_aside(tmp_path):
    """A planted name someone has since registered, or a real one since removed, is
    no longer the case it was written as: the run names it and does not score it."""
    twins = _twins()
    cases = twins.build("package-reality", tmp_path / "package-reality")
    index = tmp_path / "names"
    index.mkdir()
    # PyPI's list, sorted as the index stores it: `reqeusts` registered since, and
    # `requests` absent; every other PyPI premise holds.
    names = sorted({"flask", "humanize", "reqeusts"})
    (index / "pypi.txt").write_text("\n".join(names) + "\n")

    invalid = twins.invalid_cases([c for c in cases if "/pip/" in c.path], index)

    assert invalid == {
        "package-reality-pkg/pip/near-miss-1": "'reqeusts' is in the pip index now",
        "package-reality-pkg/pip/real-1": "'requests' is not in the pip index",
    }


def test_no_two_dependency_cases_or_fixtures_share_a_package_and_version(tmp_path):
    """A dependency finding's identity is package, version and advisory, with no path
    (ADR-0003): two lockfiles pinning the same package and version are one finding at
    one path, so one of the two cases could never be flagged."""
    import re

    twins = _twins()
    root = tmp_path / "dependencies"
    twins.build("dependencies", root)
    pins: list[tuple[str, str]] = []
    for path in root.rglob("*"):
        text = path.read_text() if path.is_file() else ""
        if path.name == "requirements.txt":
            pins += re.findall(r"^([\w.-]+)==([\w.]+)$", text, re.M)
        elif path.name == "pom.xml":
            pins += re.findall(r"<artifactId>([\w.-]+)</artifactId>\s*<version>([\w.]+)<", text)
        elif path.name == "package-lock.json":
            pins += [(k.removeprefix("node_modules/"), v["version"]) for k, v in
                     json.loads(text)["packages"].items() if k]
        elif path.name in ("Cargo.lock", "go.mod", "Gemfile.lock", "composer.lock"):
            pins += re.findall(r'name = "([\w-]+)"\nversion = "([\w.]+)"', text)
            pins += re.findall(r"^require ([\w./-]+) (v[\w.]+)$", text, re.M)
            pins += re.findall(r"^    ([\w-]+) \(([\w.]+)\)$", text, re.M)
            if path.name == "composer.lock":
                pins += [(p["name"], p["version"]) for p in json.loads(text)["packages"]]
    pins = [pin for pin in pins if pin[0] != "case"]
    assert len(pins) == len(set(pins)), sorted(p for p in set(pins) if pins.count(p) > 1)


def test_a_package_case_is_flagged_only_by_a_claim_about_the_package(tmp_path):
    """Nonexistent, near-miss, newly registered, malicious, or exposed to confusion:
    each says the package is not what it seems. A coverage note, or D27's low advice
    to reserve a privately served name, says nothing against it, so neither flags a
    safe case."""
    sys.path.insert(0, str(EVAL))
    try:
        import score  # type: ignore[import-not-found]
    finally:
        sys.path.remove(str(EVAL))
    twins = _twins()
    [case] = [c for c in twins.build("package-reality", tmp_path / "pr")
              if c.path == "pkg/pip/private-1"]

    def hit(rule: str) -> bool:
        return score.flagged(case, [{"path": "pkg/pip/private-1/requirements.txt",
                                     "rule": rule, "status": "new"}])

    for claim in ("nonexistent", "near-miss", "newly-registered", "malicious", "confusion"):
        assert hit(f"valvur.dependency.{claim}"), claim
    for statement in ("not-public", "ecosystem-not-covered", "private-registry"):
        assert not hit(f"valvur.dependency.{statement}"), statement
