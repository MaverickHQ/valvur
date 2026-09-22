"""The dependency-reality Check's output, and the ecosystem registry (task 27.3.2).

`dependency_reality.py` was 1,206 lines holding Check orchestration, seven manifest
parsers, registry transport, per-registry age decoding and typosquat matching — and
the truth about an ecosystem was spread over three modules that had to be edited
together: `ecosystems.MANIFESTS` (what to read), `name_index.FILES` (which index),
and a per-ecosystem `if` in the Check for the registry, the URL and the age. The two
modules imported each other, lazily, in both directions.

The goldens here were captured from the Check **before** any of that moved. They are
the guard on a refactor whose whole claim is that nothing changed: what a scan of a
real manifest reports is what a user sees, so "equivalent" is not the standard.

    UPDATE_DEPENDENCY_GOLDEN=1 uv run pytest tests/test_ecosystem_registry.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

GOLDEN = Path(__file__).parent / "fixtures" / "dependency-reality"
UPDATE = "UPDATE_DEPENDENCY_GOLDEN"
FIXTURES = Path(__file__).parent / "fixtures"

#: Every manifest shape the parsers know, in one tree per case. Written here rather
#: than pointing at the repository's own fixtures so a change to those cannot move
#: this guard underneath the refactor it is guarding.
TREES: dict[str, dict[str, str]] = {
    "python": {
        "requirements.txt": "requests==2.31.0\nreqeusts==1.0\nflask>=2\n",
        "pyproject.toml": '[project]\nname = "app"\ndependencies = ["httpx", "aws-helper-sdk"]\n',
    },
    "npm": {
        "package.json": json.dumps({
            "name": "app", "version": "1.0.0",
            "dependencies": {"react": "^18", "reakt": "^1", "@types/node": "^20"},
            "devDependencies": {"jest": "^29"},
        }),
    },
    "jvm": {
        "pom.xml": ('<project><dependencies><dependency>'
                    '<groupId>com.google.guava</groupId><artifactId>guava</artifactId>'
                    "</dependency></dependencies></project>"),
        "build.gradle": 'dependencies {\n  implementation "org.slf4j:slf4j-api:2.0.9"\n}\n',
    },
    "go-ruby-php-rust": {
        "go.mod": "module example.com/m\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n",
        "Gemfile": 'source "https://rubygems.org"\ngem "rack"\n',
        "composer.json": json.dumps({"require": {"monolog/monolog": "^3.0"}}),
        "Cargo.toml": '[package]\nname = "app"\n\n[dependencies]\nserde = "1"\n',
    },
}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _declared(workspace: Path) -> list[list[str]]:
    """What the Check believes is declared: the answer every later decision rests
    on, and the part a parser refactor can silently change."""
    from valvur.checks.dependency_reality import _declared_packages

    return sorted([eco, name, src] for eco, name, src in _declared_packages(workspace))


@pytest.mark.parametrize("name", sorted(TREES))
def test_what_the_check_reads_from_each_manifest_is_unchanged(name, tmp_path):
    workspace = _write(tmp_path / name, TREES[name])
    path = GOLDEN / f"{name}.json"
    declared = _declared(workspace)

    if os.environ.get(UPDATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(declared, indent=2) + "\n", encoding="utf-8")
        pytest.skip(f"regenerated {path.name}")

    assert path.is_file(), f"no golden for {name!r}; generate with {UPDATE}=1"
    assert declared == json.loads(path.read_text()), (
        f"the parsers read {name} differently than before the move"
    )


def test_the_broken_fixture_reads_the_same_as_before(tmp_path):
    """The repository's own deliberately-broken tree, which is what the e2e suite
    and every demo scan use: the two planted hallucinations are in here."""
    import shutil

    workspace = tmp_path / "broken"
    shutil.copytree(FIXTURES / "broken-repo", workspace)
    path = GOLDEN / "broken-repo.json"
    declared = _declared(workspace)

    if os.environ.get(UPDATE):
        path.write_text(json.dumps(declared, indent=2) + "\n", encoding="utf-8")
        pytest.skip("regenerated broken-repo.json")

    assert declared == json.loads(path.read_text())
    assert ["pip", "reqeusts", "requirements-ai.txt"] in declared, \
        "the planted hallucination is no longer read at all"
