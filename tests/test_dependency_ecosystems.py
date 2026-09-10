"""Task 19.D.1 — the Dependency Reality Check reads more than `requirements*.txt`.

**This closes an unmet requirement, not a missing feature.** F3.1 says *"for each
declared dependency"*; the Check read one manifest format and queried one registry.
Measured 2026-09-10: an npm project with a deliberately non-existent package returned
**0 findings**, silently.

Phase 17 did not catch it, and it is worth knowing why: 17.2's ratchet checks that
every requirement is *cited* somewhere, not that it is *satisfied*. F3.1 was cited —
by the code implementing a tenth of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import valvur.checks.dependency_reality as mod
from valvur.checks.dependency_reality import DependencyRealityCheck, RegistryUnreachable


@pytest.fixture
def registry(monkeypatch):
    """A registry where everything exists except names starting `nope-`.

    Returns the list of (ecosystem, name) pairs actually looked up, because the
    load-bearing assertion in most of these tests is *which registry was asked*, not
    what it answered.
    """
    asked: list[tuple[str, str]] = []

    def lookup(ecosystem: str, name: str):
        asked.append((ecosystem, name))
        return None if name.startswith("nope-") else {"releases": {}}

    monkeypatch.setattr(mod, "_lookup", lookup)
    return asked


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _names(asked, ecosystem):
    return sorted(n for eco, n in asked if eco == ecosystem)


# ------------------------------------------------------------------------ npm

def test_an_npm_project_with_a_hallucinated_package_is_a_finding(tmp_path, registry):
    """The measurement that opened this task: 0 findings, silently."""
    found = DependencyRealityCheck().run(_repo(tmp_path, {"package.json": json.dumps(
        {"dependencies": {"nope-fake-sdk": "^1.0.0", "express": "^4.0.0"}}
    )}))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]
    assert "nope-fake-sdk" in found[0]["title"]
    assert "the npm registry" in found[0]["title"]


def test_every_npm_dependency_field_is_read(tmp_path, registry):
    """A hallucinated peer dependency is still a name someone can register."""
    DependencyRealityCheck().run(_repo(tmp_path, {"package.json": json.dumps({
        "dependencies": {"a": "1"}, "devDependencies": {"b": "1"},
        "optionalDependencies": {"c": "1"}, "peerDependencies": {"d": "1"},
    })}))

    assert _names(registry, "npm") == ["a", "b", "c", "d"]


@pytest.mark.parametrize("spec", [
    "file:../local", "link:../sibling", "workspace:*", "git+https://x/y.git",
    "https://example.invalid/t.tgz", "portal:../p",
])
def test_a_non_registry_spec_is_not_asked_about(tmp_path, registry, spec):
    """The false positive most likely to make a real finding ignored: reporting every
    package in a monorepo as nonexistent because `workspace:*` is not on the registry.
    """
    DependencyRealityCheck().run(_repo(tmp_path, {
        "package.json": json.dumps({"dependencies": {"sibling": spec, "real": "^1"}})
    }))

    assert _names(registry, "npm") == ["real"]


def test_a_scoped_package_survives_the_url(monkeypatch):
    """`@scope/name` has a slash in it. Percent-encoding the whole name would produce
    a 404 for every scoped package on npm — a false hallucination report on the most
    ordinary dependency shape there is.

    Asserted against the URL `_lookup` builds, not against the parser. The first
    version of this test patched `_lookup` out and then claimed to be testing it,
    which proved only that the name survived JSON parsing.

    Measured 2026-09-10: registry.npmjs.org returns 200 for `@types/node`,
    `@types%2Fnode` and `@types%2fnode` alike, so the encoded form is not broken
    there. Pinned anyway — private mirrors are stricter, and this product's users are
    disproportionately behind one.
    """
    seen: list[str] = []
    monkeypatch.setattr(mod, "_fetch", lambda url: seen.append(url) or {})

    mod._lookup("npm", "@types/node")
    mod._lookup("pip", "zope.interface")

    assert seen == [
        "https://registry.npmjs.org/@types/node",
        "https://pypi.org/pypi/zope.interface/json",
    ]


def test_a_registry_url_is_always_https(monkeypatch):
    """A dependency NAME reaching urlopen with its own scheme is how a manifest turns
    into a file read. Structural, not a lint suppression."""
    with pytest.raises(RegistryUnreachable):
        mod._fetch("file:///etc/passwd")


def test_npm_names_are_not_compared_against_the_pypi_popular_list(tmp_path, registry):
    """`reqeusts` is one edit from the PyPI package `requests`. On npm that comparison
    is meaningless, and reporting it would be a fabricated typosquat warning."""
    found = DependencyRealityCheck().run(_repo(tmp_path, {
        "package.json": json.dumps({"dependencies": {"reqeusts": "^1"}})
    }))

    assert [f["rule"] for f in found] == []


# --------------------------------------------------------------------- pyproject

def test_pep_621_dependencies_are_read(tmp_path, registry):
    found = DependencyRealityCheck().run(_repo(tmp_path, {"pyproject.toml": """
[project]
name = "x"
dependencies = ["flask>=3", "nope-invented-lib==1.0"]
"""}))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]
    assert _names(registry, "pip") == ["flask", "nope-invented-lib"]


def test_pep_621_optional_dependencies_are_read(tmp_path, registry):
    DependencyRealityCheck().run(_repo(tmp_path, {"pyproject.toml": """
[project]
name = "x"
[project.optional-dependencies]
dev = ["pytest>=8"]
docs = ["sphinx"]
"""}))

    assert _names(registry, "pip") == ["pytest", "sphinx"]


def test_poetry_dependencies_are_read(tmp_path, registry):
    """A different shape entirely — a table whose keys are the names — and common
    enough that reading only PEP 621 would leave Poetry projects scanning clean for
    the wrong reason."""
    DependencyRealityCheck().run(_repo(tmp_path, {"pyproject.toml": """
[tool.poetry]
name = "x"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
"""}))

    # `python` is the interpreter constraint, not a package. Asking PyPI about it
    # would report the language itself as a dependency on every Poetry project.
    assert _names(registry, "pip") == ["pytest", "requests"]


def test_a_poetry_path_dependency_is_not_asked_about(tmp_path, registry):
    DependencyRealityCheck().run(_repo(tmp_path, {"pyproject.toml": """
[tool.poetry.dependencies]
sibling = { path = "../sibling" }
requests = { version = "^2.31" }
"""}))

    assert _names(registry, "pip") == ["requests"]


def test_a_malformed_manifest_does_not_take_the_scanner_down(tmp_path, registry):
    """This Check exists to report hallucinated packages. Raising on a TOML syntax
    error would take the real findings in the same run down with it."""
    found = DependencyRealityCheck().run(_repo(tmp_path, {
        "pyproject.toml": "[project\nthis is not toml",
        "package.json": "{not json",
        "requirements.txt": "nope-invented-lib==1.0\n",
    }))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]


# ------------------------------------------------------------------- both at once

def test_each_ecosystem_is_asked_of_its_own_registry(tmp_path, registry):
    """The same string is a different package in two registries. Asking the wrong one
    is how a real package gets reported as hallucinated."""
    DependencyRealityCheck().run(_repo(tmp_path, {
        "requirements.txt": "flask\n",
        "pyproject.toml": "[project]\nname='x'\ndependencies=['httpx']\n",
        "package.json": json.dumps({"dependencies": {"express": "^4"}}),
    }))

    assert _names(registry, "pip") == ["flask", "httpx"]
    assert _names(registry, "npm") == ["express"]


def test_a_vendored_manifest_is_not_this_project_s_dependency(tmp_path, registry):
    DependencyRealityCheck().run(_repo(tmp_path, {
        "node_modules/left-pad/package.json": json.dumps({"dependencies": {"nope-x": "1"}}),
        "package.json": json.dumps({"dependencies": {"express": "^4"}}),
    }))

    assert _names(registry, "npm") == ["express"]


def test_an_unreachable_registry_still_fails_loudly(tmp_path, monkeypatch):
    """F3.5 survives the widening. Unverified is not clean, and the message names the
    live Profile rather than the retired one (19.D.2)."""
    def unreachable(ecosystem, name):
        raise RegistryUnreachable("no network")

    monkeypatch.setattr(mod, "_lookup", unreachable)

    with pytest.raises(RegistryUnreachable) as raised:
        DependencyRealityCheck().run(_repo(tmp_path, {
            "package.json": json.dumps({"dependencies": {"express": "^4"}})
        }))

    assert "--profile full" in str(raised.value)
    assert "standard" not in str(raised.value)


def test_a_python_fingerprint_did_not_move(tmp_path, registry):
    """ADR-0003: the ecosystem joined the identity tuple, and `pip` is spelled exactly
    as before. Any change here invalidates every committed suppression keyed on a
    Python dependency-reality finding, in every repository using valvur."""
    found = DependencyRealityCheck().run(
        _repo(tmp_path, {"requirements.txt": "nope-invented-lib==1.0\n"})
    )

    assert found[0]["identity"] == ("dependency_reality", "pip", "nope-invented-lib")


def test_a_hallucinated_dependency_outranks_a_missing_licence_file(tmp_path, registry):
    """It used to arrive as `unknown`. Measured end-to-end before this: an npm project
    with an invented package reported it at the same weight as "no licence file" —
    the product's signature finding, ranked below housekeeping."""
    found = DependencyRealityCheck().run(
        _repo(tmp_path, {"requirements.txt": "nope-invented-lib==1.0\n"})
    )

    assert found[0]["severity"] == "high"
