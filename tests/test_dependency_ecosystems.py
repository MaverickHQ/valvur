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
def registry(monkeypatch, no_name_index, network_granted):
    """A registry where everything exists except names starting `nope-`, on the
    `full` Profile of a machine that has not fetched the index — so the registry is
    the only source and every declared name reaches it.

    Returns the list of (ecosystem, name) pairs actually looked up, because the
    load-bearing assertion in most of these tests is *which names were declared*,
    observed as which registry was asked about them. With an index present the
    offline path answers first and asks nothing (ADR-0018); that path has its own
    tests below and in `test_constraints.py`.
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
    monkeypatch.setattr(mod, "_fetch", lambda url, *, as_json=True: seen.append(url) or {})

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


def test_an_unreachable_registry_still_fails_loudly(
    tmp_path, monkeypatch, no_name_index, network_granted
):
    """F3.5 survives the widening. Unverified is not clean, and the message names the
    thing that fixes it — since ADR-0018, the index that answers existence with no
    registry at all — rather than a retired Profile (19.D.2)."""
    def unreachable(ecosystem, name):
        raise RegistryUnreachable("no network")

    monkeypatch.setattr(mod, "_lookup", unreachable)

    with pytest.raises(RegistryUnreachable) as raised:
        DependencyRealityCheck().run(_repo(tmp_path, {
            "package.json": json.dumps({"dependencies": {"express": "^4"}})
        }))

    assert "valvur update" in str(raised.value)
    assert "standard" not in str(raised.value)


# ------------------------------------------------------- the index path (ADR-0018)

def test_an_npm_hallucination_is_found_offline_from_the_index(tmp_path, name_index, monkeypatch):
    name_index(npm=["express"])
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: pytest.fail(f"asked about {name}"))

    found = DependencyRealityCheck().run(_repo(tmp_path, {"package.json": json.dumps(
        {"dependencies": {"nope-fake-sdk": "^1.0.0", "express": "^4.0.0"}}
    )}))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]
    assert "nope-fake-sdk" in found[0]["title"]


def test_a_scoped_npm_name_is_found_in_the_index_as_written(tmp_path, name_index):
    """`@types/node` is stored with its `@` and `/`; the index form is lowercase and
    nothing else, because npm names are case-insensitive and otherwise literal."""
    name_index(npm=["@types/node"])

    found = DependencyRealityCheck().run(_repo(tmp_path, {"package.json": json.dumps(
        {"devDependencies": {"@Types/Node": "^20", "@types/nope-x": "^1"}}
    )}))

    assert [f["title"].split("'")[1] for f in found] == ["@types/nope-x"]


def test_a_python_name_is_looked_up_in_pep_503_form(tmp_path, name_index):
    """`Zope.Interface`, `zope_interface` and `zope-interface` are one PyPI project.
    The index stores the canonical form and the Check asks in it, so a declared
    spelling that differs only by separators or case is never reported as invented."""
    name_index(pip=["zope.interface"])

    found = DependencyRealityCheck().run(_repo(tmp_path, {
        "requirements.txt": "Zope.Interface==6.1\nzope_interface\nzope-interface\n"
    }))

    assert found == []


def test_on_full_only_names_that_exist_are_asked_for_their_age(
    tmp_path, name_index, network_granted, monkeypatch
):
    """The registry is now asked one question, about names the index already
    settled as real. A hallucinated name never leaves the machine."""
    name_index(pip=["flask"])
    asked: list[str] = []
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: asked.append(name) or {"releases": {}})

    found = DependencyRealityCheck().run(_repo(tmp_path, {
        "requirements.txt": "flask\nnope-invented-lib\n"
    }))

    assert asked == ["flask"]
    assert [f["title"].split("'")[1] for f in found] == ["nope-invented-lib"]


def test_a_package_unpublished_since_the_index_was_built_is_still_reported(
    tmp_path, name_index, network_granted, monkeypatch
):
    """The index says it exists; the registry, asked for its age, says it is gone.
    A just-freed name is precisely the slopsquat target, so `full` reports it."""
    name_index(pip=["gone-lib"])
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: None)

    found = DependencyRealityCheck().run(_repo(tmp_path, {"requirements.txt": "gone-lib\n"}))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]
    assert "no longer exists" in found[0]["title"]


def test_a_newly_registered_package_is_reported_only_with_a_network(
    tmp_path, name_index, monkeypatch
):
    """Age is the one question the index cannot answer. Offline, a package the
    index knows is simply present; on `full` its first-publish date is checked."""
    from datetime import UTC, datetime, timedelta

    name_index(pip=["fresh-lib"])
    recent = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: {
        "releases": {"1.0": [{"upload_time_iso_8601": recent}]}
    })
    manifest = _repo(tmp_path, {"requirements.txt": "fresh-lib\n"})

    offline = DependencyRealityCheck().run(manifest)
    monkeypatch.setenv("VALVUR_NETWORK", "1")
    full = DependencyRealityCheck().run(manifest)

    assert offline == []
    assert [f["rule"] for f in full] == ["valvur.dependency.newly-registered"]


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


# ------------------------------------------------- 22.A.3: the lookups overlap

def _fresh_lib(days: int) -> dict:
    from datetime import UTC, datetime, timedelta

    stamp = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    return {"releases": {"1.0": [{"upload_time_iso_8601": stamp}]}}


def test_registry_lookups_run_concurrently(tmp_path, name_index, network_granted, monkeypatch):
    """Measured 2026-09-12: 159ms a name serial, 123s on a real monorepo. The
    lookups are independent and I/O-bound; eight of them at 200ms each must not
    take 1.6 seconds."""
    import time

    names = [f"lib-{i}" for i in range(8)]
    name_index(pip=names)
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: time.sleep(0.2) or _fresh_lib(400))

    started = time.monotonic()
    DependencyRealityCheck().run(_repo(tmp_path, {"requirements.txt": "\n".join(names)}))
    elapsed = time.monotonic() - started

    assert elapsed < 0.8, f"8 x 0.2s took {elapsed:.2f}s — the lookups serialised"


def test_registry_concurrency_is_bounded(tmp_path, name_index, network_granted, monkeypatch):
    """The one code path that reaches the network. Fifty connections at once to
    PyPI is a scanner that gets rate-limited and then reports "unreachable" as if
    nothing had been declared."""
    import threading
    import time

    names = [f"lib-{i:02d}" for i in range(40)]
    name_index(pip=names)
    in_flight = 0
    peak = 0
    lock = threading.Lock()

    def lookup(eco, name):
        nonlocal in_flight, peak
        with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        time.sleep(0.02)
        with lock:
            in_flight -= 1
        return _fresh_lib(400)

    monkeypatch.setattr(mod, "_lookup", lookup)

    DependencyRealityCheck().run(_repo(tmp_path, {"requirements.txt": "\n".join(names)}))

    assert 1 < peak <= mod.LOOKUP_CONCURRENCY, peak


def test_findings_arrive_in_declaration_order_whatever_order_the_answers_did(
    tmp_path, name_index, network_granted, monkeypatch
):
    """Reproducible output: the same manifest gives byte-identical findings on every
    run, or the rescan diff (F5) reports churn that never happened."""
    import random
    import time

    names = [f"new-{i}" for i in range(12)]
    name_index(pip=names)
    rng = random.Random(7)  # noqa: S311 — jitter, not a secret

    def lookup(eco, name):
        time.sleep(rng.random() * 0.05)
        return _fresh_lib(3)

    monkeypatch.setattr(mod, "_lookup", lookup)
    manifest = _repo(tmp_path, {"requirements.txt": "\n".join(reversed(names))})

    first = DependencyRealityCheck().run(manifest)
    second = DependencyRealityCheck().run(manifest)

    assert first == second
    assert [f["title"].split("'")[1] for f in first] == sorted(names)


def test_one_failed_lookup_does_not_lose_the_others(
    tmp_path, name_index, network_granted, monkeypatch
):
    """A registry hiccup on one name is one unverified name, not a failed Check:
    the run stays complete, the other answers are kept, and nothing is retried
    into a rate limit."""
    name_index(pip=["fine-a", "flaky", "fine-b"])

    def lookup(eco, name):
        if name == "flaky":
            raise RegistryUnreachable("timed out")
        return _fresh_lib(2)

    monkeypatch.setattr(mod, "_lookup", lookup)

    found = DependencyRealityCheck().run(
        _repo(tmp_path, {"requirements.txt": "fine-a\nflaky\nfine-b\n"})
    )

    assert [f["title"].split("'")[1] for f in found] == ["fine-a", "fine-b"]
    assert all(f["rule"] == "valvur.dependency.newly-registered" for f in found)
