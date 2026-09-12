"""Defects found by scanning real local projects, distilled (tasks 19.F.3-19.F.5).

Each of these was a **false positive produced by valvur itself** on an ordinary
repository. That is the worst kind of finding this product can emit: a developer who
is told three of their own packages are "almost certainly hallucinated" learns to
distrust the whole report, and the one real finding in it goes with them.

The local project proved the behaviour matters. The fixture is what keeps the
regression test small, publishable, and free of anyone else's source (19.F.2).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import valvur.checks.dependency_reality as mod
from valvur.checks.dependency_reality import DependencyRealityCheck

FIXTURE = Path(__file__).parent / "fixtures" / "monorepo"


@pytest.fixture
def registry(monkeypatch, no_name_index, network_granted):
    """A registry where nothing exists, on the `full` Profile with no index fetched —
    so the registry is the only source, and everything valvur asks about is recorded.
    The harshest setting: anything asked about comes back absent, so every name it
    *should not have asked about* becomes a finding."""
    asked: list[tuple[str, str]] = []

    def lookup(ecosystem: str, name: str):
        asked.append((ecosystem, name))
        return None

    monkeypatch.setattr(mod, "_lookup", lookup)
    return asked


def test_a_local_workspace_package_is_not_reported_as_hallucinated_offline(name_index):
    """The same defect on the default Profile (ADR-0018), against an index that has
    never heard of the workspace members — the exact situation of a real monorepo,
    whose packages are on no registry."""
    name_index(pip=["flask"], npm=["express"])

    found = DependencyRealityCheck().run(FIXTURE)

    assert [f["rule"] for f in found] == [], found


# --------------------------------------------------- a workspace member is not a lie

def test_a_local_workspace_package_is_not_reported_as_hallucinated(registry):
    """Measured on a real monorepo: **three high-severity findings**, each saying a
    package the developer wrote themselves was "almost certainly hallucinated. If
    someone registers that name, your next install runs their code."

    The npm side already guarded `workspace:*`, `file:` and `link:` specs. Python has
    no such marker — `uv`, Poetry and Hatch all resolve a plain `"demo-core"` from the
    workspace when a member defines it — so the name looks like any other dependency.
    """
    found = DependencyRealityCheck().run(FIXTURE)

    invented = {f["title"].split("'")[1] for f in found
                if f["rule"] == "valvur.dependency.nonexistent"}

    assert "demo-core" not in invented
    assert "demo-api" not in invented
    assert "@demo/widgets" not in invented


def test_a_local_package_is_never_even_asked_about(registry):
    """Not merely unreported — never sent. A workspace member's name leaving the
    machine buys nothing, and §3 is about what we transmit, not only what we say."""
    DependencyRealityCheck().run(FIXTURE)

    asked = {name for _, name in registry}

    assert "demo-core" not in asked and "@demo/widgets" not in asked
    # The pair: real external dependencies are still checked, or this "fix" would be
    # a way to silence the Check by adding a pyproject.toml.
    assert "flask" in asked and "express" in asked


def test_a_locally_defined_name_does_not_mask_a_different_package(tmp_path, registry):
    """The obvious way to get this wrong: skipping every name that appears anywhere
    in any manifest. Only names a manifest *defines* are local."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "mine"\ndependencies = ["nope-invented-lib", "mine"]\n'
    )

    found = DependencyRealityCheck().run(tmp_path)

    assert [f["title"].split("'")[1] for f in found] == ["nope-invented-lib"]


# ------------------------------------------------- PEP 503 says these are one name

def test_a_package_does_not_typosquat_itself(tmp_path, monkeypatch, name_index):
    """Measured on a real project: *"'discord.py' is one character from the far more
    popular 'discord-py'"*.

    They are the same package. PEP 503 folds `.`, `-` and `_` together, and PyPI
    serves all three spellings from one project — verified 2026-09-10: `discord.py`,
    `discord-py` and `discord_py` all return 200 with canonical name `discord.py`.

    So the comparison was one edit apart on raw strings and zero apart in fact. Any
    package whose name contains a dot or an underscore could accuse itself.
    """
    name_index(pip=["discord.py", "zope.interface"])
    monkeypatch.setattr(mod, "_popular",
                        lambda: {"discord-py": "discord-py", "zope-interface": "zope-interface"})
    (tmp_path / "requirements.txt").write_text("discord.py==2.3.2\nzope.interface==6.1\n")

    found = DependencyRealityCheck().run(tmp_path)

    assert [f["rule"] for f in found] == [], f"self-typosquat reported: {found}"


def test_a_genuine_typosquat_still_reports(tmp_path, monkeypatch, name_index):
    """The pair. Normalising must not disarm the check it protects — `reqeusts` is a
    transposition, not a separator, and PEP 503 has nothing to say about it. The
    index says `reqeusts` exists (someone registered the squat), so this is the
    near-miss finding rather than the nonexistent one."""
    name_index(pip=["reqeusts", "requests"])
    monkeypatch.setattr(mod, "_popular", lambda: {"requests": "requests"})
    (tmp_path / "requirements.txt").write_text("reqeusts==2.31.0\n")

    found = DependencyRealityCheck().run(tmp_path)

    assert [f["rule"] for f in found] == ["valvur.dependency.near-miss"]


# ------------------------------------------- other people's code in a package cache

@pytest.mark.parametrize("path", [
    ".uv-cache/archive-v0/abc/_pytest/assertion/rewrite.py",
    ".cache/pip/http/x/lib.py",
    ".yarn/cache/left-pad/index.js",
    ".cargo/registry/src/github.com-1234/serde/lib.rs",
    ".pnpm-store/v3/files/00/abc/index.js",
])
def test_a_package_cache_is_not_the_developers_code(path):
    """Measured on a real monorepo: **17 of 42 findings** were `eval` and `exec` inside
    `.uv-cache/` — pytest's, hypothesis's, pygments' and attrs' own source, every one
    reported at high severity. Forty percent of that report was other people's code.

    The mechanism already existed and worked; the directory name simply postdated the
    list. That is the failure mode of a denylist, and it is why the count of dropped
    findings is reported rather than silent.
    """
    from valvur import exclusions

    assert exclusions.is_vendored(path)


@pytest.mark.parametrize("path", [
    "src/cache/store.py",
    "app/build_tools/gen.py",
    "lib/external_api/client.py",
])
def test_a_legitimate_directory_is_not_excluded_for_its_name(path):
    """The pair, and the reason segments are matched whole rather than as substrings:
    silently skipping a developer's own `src/cache/` would hide real code from the
    person who most needs to see it."""
    from valvur import exclusions

    assert not exclusions.is_vendored(path)
