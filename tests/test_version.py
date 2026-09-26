"""One version, derived once (task 12a.2).

The literal used to live in five places, and F1.9 refuses to run a mismatched shim
and image by comparing two of them. A partial bump therefore shipped a pair that
either refused to start or — worse — agreed while being wrong.

Found while centralising it, and the reason this file exists: the editable install's
metadata was six days stale. `importlib.metadata` reported `0.1.0.dev0` while
`pyproject.toml` declared `0.1.0rc1`, so every local scan for a week ran as one
version and wrote the other into `results.sarif`. The two happened to share a
compatibility series, so F1.9 stayed quiet.
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import version as installed_version
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _declared() -> str:
    return tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]


def test_every_version_surface_agrees():
    """The whole point: one value, several readers, no way for them to diverge."""
    from valvur.compat import shim_version
    from valvur.results import _VERSION as results_version
    from valvur.runner import _VERSION as runner_version
    from valvur.version import __version__

    assert {__version__, runner_version, results_version, shim_version()} == {__version__}


def test_the_installed_metadata_matches_what_pyproject_declares():
    """Catches a stale editable install, which is how the version silently split.

    It also catches a non-canonical version string. CI labels the image with the RAW
    pyproject value while the shim reports the PEP 440 NORMALISED one, so writing
    `0.2.0-rc1` would have the two disagree at exactly the moment F1.9 compares them.
    If this fails after a version bump, reinstall: `uv pip install -e .`
    """
    assert installed_version("valvur") == _declared(), (
        "installed metadata and pyproject.toml disagree — the environment is stale, "
        "or the version string is not PEP 440 canonical"
    )


def test_the_readme_states_the_version_it_ships():
    """The one literal a human still maintains, so a test maintains it instead."""
    readme = (REPO / "README.md").read_text()
    stated = re.search(r"\*\*Status: `([^`]+)`\*\*", readme)

    assert stated, "README no longer states a version — this test needs updating with it"
    assert stated.group(1) == _declared()


def test_the_readme_does_not_call_a_version_published_before_its_tag_exists():
    """29.3.1. The prep commit bumps the line before the tag and the release brake
    can be held for days; at the first gate the README said `0.4.0 — published`
    while PyPI served `0.3.0`. Two wordings: *release in progress* until the run
    has promoted, *published and installable* after — and *published* is refused
    here when the tree's tags are known and `v<version>` is not among them. The
    daily `published.yml` asks PyPI and GHCR, which no unit test may."""
    import shutil
    import subprocess

    readme = (REPO / "README.md").read_text()
    line = next(l for l in readme.splitlines() if "**Status: `" in l)
    published = "published and installable" in line
    assert published or "release in progress" in line, f"neither wording: {line}"
    if not published:
        return
    git = shutil.which("git")
    if git is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    tags = subprocess.run([git, "-C", str(REPO), "tag", "--list", "v*"],
                          capture_output=True, text=True, check=False).stdout.split()
    if not tags:
        pytest.skip("no tags fetched here (a shallow checkout); published.yml asks PyPI")
    assert f"v{_declared()}" in tags, (
        f"the README says {_declared()} is published, and no tag v{_declared()} exists"
    )


def test_the_security_policy_names_the_series_it_supports():
    """27.2.4. `SECURITY.md` says pre-1.0 only the latest release is supported, and
    its table said `0.1.x` through `0.2.0` and `0.3.0` — so a reporter checking
    whether their version is supported read a series that had been superseded
    twice. The table is generated from nothing; this test is what keeps it true."""
    policy = (REPO / "SECURITY.md").read_text()
    series = ".".join(_declared().split(".")[:2]) + ".x"

    listed = re.findall(r"^\| `([^`]+)` \|", policy, re.M)

    assert listed, "SECURITY.md no longer lists a supported version"
    assert listed == [series], (
        f"SECURITY.md supports {listed}; this release is {_declared()}, so the "
        f"series is {series}"
    )


def test_the_default_image_carries_the_shim_version():
    """A shim that asks for whatever tag it was built alongside cannot drift from it."""
    from valvur.version import __version__, default_image

    assert default_image().endswith(f":{__version__}")


def test_an_explicit_image_still_wins(monkeypatch):
    """Local builds and air-gapped mirrors both need this override to keep working."""
    import importlib

    monkeypatch.setenv("VALVUR_IMAGE", "registry.internal/valvur:pinned")
    import valvur.runner as runner

    importlib.reload(runner)
    try:
        assert runner.IMAGE == "registry.internal/valvur:pinned"
    finally:
        monkeypatch.delenv("VALVUR_IMAGE")
        importlib.reload(runner)


def test_an_uninstalled_checkout_does_not_invent_a_release_number():
    """A plausible-looking fallback would be worse than an obviously fake one: F1.9
    would compare it against a real image and reach a confident, wrong answer."""
    from valvur.version import DEV_VERSION

    assert "dev" in DEV_VERSION
    assert DEV_VERSION.startswith("0.0.0")


def test_the_package_exposes_its_version():
    """`valvur.__version__` is where anyone will look first, including us."""
    import valvur

    assert valvur.__version__ == _declared()


def test_the_cli_reports_its_version(capsys):
    """Task 16.4. One issue template asked people to run `valvur --version` and it
    did not exist — the same class as the verification command found in 11.0, and
    found the same way: by running what the documentation says."""
    import pytest

    from valvur.cli import main

    with pytest.raises(SystemExit) as exit_code:
        main(["--version"])

    assert exit_code.value.code == 0
    assert capsys.readouterr().out.strip() == f"valvur {_declared()}"


def test_every_command_the_docs_name_actually_exists(capsys):
    """The generalisation of 11.0 and 16.4. Documentation naming a command that does
    not run is worse than no documentation: it is the first thing a sceptical reader
    tries, and valvur has now shipped two such commands — the verification one-liner
    and `--version`."""
    import re

    import pytest

    from valvur.cli import main

    named = set()
    for path in [*(REPO / ".github").rglob("*.yml"),
                 REPO / "docs" / "RELEASING.md",
                 REPO / "README.md",
                 REPO / "CONTRIBUTING.md"]:
        if path.is_file():
            named |= set(re.findall(r"`valvur (--?[\w-]+|\w+)", path.read_text()))

    assert named, "no valvur commands are documented, which cannot be right"

    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out

    missing = sorted(n for n in named if n not in help_text)
    assert not missing, f"documented but not available: {missing}"
