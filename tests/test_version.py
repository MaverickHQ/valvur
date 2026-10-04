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


def test_the_skill_s_pinned_scan_is_this_release():
    """R21.3 (D58c). When a tool is refused, the skill gives the human a command to
    run themselves, pinned so the scan is the release the skill was written for;
    `prepare_release.py` moves it with every other surface."""
    from valvur.skill import SKILL

    pinned = re.findall(r"! uvx valvur==([^\s`]+) scan", SKILL.read_text())

    assert pinned == [_declared()]


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
        # Back to the environment the suite runs in, then reload. Deleting the
        # variable here left `runner.IMAGE` at the published tag for every later
        # test in the process, and the release's whole-suite run looked for an
        # image not yet published (1.0.0's rehearsal, run 36544594332).
        monkeypatch.undo()
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


def _documents() -> list[Path]:
    """Every document that tells a person or an agent which command to run."""
    from valvur import skill

    return [*(REPO / ".github").rglob("*.yml"),
            REPO / "docs" / "RELEASING.md",
            REPO / "README.md",
            REPO / "CONTRIBUTING.md",
            *sorted(skill.DIRECTORY.rglob("*.md"))]


def test_the_skill_is_read_for_the_commands_it_names():
    """R15.1: the skill tells an agent which commands to run, in CI above all."""
    from valvur import skill

    documents = _documents()

    for path in skill.DIRECTORY.rglob("*.md"):
        assert path in documents, path


def test_every_command_the_docs_name_actually_exists(capsys):
    """The generalisation of 11.0 and 16.4. Documentation naming a command that does
    not run is worse than no documentation: it is the first thing a sceptical reader
    tries, and valvur has now shipped two such commands — the verification one-liner
    and `--version`."""
    import re

    import pytest

    from valvur.cli import main

    named = set()
    for path in _documents():
        if path.is_file():
            named |= set(re.findall(r"`valvur (--?[\w-]+|\w+)", path.read_text()))

    assert named, "no valvur commands are documented, which cannot be right"

    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out

    missing = sorted(n for n in named if n not in help_text)
    assert not missing, f"documented but not available: {missing}"


def test_the_plugin_is_this_version_and_pins_its_server_to_it():
    """R15.2 (D40): the Claude Code plugin's server is the Claude Code block every
    client is given, `uvx --from valvur valvur-mcp`, pinned to the release, so an
    installed plugin's skill and server are one version. Both move with the rest."""
    import json

    from valvur.mcp import clients

    plugin = REPO / "plugins" / "valvur"
    config = json.loads((plugin / ".mcp.json").read_text())
    manifest = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())

    pinned = clients.snippet(clients.client("claude-code"), version=_declared())
    assert config == json.loads(pinned)
    assert config["mcpServers"]["valvur"]["args"] == ["--from", f"valvur=={_declared()}",
                                                      "valvur-mcp"]
    assert manifest["version"] == _declared()


def test_the_kiro_power_is_this_version():
    """R15.3 (D40): the power's manifest moves with the rest; its server's pin is
    held in `test_power.py`, beside the spec's rules for it."""
    import json

    manifest = json.loads((REPO / "powers" / "valvur" / "plugin.json").read_text())
    server = json.loads((REPO / "powers" / "valvur" / "mcp.json").read_text())

    assert manifest["version"] == _declared()
    assert f"valvur=={_declared()}" in server["mcpServers"]["valvur"]["args"]


def test_the_plugins_hook_is_pinned_to_this_version():
    """R18.4 (D44): the hook runs the release's own valvur-hook, as the server does."""
    script = (REPO / "plugins" / "valvur" / "hooks" / "pre-tool-use.sh").read_text()

    assert f"uvx --from valvur=={_declared()} valvur-hook" in script
