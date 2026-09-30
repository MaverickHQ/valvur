"""The version the image pins is the version valvur says ran.

Each Scanner is pinned three times: by the image (the Dockerfile, or a hash-locked
requirements file), by its adapter (`VERSION`, which `run.json` records as the
version that ran), and by its golden fixture's name (the output the parser is
tested against). Dependabot bumps the first alone: its Syft 1.52.0 pull request
(#155, 2026-09-29) passed every check while the adapter still said 1.51.1. A
Scanner upgrade is now all three at once, or red.
"""

from __future__ import annotations

from pathlib import Path

from conftest import PINNED_VERSIONS

REPO = Path(__file__).resolve().parent.parent


def _image_pins() -> dict[str, str]:
    """The image's pins, by the one parser `refresh.yml` uses too (R16.3)."""
    import importlib.util
    import sys

    path = REPO / "scripts" / "scanner_pins.py"
    spec = importlib.util.spec_from_file_location("scanner_pins", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["scanner_pins"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.pins(module.in_tree(REPO))


def test_each_scanner_the_image_pins_is_the_version_its_adapter_declares():
    from valvur.adapters import DEFAULT_ADAPTERS, CheckAdapter

    declared = {a.name: a.version for a in DEFAULT_ADAPTERS if not isinstance(a, CheckAdapter)}

    assert _image_pins() == declared


def test_each_golden_fixture_is_the_pinned_version_s_output():
    pins = _image_pins()

    assert PINNED_VERSIONS == pins
    for tool, version in pins.items():
        if tool == "gitleaks":
            continue                # its fixtures are built in conftest, not captured
        assert (REPO / "tests" / "fixtures" / "golden" / f"{tool}-{version}.json").is_file(), \
            f"no golden output captured from {tool} {version}"
