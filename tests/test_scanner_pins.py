"""The version the image pins is the version valvur says ran.

Each Scanner is pinned three times: by the image (the Dockerfile, or a hash-locked
requirements file), by its adapter (`VERSION`, which `run.json` records as the
version that ran), and by its golden fixture's name (the output the parser is
tested against). Dependabot bumps the first alone: its Syft 1.52.0 pull request
(#155, 2026-09-29) passed every check while the adapter still said 1.51.1. A
Scanner upgrade is now all three at once, or red.
"""

from __future__ import annotations

import re
from pathlib import Path

from conftest import PINNED_VERSIONS

REPO = Path(__file__).resolve().parent.parent


def _image_pins() -> dict[str, str]:
    dockerfile = (REPO / "Dockerfile").read_text()
    pins = {}
    for image, stage in (("zricethezav/gitleaks", "gitleaks"), ("aquasec/trivy", "trivy"),
                         ("ghcr.io/google/osv-scanner", "osv-scanner"),
                         ("anchore/syft", "syft")):
        found = re.search(rf"^FROM {re.escape(image)}:v?([\d.]+)@sha256:", dockerfile, re.M)
        assert found, f"the Dockerfile no longer pins {image} by version and digest"
        pins[stage] = found.group(1)
    opengrep = re.search(r"^ARG OPENGREP_URL=\S+/download/v([\d.]+)$", dockerfile, re.M)
    assert opengrep, "the Dockerfile no longer names Opengrep's release"
    pins["opengrep"] = opengrep.group(1)
    for tool, lock in (("checkov", "requirements-checkov.txt"),
                       ("zizmor", "requirements-zizmor.txt")):
        found = re.search(rf"^{tool}==([\d.]+) ", (REPO / lock).read_text(), re.M)
        assert found, f"{lock} no longer pins {tool}"
        pins[tool] = found.group(1)
    return pins


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
