"""pip out of the final image (the owner, 2026-10-25).

The base's pip installs the two hash-locked environments, Checkov's and zizmor's, and is
used by nothing after them: valvur's own package is copied in, and no Scanner calls pip.
Yet it shipped, and R43.4's image gate counted six advisories in it on both architectures
(CVE-2025-8869, CVE-2026-1703, -3219, -6357, -8643 and -13346), which 1.5.4's notes omitted.
So once both environments are installed, the base's pip is removed from
`/usr/local/lib/python3.12/site-packages` and `/usr/local/bin`.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SITE = "/usr/local/lib/python3.12/site-packages"


def _final_stage() -> str:
    text = (REPO / "Dockerfile").read_text()
    return text[text.rindex("\nFROM "):]


def test_pip_is_removed_after_the_last_environment_is_installed_and_never_called_again():
    stage = _final_stage()
    code = "\n".join(line for line in stage.splitlines() if not line.lstrip().startswith("#"))

    removal = code.index(f"rm -rf {SITE}/pip {SITE}/pip-*.dist-info")
    assert code.index("--python /opt/zizmor/bin/python install") < removal
    assert code.index("--python /opt/checkov/bin/python install") < removal
    assert "/usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12" in code[removal:]
    after = code[removal:].split("\n", 1)[1]
    assert not re.search(r"(?:^|[\s&;])pip3?(?:\.12)? |-m pip\b|ensurepip", after), after


def _image() -> str:
    from valvur.engine_host import IMAGE

    return IMAGE


@pytest.mark.e2e
def test_the_image_has_no_pip():
    probe = ("import importlib.util, shutil, glob, sys; "
             "print(importlib.util.find_spec('pip') is None, "
             "[shutil.which(n) for n in ('pip', 'pip3', 'pip3.12')], "
             f"glob.glob('{SITE}/pip*'))")
    said = subprocess.run(["docker", "run", "--rm", _image(), "python3", "-c", probe],
                          capture_output=True, text=True, check=True).stdout.strip()

    assert said == "True [None, None, None] []"


@pytest.mark.e2e
def test_its_sbom_lists_no_pip():
    """What `scripts/check_image_licences.py` reads, Syft over the image: valvur's own
    component inventory of what it ships. pip 25.0.1 was in it, from the base."""
    import importlib.util

    path = REPO / "scripts" / "check_image_licences.py"
    spec = importlib.util.spec_from_file_location("check_image_licences", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    components = module.sbom(_image()).get("components", [])

    assert components, "the SBOM listed nothing"
    assert [c for c in components if c.get("name", "").lower() == "pip"] == []


#: pip 25.0.1's advisories in the image gate, run 40222670372 (2026-10-25), on both
#: architectures; 1.5.4's notes omitted them.
PIP_ADVISORIES = {"CVE-2025-8869", "CVE-2026-1703", "CVE-2026-3219", "CVE-2026-6357",
                  "CVE-2026-8643", "CVE-2026-13346"}


@pytest.mark.e2e
def test_the_image_gate_finds_none_of_pip_s_six_advisories():
    import json

    from valvur import cache

    database = cache.root() / "trivy"
    scan = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{database}:/db:ro",
         "--entrypoint", "trivy", _image(), "rootfs", "--cache-dir", "/db", "--cache-backend",
         "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--format",
         "json", "--scanners", "vuln", "--quiet", "/"],
        capture_output=True, text=True, check=True).stdout
    found = {(v["VulnerabilityID"], v["PkgName"]) for r in json.loads(scan).get("Results") or []
             for v in r.get("Vulnerabilities") or []}

    assert found, "the scan found nothing at all, so it read nothing"
    assert {i for i, package in found if package == "pip"} == set()
    assert not PIP_ADVISORIES & {i for i, _ in found}
