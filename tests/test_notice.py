"""NOTICE — the attribution the redistributed tools' licences ask for (28.3.5, B2).

The image redistributes Opengrep (LGPL-2.1), Gitleaks (MIT) and four Apache-2.0
tools, and the SBOM discloses components; it did not carry the attribution text
Apache §4(d) and the LGPL expect, and the repository had no `NOTICE`. Both now:
one file, at the root and at `/usr/share/doc/valvur/NOTICE` in the image. Held
to the Dockerfile: every `FROM … AS` stage names a tool the file attributes, so a
new tool cannot arrive unattributed.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
NOTICE = REPO / "NOTICE"

#: How a Dockerfile stage names a tool, and how NOTICE names the same one.
_STAGE_NAMES = {"opengrep": "Opengrep", "gitleaks": "Gitleaks", "trivy": "Trivy",
                "osv": "OSV-Scanner", "syft": "Syft"}


def _stages() -> set[str]:
    stages = set()
    for line in (REPO / "Dockerfile").read_text().splitlines():
        match = re.match(r"^FROM\s+\S+\s+AS\s+(\S+)", line)
        if match:
            stages.add(re.sub(r"-(amd64|arm64)$", "", match.group(1)))
    return stages


def test_every_dockerfile_stage_is_attributed():
    notice = NOTICE.read_text(encoding="utf-8")
    stages = _stages()

    assert stages, "no named stages in the Dockerfile — this test is asserting nothing"
    for stage in stages:
        assert stage in _STAGE_NAMES, (
            f"stage {stage!r} is new: add the tool to NOTICE and its name to this table"
        )
        assert _STAGE_NAMES[stage] in notice, f"{_STAGE_NAMES[stage]} is redistributed unattributed"


def test_every_tool_names_its_licence_and_its_upstream():
    """Checkov is installed by pip rather than copied from a stage, and is held
    here by name for that reason."""
    notice = NOTICE.read_text(encoding="utf-8")
    expected = {
        "Opengrep": ("LGPL-2.1", "github.com/opengrep/opengrep"),
        "Gitleaks": ("MIT", "github.com/gitleaks/gitleaks"),
        "Trivy": ("Apache License 2.0", "github.com/aquasecurity/trivy"),
        "OSV-Scanner": ("Apache License 2.0", "github.com/google/osv-scanner"),
        "Syft": ("Apache License 2.0", "github.com/anchore/syft"),
        "Checkov": ("Apache License 2.0", "github.com/bridgecrewio/checkov"),
    }
    for tool, (licence, upstream) in expected.items():
        block = notice.split(f"\n{tool}\n", 1)
        assert len(block) == 2, f"{tool} has no entry"
        entry = block[1].split("\n\n", 1)[0]
        assert licence in entry, f"{tool}: licence not named"
        assert upstream in entry, f"{tool}: upstream not named"


def test_the_dockerfile_copies_the_notice_to_the_documented_path():
    from valvur import tree_hash

    dockerfile = (REPO / "Dockerfile").read_text()
    assert f"COPY NOTICE {tree_hash.IMAGE_NOTICE}" in dockerfile
    assert tree_hash.IMAGE_NOTICE == "/usr/share/doc/valvur/NOTICE"


@pytest.mark.e2e
def test_the_image_carries_the_notice_byte_for_byte():
    from valvur import tree_hash
    from valvur.runner import IMAGE, detect_runtime

    probe = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", IMAGE, "cat", tree_hash.IMAGE_NOTICE],
        capture_output=True, text=True, timeout=120, check=False,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout == NOTICE.read_text(encoding="utf-8")
