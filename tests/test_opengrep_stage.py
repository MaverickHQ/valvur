"""R27.3: Opengrep's stage without a variable `FROM` (D63b).

Scorecard's Pinned-Dependencies read `FROM opengrep-${TARGETARCH}` as an image not
pinned by hash and scored 9 (R27.1). It was a build stage chosen by the platform, and
`COPY --from` cannot take the variable instead (BuildKit: *variable expansion is not
supported for --from*, measured). So one stage downloads the platform's binary,
checks it against that architecture's pinned digest, and fails on any other: still
one checksum-verified download per architecture, and no `FROM` names a variable.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _instructions() -> str:
    return "\n".join(line for line in (REPO / "Dockerfile").read_text().splitlines()
                     if not line.lstrip().startswith("#"))


def test_no_from_names_a_variable():
    froms = re.findall(r"^FROM\s+(\S+)", _instructions(), re.M)

    assert froms, "no FROM found"
    assert [image for image in froms if "$" in image] == []


def test_one_checksum_verified_download_per_architecture():
    code = _instructions()
    stage = code.split(" AS opengrep\n", 1)[1].split("\nFROM ", 1)[0]

    assert "ARG TARGETARCH" in stage
    assert re.search(r'case "\$TARGETARCH" in', stage)
    assert re.search(r"amd64\)\s*asset=opengrep_musllinux_x86;\s*sha=\"\$OPENGREP_SHA256_AMD64\"",
                     stage)
    assert re.search(r"arm64\)\s*asset=opengrep_musllinux_aarch64;\s*"
                     r"sha=\"\$OPENGREP_SHA256_ARM64\"", stage)
    assert re.search(r"\*\)[^\n]*exit 1", stage), "an unknown platform must fail the build"
    assert 'sha256sum -c -' in stage
    assert stage.count("urlretrieve(") == 1, "one download, of the platform's binary alone"
    assert "AS opengrep-amd64" not in code and "AS opengrep-arm64" not in code
    assert not re.search(r"^ADD .*opengrep", code, re.M)
