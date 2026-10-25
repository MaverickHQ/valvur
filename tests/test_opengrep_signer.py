"""Opengrep's signer, as its releases name it (task 15.2, moved for 1.31.0).

Opengrep signs each release keylessly with sigstore, from its `rolling-release.yml`. Up to
1.30.0 the workflow ran on `main`; from 1.30.2 it runs on a branch named for the release,
`release-v<version>` (read from each release's certificate, 2026-10-25). The check accepts
the one identity that release can have: the same repository, the same workflow, and the
branch named for exactly the version the Dockerfile pins.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_the_signature_check_accepts_only_the_release_s_own_branch():
    script = (REPO / "scripts" / "verify-opengrep.sh").read_text()

    [identity] = re.findall(r'^IDENTITY="([^"]+)"$', script, re.M)
    assert identity == ("https://github.com/opengrep/opengrep/.github/workflows/"
                        "rolling-release.yml@refs/heads/release-${VERSION}")
    assert "--certificate-identity \"$IDENTITY\"" in script
    assert "regexp" not in script


def test_the_dockerfile_names_the_same_signer_for_the_version_it_pins():
    dockerfile = (REPO / "Dockerfile").read_text()
    version = re.search(r"^ARG OPENGREP_URL=\S+/download/(v[\d.]+)$", dockerfile, re.M)[1]

    assert ("#   identity  https://github.com/opengrep/opengrep/.github/workflows/"
            f"rolling-release.yml@refs/heads/release-{version}") in dockerfile
