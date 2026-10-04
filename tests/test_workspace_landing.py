"""The Snapshot's volume is writable by whoever runs the scan (ADR-0022).

Up to `TMPFS_LIMIT` the Snapshot lands in a tmpfs made with mode 1777; past it, in a
per-scan named volume, which Docker's classic store initialises from the image's
`/workspace`: its owner and its mode. `WORKDIR /workspace` under `USER 10001` made
that 10001:10001, 755, and the scan runs as the invoking user (`--user`,
`runner._user_flags`) with every capability dropped, so the engine could not write
the first file (`PermissionError: '/workspace/app.py'`, measured on Docker 29 with
the classic store, and in rehearsal run 37210754192 on one amd64 runner). A scan of
a Snapshot over 512 MiB failed on such a host. The directory is made 1777, as the
tmpfs is, before the image drops to its own user.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _instructions() -> str:
    return "\n".join(line for line in (REPO / "Dockerfile").read_text().splitlines()
                     if not line.lstrip().startswith("#"))


def test_the_workspace_is_made_world_writable_and_sticky_before_the_image_drops_root():
    code = _instructions()
    made = re.search(r"^RUN mkdir -p /workspace && chmod 1777 /workspace$", code, re.M)

    assert made, "the volume's landing keeps the image user's owner and mode"
    assert made.start() < code.index("\nUSER 10001:10001")


@pytest.mark.e2e
def test_the_images_workspace_is_1777():
    from valvur.runner import IMAGE, detect_runtime

    probe = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", "--entrypoint", "stat", IMAGE,
         "-c", "%a", "/workspace"], capture_output=True, text=True, timeout=120, check=False)

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "1777"
