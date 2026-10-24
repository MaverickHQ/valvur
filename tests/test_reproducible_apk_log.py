"""The image stays reproducible on Alpine 3.24 (28.4.5, B3).

Alpine 3.24's apk-tools 3 appends each transaction, with the time it ran, to
`/var/log/apk.log`, which the base image ships. Two builds of one tree differed in that
file alone, measured on 2026-10-24 by comparing the two images' files: 21,605 each, one
different. apk 2, on Alpine 3.22, kept no log. Every apk call passes `--no-logfile`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_every_apk_call_in_the_dockerfile_keeps_no_log():
    dockerfile = "\n".join(line for line in (REPO / "Dockerfile").read_text().splitlines()
                           if not line.lstrip().startswith("#"))
    lines = [m.group(0) for m in re.finditer(r"\bapk (?:add|del)\b[^\n]*", dockerfile)]

    assert len(lines) == 2, lines
    for line in lines:
        assert "--no-logfile" in line, line
