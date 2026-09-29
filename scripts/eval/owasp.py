"""Track 1 of the Score: the OWASP Benchmark for Python (ADR-0026, D21).

1,230 small Flask handlers, 530 of them vulnerable, in 14 categories each named by
a CWE. It is GPL-3.0: it is cloned at the pinned commit into the build cache, read
there, and never copied into this repository.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = REPO / "tests" / "eval" / "sources.toml"
KEY = "owasp-benchmark-python"


class PinMismatch(RuntimeError):
    """The checkout is not the commit `sources.toml` pins."""


def source() -> dict:
    return tomllib.loads(SOURCES.read_text())[KEY]


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,  # noqa: S603
                          text=True, check=False)


def verify(checkout: Path) -> None:
    pinned = source()["commit"]
    head = _git(checkout, "rev-parse", "HEAD").stdout.strip()
    if head != pinned:
        raise PinMismatch(f"{checkout} is at {head or 'no commit'}, not the pinned {pinned}")
