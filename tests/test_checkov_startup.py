"""Checkov's startup, measured (task 28.2.1, F1).

The fourth review found Checkov to be the scan's wall clock — 15.5 to 18.8 s of a
16 to 19 s scan on every application repository in the corpus — and named two
hypotheses to measure before either became a change: `--framework` narrowed to
what is present, and an incremental skip. Measured on a workflow-only tree through
Docker Desktop, `--framework github_actions` saved 0.1 s of 10.6 s. A profile of
the run said where the seconds were instead, and neither was Checkov analysing
anything:

- **5.0 s in `getaddrinfo`.** `banner.py` calls the update checker at import, which
  asks PyPI for the latest version. The Dockerfile had set
  `CHECKOV_DISABLE_UPDATE_CHECK=true` to stop it since 23.4.1 — a variable Checkov
  never reads (`env_vars_config.py` reads `CKV_SKIP_PACKAGE_UPDATE_CHECK`). Under
  `--network=none` the lookup waited for DNS to fail; on `full` it would have
  reached pypi.org.
- **2.6 s in `compile`.** The image deleted Checkov's `__pycache__` and runs on a
  read-only root as a non-root user, so every start compiled 3,913 modules from
  source. `checkov --version`: 5.9 s cold, 1.3 s with bytecode.

Both are properties of the image, and both tests here hold them: one over the
Dockerfile's text, one over the image itself.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "Dockerfile"


def _instructions() -> str:
    """The Dockerfile without its comments, so a rule cannot be met by prose."""
    return "\n".join(line for line in DOCKERFILE.read_text().splitlines()
                     if not line.lstrip().startswith("#"))


def test_the_update_check_is_off_by_the_variable_this_checkov_reads():
    code = _instructions()
    assert "CKV_SKIP_PACKAGE_UPDATE_CHECK=true" in code, \
        "the update check runs at every start and waits for DNS under --network=none"
    assert "CHECKOV_DISABLE_UPDATE_CHECK" not in code, \
        "a variable Checkov does not read, kept as if it did"


def test_checkovs_bytecode_is_compiled_into_the_image():
    code = _instructions()
    assert re.search(r"compileall\b[^\n]*/opt/checkov", code), \
        "every Checkov start compiles ~3,900 modules from source"
    assert not re.search(r"find /opt/checkov[^\n]*__pycache__", code), \
        "the bytecode is deleted again after it is compiled"
    assert re.search(r"compileall\b[^\n]*site-packages/valvur", code), \
        "the Checks' own package starts from source too"


@pytest.mark.e2e
def test_the_images_checkov_reads_the_skip_as_true():
    """Not the Dockerfile's word for it: the installed Checkov's own configuration
    object, asked in the image, with no network — the reading that decides whether
    `banner.py` calls out."""
    from valvur.runner import IMAGE, detect_runtime

    probe = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", IMAGE, "/opt/checkov/bin/python",
         "-c", "from checkov.common.util.env_vars_config import env_vars_config as c; "
               "print(c.SKIP_PACKAGE_UPDATE_CHECK)"],
        capture_output=True, text=True, timeout=120, check=False,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "True", probe.stdout


@pytest.mark.e2e
def test_the_image_carries_bytecode_for_checkov_and_the_checks():
    from valvur.runner import IMAGE, detect_runtime

    probe = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", IMAGE, "sh", "-c",
         "find /opt/checkov -name '*.pyc' | wc -l; "
         "find /usr/local/lib/python3.12/site-packages/valvur -name '*.pyc' | wc -l"],
        capture_output=True, text=True, timeout=120, check=False,
    )

    assert probe.returncode == 0, probe.stderr
    checkov, valvur = (int(n) for n in probe.stdout.split())
    assert checkov >= 3000, f"Checkov's bytecode is not in the image ({checkov} .pyc files)"
    assert valvur >= 30, f"valvur's bytecode is not in the image ({valvur} .pyc files)"
