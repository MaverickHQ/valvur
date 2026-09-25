"""GitHub's own guards on this repository (task 28.0.1, O1).

Measured 2026-09-23: `secret_scanning`, `secret_scanning_push_protection`,
`dependabot_security_updates` and vulnerability alerts were all disabled on a
security scanner's public repository — code scanning alone was on. The defences
that existed (the gitleaks pre-commit hook, the per-PR self-scan) are local,
bypassable with `--no-verify`, cover the working tree and not the history, and
cannot revoke a leaked partner token. CLAUDE.md §9: anything we preach but do not
practise is the first thing a reviewer will notice.

Marked `e2e` because it asks GitHub; the unit suite never opens a socket.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

REPOSITORY = "MaverickHQ/valvur"

#: What must be on, and stay on. A fifth guard that arrives is added here, not
#: switched on quietly.
REQUIRED = (
    "secret_scanning",
    "secret_scanning_push_protection",
    "dependabot_security_updates",
)


def _gh(*args: str) -> str:
    gh = shutil.which("gh")
    if gh is None:
        pytest.skip("gh is not installed")
    done = subprocess.run([gh, *args], capture_output=True, text=True, check=False, timeout=60)
    if done.returncode != 0:
        pytest.skip(f"gh could not ask GitHub: {done.stderr.strip()[:120]}")
    return done.stdout


@pytest.mark.e2e
def test_the_repositorys_own_guards_are_on():
    settings = json.loads(_gh("api", f"repos/{REPOSITORY}", "--jq", ".security_and_analysis"))
    off = [name for name in REQUIRED if (settings.get(name) or {}).get("status") != "enabled"]

    assert not off, f"disabled on {REPOSITORY}: {off} — a security tool with its own guards off"


@pytest.mark.e2e
def test_vulnerability_alerts_are_on():
    """`GET /vulnerability-alerts` answers 204 when on and 404 when off. Both
    endpoints here need an admin-scoped token: on CI the e2e job's `gh` has no
    token at all (exit 4, measured on PR #83's first run) and its GITHUB_TOKEN is
    `contents: read`, so there the answer is a skip, and the tests hold on a
    maintainer's machine. Only the 404 — the guard actually off — is a failure."""
    gh = shutil.which("gh")
    if gh is None:
        pytest.skip("gh is not installed")
    done = subprocess.run([gh, "api", f"repos/{REPOSITORY}/vulnerability-alerts"],
                          capture_output=True, text=True, check=False, timeout=60)

    if done.returncode != 0 and "404" not in done.stderr:
        pytest.skip(f"gh could not ask GitHub: {done.stderr.strip()[:120]}")
    assert done.returncode == 0, (
        f"vulnerability alerts are off on {REPOSITORY}: {done.stderr.strip()[:120]}"
    )
