"""Phase 11 cycle 4 — nothing is written outside the Results Folder and the
scratch mount, and every Scanner sees the Workspace read-only. Split from
`test_constraints.py` (28.4.3).
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

import pytest

from valvur import profiles
from valvur.api import scan

# ------------------------ cycle 4: nothing is written outside results and scratch

@pytest.mark.e2e
def test_every_scanner_mounts_the_workspace_read_only(monkeypatch, tmp_path):
    """F1.1, N2.2 — the mount IS the jail (ADR-0001). Not a check valvur performs, a
    thing that cannot happen.

    Asserted over every Scanner the Profile runs, rather than one ad-hoc container:
    a Scanner added without `:ro` would otherwise be caught by review or not at all.
    """
    from valvur import cache
    from valvur.adapters import DEFAULT_ADAPTERS
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []

    def capture(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(subprocess, "run", capture)
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    for adapter in profiles.select(DEFAULT_ADAPTERS, profiles.FULL):
        with contextlib.suppress(Exception):
            adapter.run(runner, tmp_path)

    # Only the values of -v flags. Syft's scan target is the string "dir:/workspace",
    # which is an argument rather than a mount and would otherwise fail this.
    mounts = [
        cmd[i + 1]
        for cmd in launched if isinstance(cmd, list)
        for i, arg in enumerate(cmd[:-1])
        if arg == "-v" and ":/workspace" in str(cmd[i + 1])
    ]
    assert mounts, "no workspace mount was built, so nothing was asserted"
    for mount in mounts:
        assert mount.endswith(":/workspace:ro"), f"workspace mounted writable: {mount}"


@pytest.mark.e2e
def test_a_scan_writes_nothing_outside_the_results_folder(mountable_tmp):
    """N2.2 — a real scan, with sentinels planted around the Workspace.

    The existing workspace-unchanged test runs against a fake runner, so it proves
    the orchestration does not write. This runs the real containers, and watches the
    parent directory too: a path-handling bug that escaped the mount would land
    beside the Workspace rather than inside it, where the other test cannot see it.
    """
    import hashlib
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "repo"
    shutil.copytree(FIXTURES / "broken-repo", ws)
    sentinel = mountable_tmp / "DO-NOT-TOUCH.txt"
    sentinel.write_text("untouched")
    neighbour = mountable_tmp / "sibling"
    neighbour.mkdir()
    (neighbour / "file.txt").write_text("also untouched")

    def digest(root):
        return {
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*"))
            if p.is_file() and ".security-scan" not in p.parts
        }

    before = digest(mountable_tmp)
    scan(ws, runner=ContainerRunner(), profile=profiles.OFFLINE)
    after = digest(mountable_tmp)

    assert after == before, (
        f"files changed outside the Results Folder: "
        f"{set(after) ^ set(before) or [k for k in before if before[k] != after.get(k)]}"
    )
    assert (ws / ".security-scan" / "SUMMARY.md").is_file(), "the scan wrote nothing at all"


@pytest.mark.e2e
def test_the_host_scratch_is_removed_after_a_scan(mountable_tmp):
    """ADR-0001 mounts a scratch dir `:rw` so containers can write reports. It is a
    TemporaryDirectory, so it must not survive the run — a scanner's raw output
    contains live credentials (F5.7), and leaving it in /tmp puts them in a second
    cleartext location nobody knows to clean up."""
    import shutil
    import tempfile

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "repo"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    root = Path(tempfile.gettempdir())
    before = {p.name for p in root.glob("valvur-*")}
    scan(ws, runner=ContainerRunner(), profile=profiles.OFFLINE)
    leaked = {p.name for p in root.glob("valvur-*")} - before

    assert not leaked, f"scratch directories survived the scan: {sorted(leaked)}"


