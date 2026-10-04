"""Phase 11 cycle 4 — nothing is written outside the Results Folder and the
scratch mount, and every Scanner sees the Workspace read-only. Split from
`test_constraints.py` (28.4.3).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fixture_copy import copy_fixture

from valvur import profiles
from valvur.api import scan

# ------------------------ cycle 4: nothing is written outside results and scratch

def test_every_scanner_reads_a_snapshot_and_the_source_is_never_mounted(monkeypatch, tmp_path):
    """F1.1, N2.2 — the source cannot be written because no container can reach it.
    Protocol 1 mounted it `:ro` into every Scanner's container (ADR-0001); since
    R3.9 it is copied into the Scan Container on stdin (ADR-0022), and nothing
    mounts it at all. Asserted over every Scan Container a `full` scan starts."""
    from test_constraints_exfiltration import _launches

    launched = _launches(profiles.FULL, tmp_path, monkeypatch)
    assert launched, "no container was launched, so nothing was asserted"
    workspace = str(tmp_path / "ws")
    for argv, tools in launched:
        mounts = [argv[i + 1] for i, flag in enumerate(argv) if flag == "-v"]
        assert not any(m.split(":", 1)[0].startswith(workspace) for m in mounts), mounts
        assert "-i" in argv, "the Snapshot arrives on stdin"
        landing = [argv[i + 1] for i in range(len(argv) - 1)
                   if argv[i] in ("--tmpfs", "-v")
                   and (argv[i + 1].startswith("/workspace:") or ":/workspace" in argv[i + 1])]
        assert landing, f"no /workspace for the Snapshot: {tools}"


@pytest.mark.e2e
def test_a_scan_writes_nothing_outside_the_results_folder(mountable_tmp):
    """N2.2 — a real scan, with sentinels planted around the Workspace.

    The existing workspace-unchanged test runs against a fake runner, so it proves
    the orchestration does not write. This runs the real containers, and watches the
    parent directory too: a path-handling bug that escaped the mount would land
    beside the Workspace rather than inside it, where the other test cannot see it.
    """
    import hashlib

    from conftest import FIXTURES

    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "repo"
    copy_fixture(FIXTURES / "broken-repo", ws)
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
    scan(ws, runner=ContainerRuntime(), profile=profiles.OFFLINE)
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
    import tempfile

    from conftest import FIXTURES

    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "repo"
    copy_fixture(FIXTURES / "broken-repo", ws)

    root = Path(tempfile.gettempdir())
    before = {p.name for p in root.glob("valvur-*")}
    scan(ws, runner=ContainerRuntime(), profile=profiles.OFFLINE)
    leaked = {p.name for p in root.glob("valvur-*")} - before

    assert not leaked, f"scratch directories survived the scan: {sorted(leaked)}"


