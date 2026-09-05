"""F1.12 and N2.6 — one writer per Results Folder, one writer per database cache.

Two resources with different shapes, so two policies.

The Workspace: concurrent scans do not corrupt anything — measured 2026-09-05, four
of them left every artifact valid and internally consistent — but both read the same
`state.json`, both write their own, and the last wins. The next run then computes its
new/fixed/regressed diff against a view that never happened. Silent, and the status
diff is the one artifact a developer trusts to say whether they made progress.

The database cache: every scan reads it, only `valvur update` writes it. So readers
share and the writer excludes, rather than everything excluding everything.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from valvur.locking import Busy, cache_lock, held, workspace_lock

PROBE = """
import sys
from pathlib import Path
from valvur.locking import held, Busy
exclusive = sys.argv[2] == "exclusive"
try:
    with held(Path(sys.argv[1]), exclusive=exclusive, wait=False):
        print("ACQUIRED")
except Busy:
    print("REFUSED")
"""


def _other_process(lock: Path, *, exclusive: bool) -> str:
    """A genuinely separate process.

    `os.fork` will not do: flock belongs to the open file description, which a fork
    inherits, so the child holds the same lock and every test passes vacuously. Found
    the hard way while writing this.
    """
    mode = "exclusive" if exclusive else "shared"
    return subprocess.run(
        [sys.executable, "-c", PROBE, str(lock), mode],
        capture_output=True, text=True, check=False,
    ).stdout.strip()


def test_a_second_scan_of_one_workspace_is_refused(tmp_path):
    lock = workspace_lock(tmp_path / ".security-scan")

    with held(lock, exclusive=True, wait=False):
        assert _other_process(lock, exclusive=True) == "REFUSED"


def test_the_lock_is_released_when_the_scan_finishes(tmp_path):
    """The pair. A lock that is never released turns one crashed scan into a
    permanently unscannable workspace."""
    lock = workspace_lock(tmp_path / ".security-scan")

    with held(lock, exclusive=True, wait=False):
        pass

    assert _other_process(lock, exclusive=True) == "ACQUIRED"


def test_a_killed_process_leaves_no_stale_lock(tmp_path):
    """Why flock rather than a PID file: the kernel releases it when the process
    dies, so a crashed or Ctrl-C'd scan (task 16.2 makes that routine) leaves nothing
    to reap and no manual cleanup for the user."""
    lock = workspace_lock(tmp_path / ".security-scan")
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys, time\n"
         "from pathlib import Path\n"
         "from valvur.locking import held\n"
         "with held(Path(sys.argv[1]), exclusive=True, wait=True):\n"
         "    print('HELD', flush=True)\n"
         "    time.sleep(60)\n", str(lock)],
        stdout=subprocess.PIPE, text=True,
    )
    assert holder.stdout.readline().strip() == "HELD"
    holder.kill()
    holder.wait(timeout=10)

    assert _other_process(lock, exclusive=True) == "ACQUIRED"


def test_many_scans_may_read_the_database_at_once(tmp_path):
    """Shared, because every scan reads the database and only `update` writes it.
    Mutual exclusion here would serialise unrelated scans for no reason."""
    lock = cache_lock(tmp_path)

    with held(lock, exclusive=False, wait=False):
        assert _other_process(lock, exclusive=False) == "ACQUIRED"


def test_an_update_cannot_start_while_a_scan_is_reading(tmp_path):
    """The hazard this exists for. trivy.db is a 1.35GB BoltDB and Trivy takes no
    lock of its own — measured, there is no lock file in the cache directory."""
    lock = cache_lock(tmp_path)

    with held(lock, exclusive=False, wait=False):
        assert _other_process(lock, exclusive=True) == "REFUSED"


def test_the_results_folder_ignores_itself_from_the_moment_it_exists(tmp_path):
    """ADR-0011 is a guarantee about the folder, not about a successful scan.

    Taking the lock creates the Results Folder before the scan has produced anything,
    and `results.write()` writes the self-ignoring `.gitignore` only at the end — too
    late if the run is interrupted, which task 16.2 makes routine.
    """
    results = tmp_path / ".security-scan"

    workspace_lock(results)

    assert (results / ".gitignore").read_text().strip() == "*"


def test_a_busy_lock_says_what_to_do_about_it(tmp_path):
    lock = workspace_lock(tmp_path / ".security-scan")

    with held(lock, exclusive=True, wait=False):
        with pytest.raises(Busy) as refused:
            with held(lock, exclusive=True, wait=False,
                      busy_message="a scan is already running here"):
                pass

    assert "already running" in str(refused.value)
