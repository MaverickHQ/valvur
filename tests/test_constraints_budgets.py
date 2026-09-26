"""Phase 11 cycle 5 — the time and memory budgets (N1.1, N1.2, N1.4), asserted as
budgets rather than as measurements. Split from `test_constraints.py` (28.4.3).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from conftest import LegacyDispatch

from valvur import profiles
from valvur.api import scan

# ------------------------------------------------------ cycle 5: both budgets

# Measured 2026-09-01 on this repository's own source — 38,697 lines, the largest
# real codebase to hand — with a warm image and database:
#
#   offline  23.4s   (N1.1 budget: 60s)
#   full     25.2s   (N1.2 budget: 300s)
#   peak container memory  344 MiB   (N1.4 budget: 2 GB)
#
# And 2026-09-13 (task 24.3) on the public corpus, on GitHub's ubuntu-latest (24.04), with
# 23.3.2's per-Scanner timing: 14-18s offline on every application repository from
# 22k to 100k lines — flat with size, because it is Checkov's ~15s start-up and
# every other Scanner is 1-4s — and 88s on a 22k-line Terraform module, which is
# Checkov analysing it. N1.1 was amended to say both. On this laptop through Docker
# Desktop the same workspace read 60-94s under load, which is why the requirement
# names the machine class; CI is the arbiter of this test.
#
# The budgets are asserted rather than the measurements: a test pinned to 23.4s
# fails on a slower machine while telling nobody anything useful. A failure here
# means the REQUIREMENT is at risk, which is the only reason to have it.
N1_1_OFFLINE_SECONDS = 60
N1_2_FULL_SECONDS = 300


def _sizeable_workspace(root: Path) -> Path:
    """A real codebase, without the virtualenv. Copying the repository wholesale
    would scan .venv, which is both enormous and excluded in practice."""
    import shutil

    repo = Path(__file__).resolve().parent.parent
    ws = root / "sizeable"
    ws.mkdir()
    for name in ("src", "tests", "docs", "scripts", "rules"):
        source = repo / name
        if source.is_dir():
            shutil.copytree(source, ws / name, ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("pyproject.toml", "Dockerfile", "README.md", "CLAUDE.md"):
        if (repo / name).is_file():
            shutil.copy2(repo / name, ws / name)
    return ws


@pytest.mark.e2e
def test_the_offline_profile_meets_its_time_budget(mountable_tmp):
    """N1.1 — 60 seconds. This is now the TIGHTER of the two budgets, which it was
    not when written: ADR-0016 moved Checkov into `offline`, and Checkov is the
    single slowest Scanner. The old `quick` had no Checkov and no risk here."""
    import time

    from valvur.runner import ContainerRunner

    ws = _sizeable_workspace(mountable_tmp)
    started = time.monotonic()
    run = scan(ws, runner=ContainerRunner(), profile=profiles.OFFLINE)
    elapsed = time.monotonic() - started

    assert not run.failures, f"a Scanner failed, so the timing is meaningless: {run.failures}"
    assert elapsed < N1_1_OFFLINE_SECONDS, (
        f"offline took {elapsed:.1f}s against a {N1_1_OFFLINE_SECONDS}s budget (N1.1)"
    )


@pytest.mark.e2e
def test_the_full_profile_meets_its_time_budget(mountable_tmp):
    """N1.2 — 5 minutes."""
    import time

    from valvur.runner import ContainerRunner

    ws = _sizeable_workspace(mountable_tmp)
    started = time.monotonic()
    run = scan(ws, runner=ContainerRunner(), profile=profiles.FULL)
    elapsed = time.monotonic() - started

    assert not run.failures, f"a Scanner failed, so the timing is meaningless: {run.failures}"
    assert elapsed < N1_2_FULL_SECONDS, (
        f"full took {elapsed:.1f}s against a {N1_2_FULL_SECONDS}s budget (N1.2)"
    )


# N1.4 — 2 GB, for the whole fleet together plus the shim. Measured by hand at
# 344 MiB on 2026-09-01 and never asserted until task 24.3: the requirement was
# cited by a test that skipped itself. Now sampled from `<runtime> stats` while a
# `full` scan runs — on Linux, where the runtime's cgroup accounting is native;
# through Docker Desktop's VM the same numbers are reported but describe the VM's
# view, so macOS keeps the hand measurement and the skip says so.
N1_4_BYTES = 2 * 1024**3

_UNITS = {"b": 1, "kb": 1000, "mb": 1000**2, "gb": 1000**3,
          "kib": 1024, "mib": 1024**2, "gib": 1024**3}


def _parse_mem_usage(text: str) -> int:
    """The bytes in use from a `stats` MemUsage cell: docker prints `123.4MiB /
    15.6GiB`, podman `123.4MB / 15.6GB`. The first half is the usage."""
    import re

    used = text.split("/")[0].strip()
    match = re.fullmatch(r"([0-9.]+)\s*([A-Za-z]+)", used)
    if not match:
        raise ValueError(f"unrecognised memory usage: {text!r}")
    return int(float(match.group(1)) * _UNITS[match.group(2).lower()])


class _FleetMemory(LegacyDispatch):
    """Samples every valvur container's memory while a scan runs and keeps the
    highest sum seen. A sample is one `stats --no-stream`, about a second."""

    def __init__(self, runtime: str):
        self.runtime = runtime
        self.peak = 0
        self.peak_seen = ""
        self.samples = 0
        self._stop = False

    def _sample(self) -> None:
        proc = subprocess.run(
            [self.runtime, "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode != 0:
            return
        fleet = {}
        for line in proc.stdout.splitlines():
            name, _, usage = line.partition("\t")
            if name.startswith("valvur-") and usage:
                fleet[name] = _parse_mem_usage(usage)
        self.samples += 1
        if sum(fleet.values()) > self.peak:
            self.peak = sum(fleet.values())
            self.peak_seen = ", ".join(f"{n} {b // 2**20}MiB" for n, b in sorted(fleet.items()))

    def run(self) -> None:
        while not self._stop:
            self._sample()

    def stop(self) -> None:
        self._stop = True


@pytest.mark.e2e
@pytest.mark.skipif(
    __import__("platform").system() != "Linux",
    reason="N1.4 is asserted on Linux (CI), where the runtime's memory accounting is "
    "the kernel's own. Measured by hand on macOS at 344 MiB on 2026-09-01.",
)
def test_a_full_scan_stays_within_its_memory_budget(mountable_tmp):
    """N1.4 — 2 GB: every container of the fleet at once, plus the shim itself."""
    import os
    import resource
    import threading

    from valvur.runner import ContainerRunner, detect_runtime

    ws = _sizeable_workspace(mountable_tmp)
    fleet = _FleetMemory(detect_runtime())
    sampler = threading.Thread(target=fleet.run, daemon=True)
    sampler.start()
    try:
        run = scan(ws, runner=ContainerRunner(), profile=profiles.FULL)
    finally:
        fleet.stop()
        sampler.join(timeout=90)
    shim = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024   # KiB on Linux
    peak = fleet.peak + shim
    report = (f"N1.4: peak {peak / 2**20:.0f} MiB of a {N1_4_BYTES / 2**30:.0f} GiB budget — "
              f"fleet {fleet.peak / 2**20:.0f} MiB at most ({fleet.peak_seen}), shim "
              f"{shim / 2**20:.0f} MiB, {fleet.samples} samples")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).open("a", encoding="utf-8").write(report + "\n")
    print(report)

    assert not run.failures, f"a Scanner failed, so the measurement is void: {run.failures}"
    assert fleet.samples >= 3, f"stats answered {fleet.samples} time(s); the measurement is void"
    assert peak < N1_4_BYTES, report


def test_a_stats_cell_is_read_in_either_runtimes_units():
    assert _parse_mem_usage("123.4MiB / 15.6GiB") == int(123.4 * 1024**2)
    assert _parse_mem_usage("123.4MB / 15.6GB") == int(123.4 * 1000**2)
    assert _parse_mem_usage("2.5GiB / 15.6GiB") == int(2.5 * 1024**3)
    assert _parse_mem_usage("900kB / 1GB") == 900_000
    with pytest.raises(ValueError):
        _parse_mem_usage("-- / --")


