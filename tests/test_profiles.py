"""Sub-phase 3.2 — Profile selection and concurrency."""

import time

from valvur import scan
from valvur.adapters import GitleaksAdapter


class SlowAdapter:
    """A Scanner that takes its time, so serialisation is observable."""

    def __init__(self, name, seconds=0.3):
        self.name = name
        self._seconds = seconds

    def run(self, runner, workspace):
        from valvur.runner import ScannerOutput

        time.sleep(self._seconds)
        return ScannerOutput(tool=self.name, version="1.0", stdout="[]", stderr="", exit_code=0)

    def parse(self, output):
        return []


def test_the_quick_profile_runs_only_its_designated_scanners(
    workspace, runner_finding_one_secret
):
    """F2.3 — the quick profile exists to be fast and offline. Running everything
    would silently break both promises."""
    from valvur.profiles import scanners_for

    run = scan(workspace, runner=runner_finding_one_secret, profile="quick")
    ran = {s.tool for s in run.scanners}

    # Only registered adapters can run; quick must not pull in standard-only ones.
    assert ran <= set(scanners_for("quick"))
    assert "osv-scanner" not in ran and "checkov" not in ran


def test_independent_scanners_do_not_serialise(workspace, runner_finding_nothing):
    """F2.6 — six Scanners run serially will not meet the 5-minute standard budget."""
    adapters = [SlowAdapter(f"slow-{i}") for i in range(4)]

    started = time.monotonic()
    scan(workspace, runner=runner_finding_nothing, adapters=adapters)
    elapsed = time.monotonic() - started

    assert elapsed < 0.9, f"4 x 0.3s took {elapsed:.2f}s — they serialised"


def test_one_scanner_timing_out_does_not_delay_or_fail_the_others(
    workspace, runner_finding_nothing
):
    """F2.7 — the timeout is per-Scanner. A hung Trivy must not hold up Gitleaks."""
    import subprocess

    class TimingOut:
        name = "hangs"

        def run(self, runner, ws):
            time.sleep(0.2)
            raise subprocess.TimeoutExpired(cmd="hangs", timeout=0.2)

        def parse(self, output):  # pragma: no cover
            return []

    started = time.monotonic()
    run = scan(
        workspace,
        runner=runner_finding_nothing,
        adapters=[GitleaksAdapter(), TimingOut(), SlowAdapter("slow", 0.2)],
    )
    elapsed = time.monotonic() - started

    assert [s.tool for s in run.failures] == ["hangs"]
    assert elapsed < 0.5, f"took {elapsed:.2f}s — the timeout serialised the others"
