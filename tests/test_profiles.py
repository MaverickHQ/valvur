"""Sub-phase 3.2 — Profile selection and concurrency."""

import time

from valvur import scan
from valvur.adapters import GitleaksAdapter
from valvur.adapters.base import ScannerAdapter


class SlowAdapter(ScannerAdapter):
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


def test_the_offline_profile_runs_only_its_designated_scanners(
    workspace, runner_finding_one_secret
):
    """F2.3 — the offline Profile exists to make non-exfiltration provable. Pulling
    in a Scanner that opens a socket would break that silently.

    Checkov and Syft are deliberately NOT excluded: both complete under
    --network=none, so keeping them out bought nothing and cost coverage (ADR-0016).
    """
    from valvur.profiles import scanners_for

    run = scan(workspace, runner=runner_finding_one_secret, profile="offline")
    ran = {s.tool for s in run.scanners}

    assert ran <= set(scanners_for("offline"))
    assert "osv-scanner" not in ran
    # And the one that USED to be excluded now runs here, from the local index
    # (ADR-0018) — the hallucination check is what the offline Profile is for.
    assert "dependency-reality" in ran


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

    class TimingOut(ScannerAdapter):
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


def test_the_quick_profile_includes_the_ai_artifact_check(workspace, runner_finding_nothing):
    """The differentiator must run on the fast path.

    It is pure static inspection with no network need, so there is no reason to
    make someone opt into a slower scan to get the check nothing else ships.
    """
    run = scan(workspace, runner=runner_finding_nothing, profile="quick")

    assert "ai-artifact" in {s.tool for s in run.scanners}


def test_the_offline_profile_excludes_every_scanner_needing_network(
    workspace, runner_finding_nothing
):
    """N2.1 — the offline Profile must stay offline, so nothing that reaches an
    advisory API may run in it. dependency-reality is no longer in that set: it
    answers existence from the local index and asks a registry only when the Profile
    grants a network (ADR-0018) — asserted in test_constraints, in-process."""
    from valvur.adapters import DEFAULT_ADAPTERS
    from valvur.profiles import ALLOWS_NETWORK, scanners_for, select

    assert ALLOWS_NETWORK["offline"] is False
    assert "osv-scanner" not in scanners_for("offline")
    # Selection is where a network is granted, and offline grants none.
    for adapter in select(DEFAULT_ADAPTERS, "offline"):
        assert not getattr(adapter, "network", False), adapter.name


# ------------------------------------------------ the two-profile split (ADR-0016)

def test_the_offline_profile_runs_every_scanner_that_works_without_a_socket():
    """The split is drawn on whether anything leaves the machine, which is the only
    line this product cares about. Verified, not assumed: checkov with
    --skip-download and syft cataloguing local files both complete under
    --network=none."""
    from valvur.profiles import ALLOWS_NETWORK, OFFLINE, SCANNERS

    assert ALLOWS_NETWORK[OFFLINE] is False
    assert {"checkov", "syft", "trivy", "dependency-reality"} <= set(SCANNERS[OFFLINE])
    assert "osv-scanner" not in SCANNERS[OFFLINE]


def test_only_the_one_socket_scanner_separates_the_profiles():
    """ADR-0018 amended ADR-0016's "the two that genuinely need a socket": the
    dependency-reality Check runs on both, and only its age question needs one."""
    from valvur.profiles import FULL, NEEDS_NETWORK_FOR, OFFLINE, SCANNERS

    extra = set(SCANNERS[FULL]) - set(SCANNERS[OFFLINE])

    assert extra == {"osv-scanner"}
    assert set(NEEDS_NETWORK_FOR) == {"dependency-reality"}


def test_the_full_profile_grants_the_dependency_check_a_network_and_offline_does_not():
    """The grant happens at selection and nowhere else. An adapter taken straight
    from the registry has no network, whatever Profile later runs it."""
    from valvur.adapters import DEFAULT_ADAPTERS
    from valvur.profiles import select

    registry = next(a for a in DEFAULT_ADAPTERS if a.name == "dependency-reality")
    offline = next(a for a in select(DEFAULT_ADAPTERS, "offline") if a.name == registry.name)
    full = next(a for a in select(DEFAULT_ADAPTERS, "full") if a.name == registry.name)

    assert registry.network is False
    assert offline.network is False
    assert full.network is True
    assert registry.network is False, "selection must configure a copy, not the registry entry"


def test_the_offline_gap_prose_names_what_the_check_could_not_do_without_a_network():
    """The Summary's caveat used to say offline lacked "hallucinated and typosquatted
    packages". It no longer lacks those; it lacks package age. Saying the old thing
    would claim less coverage than the scan had — the mirror image of the usual
    failure, and still a false statement about what ran."""
    from valvur.profiles import gaps_in_prose

    offline = gaps_in_prose("offline")

    assert "package age" in offline
    assert "hallucinated" not in offline
    assert "package age" not in gaps_in_prose("full")


def test_offline_is_the_default():
    """The target market cannot send code or manifests anywhere, and the
    dependency-reality Check does transmit package names. Reaching the network is
    opted into, never acquired by typing `valvur scan`."""
    from valvur.profiles import ALLOWS_NETWORK, DEFAULT

    assert ALLOWS_NETWORK[DEFAULT] is False


def test_the_retired_names_still_resolve():
    """An agent config written against 0.1.0rc1 must keep working. `deep` was
    byte-identical to `standard`, so both land on `full`."""
    from valvur.profiles import FULL, OFFLINE, resolve

    assert resolve("quick") == OFFLINE
    assert resolve("standard") == resolve("deep") == FULL
    assert resolve("offline") == OFFLINE


def test_a_retired_name_does_not_silently_disable_the_network():
    """Every downstream lookup is a dict.get with a default, so an unresolved
    "standard" would land on ALLOWS_NETWORK's False and turn the network off without
    saying so — a silent narrowing of the scan."""
    from valvur.profiles import ALLOWS_NETWORK, resolve

    assert ALLOWS_NETWORK[resolve("standard")] is True


def test_the_coverage_contract_says_whether_package_age_was_checked(
    workspace, runner_finding_nothing
):
    """`run.json`'s coverage block is the reader's answer to "what did you look
    at?". Offline it must say age was not; on `full` it must not say that — the
    contract is collected from the whole registry, so each adapter has to be told the
    Profile's grant or the offline sentence would appear on every run (ADR-0018)."""
    offline = scan(workspace, runner=runner_finding_nothing, profile="offline")
    full = scan(workspace, runner=runner_finding_nothing, profile="full")

    def ignores(run):
        return " ".join(run.coverage["dependency-reality"]["ignores"])

    assert "first-publish age" in ignores(offline)
    assert "first-publish age" not in ignores(full)
