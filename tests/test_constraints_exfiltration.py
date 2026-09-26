"""Phase 11 — the product's central claims, as tests rather than assertions.

N2.1 and ADR-0010: an `offline` **Scan Run** sends nothing. The claim has two halves
and one flag only covers one of them:

  - The **Scanners** run in containers launched with `--network=none`.
  - The **host shim** is not in a container and could open a socket. It has a reason
    to — enrichment fetches EPSS from FIRST — gated by a single boolean threaded from
    the **Profile**. One inverted condition and the guarantee is gone with no visible
    symptom, because nothing in the output would change.

Both halves are asserted here, and each is paired with a check that it can FAIL. An
assertion that cannot fail is how the first version of this passed against a clean
repository on 2026-08-31: with no CVEs, enrichment is never reached, so "no
connection was made" was true and meaningless.
"""

from __future__ import annotations

import contextlib
import subprocess

import pytest
from constraints_support import CveRunner

from valvur import profiles
from valvur.api import scan

# ------------------------------------------------- half 1: the host shim (N2.1)

def test_the_offline_profile_opens_no_connection_from_the_host_process(
    workspace, record_connections
):
    """N2.1, ADR-0010 — the single most important test in the suite.

    Asserting only that containers carry --network=none would leave the shim free to
    reach the network with the test still passing.
    """
    run = scan(workspace, runner=CveRunner(), profile=profiles.OFFLINE)

    assert record_connections == [], f"the host process connected: {record_connections}"
    # The assertion is only meaningful if enrichment was actually reachable.
    assert any(f.exploit and f.exploit.cve for f in run.findings), (
        "no CVE in the findings, so enrichment short-circuited and this proved nothing"
    )


def test_the_full_profile_does_connect_so_the_previous_test_can_fail(
    workspace, record_connections
):
    """The falsifiability half, and not optional.

    On 2026-08-31 the first version of this check passed against a repository with no
    findings: enrichment is never called without a CVE, so "no connection" was true
    and worthless. If this test ever stops recording an attempt, the test above has
    silently become decorative — either enrichment stopped fetching, or the poison
    stopped catching it. Both mean the offline result no longer means anything.
    """
    scan(workspace, runner=CveRunner(), profile=profiles.FULL)

    assert record_connections, (
        "the networked Profile made no connection, so the offline assertion "
        "distinguishes nothing"
    )


def test_a_scan_survives_the_network_being_unavailable(workspace, record_connections):
    """ADR-0007 — enrichment degrades to KEV-only rather than failing the scan. A
    reviewer running this on a disconnected machine must get results, not a crash."""
    run = scan(workspace, runner=CveRunner(), profile=profiles.FULL)

    assert run.findings
    assert run.status in {"findings", "clean"}


# --------------------------------------------- half 2: the containers (N2.1)

def test_every_scanner_on_the_offline_profile_is_launched_with_no_network(  # F1.2
    monkeypatch, tmp_path
):
    """Asserted over the whole Profile rather than one Scanner, so adding a Scanner
    that forgets the flag fails the build instead of failing review."""
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

    for adapter in profiles.select(DEFAULT_ADAPTERS, profiles.OFFLINE):
        # A stubbed run fails after launch, because no real report is written. The
        # argv is what this test is about and it has already been captured by then.
        with contextlib.suppress(Exception):
            adapter.run(runner, tmp_path)

    container_cmds = [c for c in launched if isinstance(c, list) and "run" in c]
    assert container_cmds, "no container was launched, so nothing was asserted"
    for cmd in container_cmds:
        assert "--network=none" in cmd, f"launched without --network=none: {cmd}"


def test_the_networked_scanner_is_not_launched_with_no_network(monkeypatch, tmp_path):
    """The falsifiability half of the check above: if --network=none were
    unconditional, the assertion would pass while proving nothing about the Profile."""
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []

    def capture(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", capture)
    from valvur.adapters import OsvAdapter

    OsvAdapter().run(ContainerRunner(runtime="/usr/local/bin/docker"), tmp_path)

    assert launched
    assert "--network=none" not in launched[0]


def test_osv_is_the_only_scanner_the_offline_profile_does_not_run():
    """N2.1 — the offline guarantee is a property of the Profile's membership, so it
    is asserted there and not only at each call site. Since ADR-0018 the
    dependency-reality Check runs on both Profiles; what changes with the network is
    asserted in-process below, because membership alone no longer says it."""
    networked = set(profiles.SCANNERS[profiles.FULL]) - set(profiles.SCANNERS[profiles.OFFLINE])

    assert networked == {"osv-scanner"}
    assert profiles.ALLOWS_NETWORK[profiles.OFFLINE] is False


# ------------------------------ half 3: the Check that runs on both sides (ADR-0018)

def test_the_dependency_check_opens_no_connection_without_a_network_grant(
    workspace, record_connections
):
    """The Check now runs on `offline`, so the container flag is no longer the only
    thing between a package name and a registry: the Check itself must not try. Run
    in-process against the broken fixture, which declares two hallucinated names —
    so the check has every reason to reach out, and the index has to answer instead.
    """
    from valvur.checks.dependency_reality import DependencyRealityCheck

    found = DependencyRealityCheck().run(workspace)

    assert record_connections == [], f"the Check connected: {record_connections}"
    nonexistent = {f["title"].split("'")[1] for f in found
                   if f["rule"] == "valvur.dependency.nonexistent"}
    assert {"reqeusts", "aws-helper-sdk"} <= nonexistent, (
        "no hallucination was reported, so the assertion above proved nothing"
    )


def test_the_dependency_check_does_connect_when_granted_so_the_previous_test_can_fail(
    workspace, record_connections, network_granted
):
    """Falsifiability, again. With the grant the Check asks a registry about the
    names the index says exist (for their age) — and the poison records it."""
    from valvur.checks.dependency_reality import DependencyRealityCheck, RegistryUnreachable

    with contextlib.suppress(RegistryUnreachable):
        DependencyRealityCheck().run(workspace)

    assert record_connections, "granted a network, the Check made no connection"


def test_a_name_the_index_settles_is_never_sent_to_a_registry(
    workspace, network_granted, monkeypatch
):
    """Section 3 is about what leaves the machine. A hallucinated name is the one
    most worth not sending — it is the one a registry operator could register."""
    import valvur.checks.dependency_reality as mod

    asked: list[str] = []
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: asked.append(name) or {"releases": {}})

    mod.DependencyRealityCheck().run(workspace)

    assert "reqeusts" not in asked and "aws-helper-sdk" not in asked
    assert "urllib3" in asked, "an existing name was not asked for its age, so nothing was sent"


def test_without_an_index_the_offline_check_fails_rather_than_reporting_clean(
    workspace, no_name_index
):
    """F3.5 on the new path. A machine that never ran `valvur update` has nothing
    to check existence against and no network to ask — and must say so."""
    from valvur.checks.dependency_reality import DependencyRealityCheck, IndexMissing

    with pytest.raises(IndexMissing, match="valvur update"):
        DependencyRealityCheck().run(workspace)


def test_the_networked_containers_are_told_and_the_offline_ones_are_not(monkeypatch, tmp_path):
    """The Check reads VALVUR_NETWORK; the runner sets it in exactly the case it
    omits --network=none. Both halves, because either alone would pass with the
    variable set unconditionally."""
    from valvur import cache
    from valvur.runner import NETWORK_ENV, ContainerRunner

    launched: list[list[str]] = []

    def capture(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(subprocess, "run", capture)
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    from valvur.adapters import CheckAdapter

    CheckAdapter("dependency-reality", uses_network=True, network=False).run(runner, tmp_path)
    CheckAdapter("dependency-reality", uses_network=True, network=True).run(runner, tmp_path)

    offline, full = launched
    assert "--network=none" in offline and f"{NETWORK_ENV}=1" not in offline
    assert "--network=none" not in full and f"{NETWORK_ENV}=1" in full


def test_the_index_is_mounted_read_only_into_every_container(monkeypatch, tmp_path):
    """The Check only asks the index questions. A writable mount would let a
    compromised Scanner edit the list of what exists."""
    from valvur import cache
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []
    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(cache, "name_index", lambda: tmp_path / "names")

    def capture(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", capture)
    from valvur.adapters import CheckAdapter

    CheckAdapter("licence-file").run(ContainerRunner(runtime="/usr/local/bin/docker"), tmp_path)

    mounts = [launched[0][i + 1] for i, flag in enumerate(launched[0]) if flag == "-v"]
    index_mount = next(m for m in mounts if m.endswith("/cache/names:ro"))
    assert index_mount.startswith(str(tmp_path / "names") + ":")


# ------------------------------------------------------------- the known gap

@pytest.mark.skip(
    reason="Needs Linux. Recorded rather than omitted: see docs/adr/0010 and task 11.1. "
    "The tests above cover the shim (in-process) and the containers (argv). Neither "
    "covers a SUBPROCESS opening a socket — the docker CLI itself, or a future helper "
    "binary. Only an OS-level denial covers that, and `unshare -rn` is Linux-only: "
    "Docker Desktop's seccomp profile blocks it even inside a container, and "
    "containerising the shim breaks the mounts because the daemon resolves paths on "
    "the host. This must run in CI on Linux, where it is a real assertion."
)
def test_the_whole_process_tree_is_denied_the_network_under_unshare():
    """CI-on-Linux: `unshare -rn valvur scan --profile offline` must exit 0.

    It works because the container runtime is reached over a unix socket rather than
    the network, so removing the network namespace entirely leaves the scan intact.
    Verified by hand on Fedora 44, 2026-08-31; unverifiable from macOS.
    """
    raise AssertionError("must be enabled in CI on Linux")


