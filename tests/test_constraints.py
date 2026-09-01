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
import json
import socket as socket_mod
import subprocess

import pytest

from valvur import profiles
from valvur.api import scan
from valvur.runner import ScannerOutput

# Trivy output carrying a real CVE. The CVE is the point: enrichment short-circuits
# on a finding set with none, so a stub without one tests nothing.
TRIVY_ONE_CVE = json.dumps({"Results": [{
    "Target": "requirements.txt", "Type": "pip", "Class": "lang-pkgs",
    "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2023-4863", "PkgName": "pillow",
        "InstalledVersion": "10.0.0", "FixedVersion": "10.0.1",
        "Severity": "HIGH", "Title": "heap buffer overflow in libwebp",
    }],
}]})


class CveRunner:
    """A runner whose findings reach the enrichment path."""

    def _out(self, tool, payload=""):
        return ScannerOutput(tool=tool, version="0", stdout=payload, stderr="", exit_code=0)

    def run_trivy(self, workspace): return self._out("trivy", TRIVY_ONE_CVE)
    def run_gitleaks(self, workspace): return self._out("gitleaks", "[]")
    def run_osv(self, workspace): return self._out("osv-scanner", '{"results": []}')
    def run_checkov(self, workspace):
        return self._out("checkov", '{"results": {"failed_checks": []}}')
    def run_syft(self, workspace): return self._out("syft", "")
    def run_opengrep(self, workspace): return self._out("opengrep", '{"results": []}')

    def run_check(self, name, workspace, *, network=False):
        return self._out(name, "[]")


@pytest.fixture
def record_connections(monkeypatch):
    """Poison every outbound connect path in this process and record attempts.

    Patches the connect methods rather than the socket class: creating a socket is
    harmless, and `ssl` subclasses socket at import time, so replacing the class
    breaks the interpreter instead of the network. Connecting is the exfiltration.
    """
    attempts: list[str] = []

    def deny(name):
        def blocked(*args, **kwargs):
            target = args[1] if len(args) > 1 else kwargs.get("address", "?")
            attempts.append(f"{name} -> {target}")
            raise OSError(f"blocked: {name} -> {target}")
        return blocked

    monkeypatch.setattr(socket_mod.socket, "connect", deny("connect"), raising=False)
    monkeypatch.setattr(socket_mod.socket, "connect_ex", deny("connect_ex"), raising=False)
    monkeypatch.setattr(socket_mod, "create_connection", deny("create_connection"))
    monkeypatch.setattr(socket_mod, "getaddrinfo", deny("getaddrinfo"))
    return attempts


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

def test_every_scanner_on_the_offline_profile_is_launched_with_no_network(
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
    ContainerRunner(runtime="/usr/local/bin/docker").run_osv(tmp_path)

    assert launched
    assert "--network=none" not in launched[0]


def test_osv_and_dependency_reality_are_the_only_networked_scanners():
    """N2.1 — the offline guarantee is a property of the Profile's membership, so it
    is asserted there and not only at each call site."""
    networked = set(profiles.SCANNERS[profiles.FULL]) - set(profiles.SCANNERS[profiles.OFFLINE])

    assert networked == {"osv-scanner", "dependency-reality"}
    assert profiles.ALLOWS_NETWORK[profiles.OFFLINE] is False


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
