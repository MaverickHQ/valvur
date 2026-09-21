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
from pathlib import Path

import pytest
from conftest import LegacyDispatch

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


class CveRunner(LegacyDispatch):
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
    import urllib.request

    import conftest

    attempts: list[str] = []
    # The unit suite refuses at the HTTP layer (conftest). This fixture denies one
    # layer down and records, so the real `urlopen` has to be in place for the
    # attempt to reach the poison — otherwise the falsifiability tests below would
    # see no connection for the wrong reason.
    monkeypatch.setattr(urllib.request, "urlopen", conftest.REAL_URLOPEN)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", conftest.REAL_OPENER_OPEN)

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
    ContainerRunner(runtime="/usr/local/bin/docker").run_osv(tmp_path)

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

    runner.run_check("dependency-reality", tmp_path, network=False)
    runner.run_check("dependency-reality", tmp_path, network=True)

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
    ContainerRunner(runtime="/usr/local/bin/docker").run_check("licence-file", tmp_path)

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


# ------------------------------------------ cycle 2: coverage has not narrowed

# Measured on the `full` Profile, 2026-09-05: 75 findings across nine Scanners —
# osv-scanner 38, trivy 37, checkov 13, opengrep 12, ai-artifact 6, gitleaks 2,
# dependency-reality 2, licence-file 1, valvur 1.
#
# Floors, not exact counts. Advisory databases grow, and a test that breaks whenever
# OSV publishes is a test people delete — but a Scanner reaching ZERO is never
# normal, and that is what every silent failure this project has hit looked like.
#
# Opengrep reads 12 here rather than the 14 in the golden fixture: rules ship INSIDE
# the image, so `valvur.pinning.mutable-action-ref` (added 12a.6) reaches a real scan
# only once the image is rebuilt. The golden covers the rule today; this number moves
# when 12a.7 rebuilds.
CANARY_FLOOR = {
    "osv-scanner": 20,
    "trivy": 20,
    "opengrep": 8,
    "checkov": 8,
    "ai-artifact": 5,
    "gitleaks": 2,
    "dependency-reality": 2,
    "licence-file": 1,
}


@pytest.mark.e2e
def test_the_canary_fixture_still_exercises_every_scanner(mountable_tmp):
    """The regression net for silent coverage loss.

    Every defect that mattered this week was a Scanner succeeding perfectly at
    scanning nothing: Trivy's dev-dependency exclusion, "no package sources found"
    treated as a failure, an ecosystem mismatch that double-reported everything. None
    would have been caught by a constraint test. All of them move a number here.
    """
    import collections
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "canary"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    run = scan(ws, runner=ContainerRunner(), profile=profiles.FULL)
    counts = collections.Counter(s for f in run.findings for s in f.sources)

    assert run.complete if hasattr(run, "complete") else not run.failures, (
        f"a Scanner failed, so the counts below are not comparable: {run.failures}"
    )
    for tool, floor in CANARY_FLOOR.items():
        assert counts[tool] >= floor, (
            f"{tool} reported {counts[tool]}, floor is {floor} — coverage has "
            f"narrowed. All counts: {dict(counts)}"
        )


@pytest.mark.e2e
def test_the_canary_covers_dev_only_dependencies(mountable_tmp):
    """Trivy excludes dev dependencies by default. On 2026-08-31 that turned a real
    project's 24 CVEs into 0, and the fixture could not have caught it — every
    package in its lockfile was a production dependency.

    `minimist` is reachable only through devDependencies, so it is reported only when
    --include-dev-deps is passed. Verified against the image both ways: without the
    flag the production tree still reports and minimist alone disappears, which is
    exactly the shape of a silent narrowing.
    """
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "canary"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    run = scan(ws, runner=ContainerRunner(), profile=profiles.OFFLINE)
    packages = {
        f.dependency.package for f in run.findings if f.dependency and f.dependency.package
    }

    assert "minimist" in packages, (
        "the dev-only dependency was not scanned — Trivy's --include-dev-deps has "
        "been lost, and every project whose vulnerabilities live in build tooling "
        "now reports clean"
    )


# --------------------------------------- cycle 3: the offline Profile misses nothing

@pytest.mark.e2e
def test_the_offline_profile_misses_no_vulnerable_package(mountable_tmp):
    """ADR-0016 claims `offline` gives up a second advisory source and the slopsquat
    Check, and nothing else. That claim was false until 2026-08-31, when `offline`
    returned 0 CVEs on a repository where `full` found 24 — same lockfile, same
    minute. An offline Profile that quietly finds less makes "no network required"
    worth nothing, because the honest advice becomes "run the networked one anyway".

    Asserted at package level, not advisory level. `full` legitimately reports MORE
    advisory IDs, because OSV carries records Trivy's database does not — measured
    2026-09-01: PYSEC-2023-175 on pillow. What must never happen is a vulnerable
    package disappearing, which is what the CLU failure looked like: seven packages
    to zero.
    """
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    def packages(profile):
        ws = mountable_tmp / profile
        shutil.copytree(FIXTURES / "broken-repo", ws)
        run = scan(ws, runner=ContainerRunner(), profile=profile)
        return {
            f.dependency.package.lower()
            for f in run.findings
            if f.dependency and f.dependency.package
        }

    offline = packages(profiles.OFFLINE)
    full = packages(profiles.FULL)

    assert offline, "the offline Profile found no vulnerable package at all"
    assert not (full - offline), (
        f"the offline Profile missed packages that full found: {sorted(full - offline)}"
    )


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


# ------------------------------------------------- our own supply chain (12a.6/7)

def test_every_action_in_every_workflow_is_pinned_to_a_sha():
    """A tag is a mutable pointer, and the release workflow holds signing
    credentials — `id-token: write`, `packages: write`, `contents: write`. A moved
    tag there does not just run bad code, it signs it with our identity.

    `valvur.pinning.mutable-action-ref` catches this in a scan, but rules ship inside
    the image, so that only helps after a rebuild. This is the commit-time guard.
    """
    import re

    workflows = sorted(Path(".github/workflows").glob("*.yml"))
    assert workflows, "no workflows found — this test is asserting nothing"

    unpinned = []
    for path in workflows:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = re.search(r"uses:\s*([\w.-]+/[\w./-]+)@(\S+)", line)
            if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(2)):
                unpinned.append(f"{path.name}:{number} {match.group(1)}@{match.group(2)}")

    assert not unpinned, "actions pinned to a mutable tag: " + "; ".join(unpinned)


def test_every_runner_in_every_workflow_is_a_named_image():
    """The runner is the one input under the build that was still a floating
    pointer. Every action is a SHA and every base image a digest, and the release
    ran on whatever `ubuntu-latest` meant that week — which GitHub moves to a new
    LTS every two years over a rollout of a month (24.04 → 26.04 from 2026-10-19,
    actions/runner-images#14748), during which a rerun of one commit lands on
    either image. What it costs here is not breakage — a kernel and a Docker
    changing under N1.1's and N1.4's numbers, which name the runner as the
    machine class they were measured on. So the image is named, and moving it is
    a diff that re-measures them (2026-09-20)."""
    import re

    floating = []
    for path in sorted(Path(".github/workflows").glob("*.yml")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if re.search(r"\b(ubuntu|macos|windows)-latest\b", line):
                floating.append(f"{path.name}:{number} {line.strip()}")

    assert not floating, "runners on a floating label: " + "; ".join(floating)


def test_no_workflow_grants_write_permission_it_does_not_need():
    """Least privilege, asserted rather than reviewed. `ci.yml` runs on every pull
    request including from forks; a write token there is the difference between a
    malicious PR reading the repository and rewriting it."""
    import re

    text = Path(".github/workflows/ci.yml").read_text()
    top_level = re.search(r"^permissions:\n((?:\s+\w[\w-]*:.*\n)+)", text, re.M)

    assert top_level, "ci.yml declares no top-level permissions block"
    assert "write" not in top_level.group(1), (
        f"ci.yml grants write at the top level: {top_level.group(1).strip()}"
    )


def test_every_base_image_is_pinned_by_digest():  # F2.2, and 15.1's stronger form
    """Task 15.1, and the same rule we apply to actions.

    A tag is a mutable pointer. Every `FROM` here was pinned by tag while every
    action was pinned by SHA — the same defect, in the build that signs our releases,
    where a moved tag does not merely run different code but signs it with our
    identity and logs it as authentic.
    """
    import re

    dockerfile = Path("Dockerfile").read_text()
    unpinned = []
    for number, line in enumerate(dockerfile.splitlines(), start=1):
        match = re.match(r"^FROM\s+(\S+)", line)
        if not match:
            continue
        reference = match.group(1)
        # A stage built on an earlier stage carries no registry reference to pin.
        if "/" not in reference and ":" not in reference:
            continue
        if reference.startswith("opengrep-"):
            continue
        if "@sha256:" not in reference:
            unpinned.append(f"Dockerfile:{number} {reference}")

    assert not unpinned, "base images pinned by mutable tag: " + "; ".join(unpinned)


def test_checkov_is_hash_locked_into_its_own_environment():
    """Task 23.4.1. `pip install checkov==3.2.517` pinned one package and resolved
    the other ~95 afresh on every build — the one input of the image we sign with
    our identity that was not pinned by hash. Now every one is, and the lock is
    what the image installs from, into a venv that shares nothing with valvur's
    interpreter."""
    import re

    lock = Path("requirements-checkov.txt").read_text()
    pinned = re.findall(r"^([A-Za-z0-9_.\-]+)==([^ \\]+)", lock, re.M)
    assert len(pinned) >= 80, f"only {len(pinned)} packages in the lock; Checkov needs ~96"
    hashes = lock.count("--hash=sha256:")
    assert hashes >= len(pinned), "a package in the lock carries no hash"
    checkov = dict(pinned).get("checkov")
    assert checkov, "the lock does not pin checkov itself"

    wanted = re.search(r"^checkov==(\S+)", Path("requirements-checkov.in").read_text(), re.M)
    assert wanted and wanted.group(1) == checkov, "the lock and its input disagree"
    import inspect

    from valvur.runner import ContainerRunner

    assert f'version="{checkov}"' in inspect.getsource(ContainerRunner.run_checkov), (
        "the runner reports a Checkov version the lock does not install"
    )

    # An override is a transitive pin of Checkov's we refuse to ship — with the
    # reason beside it, and the lock must carry exactly that version.
    overrides = Path("requirements-checkov.overrides").read_text()
    forced = re.findall(r"^([A-Za-z0-9_.\-]+)==(\S+)", overrides, re.M)
    assert forced, "the overrides file is empty; asteval was overridden for a reason"
    for name, version in forced:
        assert dict(pinned).get(name) == version, (
            f"{name} is overridden to {version} but the lock says {dict(pinned).get(name)}")
        assert re.search(rf"^# {name}:", overrides, re.M), (
            f"the override of {name} carries no reason")

    dockerfile = "\n".join(line for line in Path("Dockerfile").read_text().splitlines()
                           if not line.lstrip().startswith("#"))
    assert "--require-hashes -r /opt/checkov-requirements.txt" in dockerfile
    assert "--no-deps" in dockerfile, "the lock is the resolution; pip must not resolve again"
    assert "python3 -m venv --without-pip /opt/checkov" in dockerfile
    assert not re.search(r"\bpip\b[^\n]*\binstall\b[^\n]*checkov==", dockerfile), (
        "Checkov is still installed by name, outside the lock"
    )


def test_no_run_chain_in_the_dockerfile_can_swallow_its_own_failure():
    """Found by 23.4.1's first build: `a && b && c || true` makes `|| true` cover
    the whole chain, so a failed `pip install` produced an image without Checkov
    and the build reported success. A tolerated step must be scoped in a subshell."""
    import re

    dockerfile = Path("Dockerfile").read_text()
    runs = re.findall(r"^RUN\b(.*?)(?=^\S|\Z)", dockerfile, re.M | re.S)
    assert runs, "no RUN instructions found — this test is asserting nothing"
    for run in runs:
        joined = " ".join(line.strip().rstrip("\\").strip() for line in run.splitlines())
        if "&&" in joined and re.search(r"&&[^()]*\|\|\s*true\s*$", joined):
            raise AssertionError(f"a RUN chain ends in a bare `|| true`: {joined[:120]}…")


def test_the_image_digest_covers_the_checkov_lock():
    """A changed hash is a changed image; the staleness guard (22.C.1) must see it."""
    from valvur import tree_hash

    assert "checkov-lock" in tree_hash.tree_parts(Path("."))
    assert tree_hash.image_parts()["checkov-lock"] == Path(tree_hash.IMAGE_CHECKOV_LOCK)
    assert "requirements-checkov.txt" in Path("Dockerfile").read_text()


def test_every_image_build_goes_through_the_bake_file():
    """Task 23.4.3. Four copies of the build command drifted the way 19.A.3's
    copies did; now `docker-bake.hcl` is the one place, and the release builds each
    architecture natively — no QEMU — merging with `imagetools create`."""
    import re

    bake = Path("docker-bake.hcl").read_text()
    assert re.search(r'^target "dev"', bake, re.M) and re.search(r'^target "release"', bake, re.M)
    assert "push-by-digest=true" in bake
    assert 'VALVUR_VERSION = VALVUR_VERSION' in bake, "the version must reach the Dockerfile"

    for name in ("ci.yml", "corpus.yml", "release.yml"):
        text = Path(".github/workflows", name).read_text()
        assert "docker buildx build" not in text, f"{name} still carries its own build command"
        assert "docker buildx bake" in text, f"{name} does not build through the bake file"
    contributing = Path("CONTRIBUTING.md").read_text()
    assert "docker buildx bake" in contributing and "docker buildx build" not in contributing

    release = Path(".github/workflows/release.yml").read_text()
    assert "ubuntu-24.04-arm" in release, "the arm64 half is not built natively"
    assert "setup-qemu-action" not in release, "QEMU is still installed for the release"
    assert "docker buildx imagetools create" in release
    assert 'needs: [verify, build]' in release


def _release_jobs() -> dict[str, str]:
    """release.yml's jobs, id → text, split at the two-space job headers."""
    import re

    text = Path(".github/workflows/release.yml").read_text()
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z_-]+):\n", body, flags=re.M)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def test_the_release_promotes_only_after_the_artifact_is_validated():
    """26.1.1. Until this, `release` pushed `:VERSION` and `:latest`, signed,
    published to PyPI and created the GitHub release — and THEN the artifact job
    validated the wheel/image pair, with a comment admitting it could not stop a
    release that had left. Now `stage` pushes a candidate tag, signs, attests and
    builds `dist/`; `artifact` validates; and the three things that cannot be
    taken back — the PyPI upload, the `:VERSION` and `:latest` tags, the GitHub
    release — live only in `promote`, which needs `artifact`. The candidate is
    promoted by re-tagging the signed digest, so the signature and the
    attestation hold."""
    import re

    jobs = _release_jobs()
    assert {"verify", "build", "stage", "artifact", "promote"} <= set(jobs), sorted(jobs)

    for irreversible in ("pypa/gh-action-pypi-publish", '"$IMAGE:latest"', "gh release create"):
        owners = [job for job, text in jobs.items() if irreversible in text]
        assert owners == ["promote"], f"{irreversible!r} is in {owners}, not only promote"
    assert re.search(r"needs:\s*\[[^\]]*\bartifact\b", jobs["promote"]), \
        "promote does not wait for artifact"
    assert re.search(r"needs:\s*\[[^\]]*\bstage\b", jobs["artifact"]), \
        "artifact does not follow stage"
    assert "needs: [verify, build]" in jobs["stage"]
    # The manual brake — a required reviewer on the environment — sits before the
    # irreversible step, not before the candidate push.
    assert "environment: release" in jobs["promote"]
    assert "environment: release" not in jobs["stage"]
    # stage never writes the version tag: a red artifact job leaves only a
    # candidate, and the version number is not burned.
    assert '"$IMAGE:$VERSION-candidate"' in jobs["stage"]
    assert re.search(r'-t "\$IMAGE:\$VERSION"', jobs["stage"]) is None
    assert '"$IMAGE@$DIGEST"' in jobs["promote"], "promote does not re-tag the validated digest"


def test_the_published_artifact_runs_on_both_architectures():
    """26.1.2, F10.7. The arm64 image was built natively, listed in the index and
    never executed by the pipeline: `verify`, `published` and `artifact` all ran
    on amd64, and the only machine that had ever run the arm64 image was a
    laptop. Now `artifact` in release.yml and `published` in ci.yml are each a
    two-runner matrix, and `promote` waits for both legs."""
    import re

    jobs = _release_jobs()
    artifact = jobs["artifact"]
    runners = set(re.findall(r"runner:\s*(\S+)", artifact))
    assert runners == {"ubuntu-24.04", "ubuntu-24.04-arm"}, \
        f"artifact does not run on both architectures: {sorted(runners)}"
    assert "runs-on: ${{ matrix.runner }}" in artifact

    ci = Path(".github/workflows/ci.yml").read_text()
    published = ci.split("\n  published:\n", 1)[1].split("\n  selfscan:\n", 1)[0]
    assert re.search(r"runner:\s*ubuntu-24\.04-arm", published), \
        "ci.yml's published job does not run the published image on arm64"
    assert re.search(r"runner:\s*ubuntu-24\.04\n", published)
    # The amd64 leg keeps the name main's branch protection requires.
    assert "name: the published image, on ${{ matrix.arch }}" in published


def test_the_pipeline_verifies_the_provenance_it_publishes_and_has_no_private_repo_branch():
    """26.1.3, F10.3. The repository went public on 2026-09-13; both workflows
    still carried the private-repository branches — an attestation step skipped
    with a warning, a `published` job that skipped with a warning when the
    package could not be pulled anonymously — each a way for a real failure to
    read as an expected skip. And the SLSA provenance the release attested was
    verified by nothing in the pipeline: `artifact` ran `cosign verify` and
    stopped. Now `artifact` verifies the image's attestation and `promote`
    verifies the wheel's on the index it published to."""
    import re

    release = Path(".github/workflows/release.yml").read_text()
    ci = Path(".github/workflows/ci.yml").read_text()
    for dead in ("private repository", "not publicly pullable", "repository.visibility"):
        assert dead not in release, f"release.yml still has the private-repository case: {dead!r}"
        assert dead not in ci, f"ci.yml still has the private-repository case: {dead!r}"

    jobs = _release_jobs()
    assert re.search(r'gh attestation verify "?oci://', jobs["artifact"]), \
        "artifact does not verify the image's build provenance"
    assert "pypi-attestations verify pypi" in jobs["promote"], \
        "promote does not verify the wheel's attestation on the index"
    assert "gh attestation verify" not in jobs["stage"]


def test_the_opengrep_binaries_are_checksum_pinned():
    """Task 15.2. They were fetched over HTTPS and trusted, with no verification of
    any kind, beside a comment noting that Opengrep publishes them signed."""
    import re

    dockerfile = Path("Dockerfile").read_text()

    for arch in ("AMD64", "ARM64"):
        pin = re.search(rf"^ARG OPENGREP_SHA256_{arch}=([0-9a-f]{{64}})$", dockerfile, re.M)
        assert pin, f"no pinned SHA256 for {arch}"

    assert "sha256sum -c -" in dockerfile, (
        "the pinned digests are declared but never checked, which is worse than not "
        "declaring them: it reads as verification and is not"
    )


def test_only_the_needed_opengrep_binary_is_fetched():
    """Task 15.4. Both were ADDed and the unused one deleted — but layers are
    additive, so `rm` reclaims nothing. Measured at 98MB of dead weight in every
    image, for a 50MB tool."""
    dockerfile = Path("Dockerfile").read_text()

    assert "FROM opengrep-${TARGETARCH}" in dockerfile, (
        "the per-architecture stage selection is gone; both binaries will ship again"
    )
    assert "rm -f /tmp/opengrep_*" not in dockerfile


# ------------------------------------------- interruption is its own outcome (16.2)

def test_interrupting_a_scan_stops_the_containers(monkeypatch):
    """F1.11, task 16.2. Measured before this existed: `docker run` does not stop its
    container on SIGINT, nor when the CLI is SIGKILLed — the daemon owns the
    lifecycle. The developer cancelled and the machine kept working, with the scratch
    mount holding raw output and live credentials (F5.7) alive for the duration.
    """
    import valvur.runner as runner_module

    killed: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        killed.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    # runner.py imports subprocess inside functions, so the global is the one that
    # matters — patching a module attribute would create one nothing reads.
    monkeypatch.setattr(subprocess, "run", fake_run)
    with runner_module._live_lock:
        runner_module._live_containers.update({"valvur-aaa", "valvur-bbb"})
    try:
        stopped = runner_module.kill_running("/usr/local/bin/docker")
    finally:
        with runner_module._live_lock:
            runner_module._live_containers.clear()

    assert stopped == 2
    assert all(c[1] == "kill" for c in killed), killed
    assert {name for c in killed for name in c[2:]} == {"valvur-aaa", "valvur-bbb"}


def test_every_container_launch_carries_a_name_to_kill_it_by(monkeypatch, tmp_path):
    """A container with no `--name` and no `--cidfile` cannot be stopped at all,
    which is the state valvur was in. Asserted over every Scanner rather than one,
    so a launch added without a handle fails the build."""
    from valvur import cache, profiles
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

    runs = [c for c in launched if isinstance(c, list) and "run" in c]
    assert runs, "no container was launched, so nothing was asserted"
    for cmd in runs:
        assert "--name" in cmd, f"launched with no handle to kill it by: {cmd[:6]}"


def test_a_launch_stops_being_tracked_once_it_finishes(monkeypatch, tmp_path):
    """Otherwise the registry grows for the life of the process and an interrupt
    tries to kill containers that exited long ago — noisy, and it hides the ones that
    are genuinely still running."""
    import valvur.runner as runner_module
    from valvur import cache
    from valvur.runner import ContainerRunner

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "{}", ""),
    )
    from valvur.adapters import GitleaksAdapter

    GitleaksAdapter().run(ContainerRunner(runtime="/usr/local/bin/docker"), tmp_path)

    with runner_module._live_lock:
        assert runner_module._live_containers == set()


def test_without_an_index_the_runner_refuses_before_launching_and_names_the_fix(
    monkeypatch, tmp_path
):
    """The first-run experience. Measured 2026-09-12 with an empty cache: the Check
    failed inside the container and the reason reached `SUMMARY.md` as a traceback
    truncated at 200 characters, with `valvur update` cut off. Trivy already refuses
    host-side with the fix first; the Check gets the same treatment."""
    from valvur import cache
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []
    monkeypatch.setattr(cache, "name_index_present", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: launched.append(cmd))
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    with pytest.raises(RuntimeError, match="valvur update"):
        runner.run_check("dependency-reality", tmp_path, network=False)

    assert launched == [], "a container was launched with nothing to check against"
    # With a network the registry can answer instead, so no refusal.
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "[]", ""))
    runner.run_check("dependency-reality", tmp_path, network=True)


def test_the_check_entry_point_turns_its_own_refusal_into_one_line(capsys, tmp_path):
    """In-container half of the same fix: a refusal is a sentence on stderr and a
    non-zero exit, not a traceback."""
    from valvur.checks.__main__ import main

    (tmp_path / "requirements.txt").write_text("nope-x\n")
    empty = tmp_path / "no-index"
    empty.mkdir()
    import os
    os.environ["VALVUR_NAME_INDEX"] = str(empty)
    try:
        code = main(["dependency-reality", str(tmp_path)])
    finally:
        del os.environ["VALVUR_NAME_INDEX"]

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("Run `valvur update`")
    assert "Traceback" not in captured.err
    assert captured.out == ""
