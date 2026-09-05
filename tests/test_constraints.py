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


@pytest.mark.skip(
    reason="Needs Linux. N1.4 (2 GB) was measured by hand at 344 MiB peak container "
    "usage on 2026-09-01, but asserting it continuously needs cgroup accounting the "
    "container runtime exposes properly only on Linux; sampling `docker stats` from "
    "a test races the scan and reports whatever it happened to catch. Enable in CI "
    "with 11.7, where the runtime is native."
)
def test_a_scan_stays_within_its_memory_budget():
    """N1.4 — 2 GB. Measured 344 MiB; unasserted from macOS."""
    raise AssertionError("must be enabled in CI on Linux")


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


def test_every_base_image_is_pinned_by_digest():
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
