"""Sub-phases 8.1 and 8.2 — portability and isolation across container runtimes.

The file-ownership tests are the reason ADR-0001 exists: container-written files land
with different ownership on every runtime, which is why the shim writes the Results
Folder itself rather than the container doing it.
"""

import functools
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from valvur import scan
from valvur.adapters import GitleaksAdapter
from valvur.runner import _EXTRA_LOCATIONS, ContainerRunner, detect_runtime


def _available(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for location in _EXTRA_LOCATIONS:
        candidate = Path(location).expanduser() / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


@functools.cache
def _has_image(name: str) -> bool:
    """Whether this runtime can actually obtain the image.

    Parity cannot be tested against a runtime that has no image to run, and failing
    instead of skipping teaches everyone to ignore a permanently red suite. Skipping
    keeps the signal: a real parity regression still turns these red.
    """
    binary = _available(name)
    if binary is None:
        return False
    from valvur.runner import IMAGE

    return subprocess.run(
        [binary, "image", "exists", IMAGE] if "podman" in name
        else [binary, "image", "inspect", IMAGE],
        capture_output=True, check=False,
    ).returncode == 0


RUNTIMES = [
    pytest.param(name, marks=[
        pytest.mark.skipif(_available(name) is None, reason=f"{name} not installed"),
        pytest.mark.skipif(
            _available(name) is not None and not _has_image(name),
            reason=f"{name} has no local valvur image (ghcr.io package is not public)",
        ),
    ])
    for name in ("docker", "podman")
]


# ------------------------------------------------------------- 8.1 ownership

@pytest.mark.e2e
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_results_are_owned_by_the_invoking_user(workspace, runtime):
    """F1.4 — the reason ADR-0001 exists.

    Under rootful Docker a container-written file lands owned by root; under rootless
    Podman it lands owned by a subuid the user cannot even read. The developer would
    need sudo to delete their own scan output. The shim writes these files instead,
    so ownership is correct by construction on every runtime.
    """
    run = scan(workspace, runner=ContainerRunner(runtime=_available(runtime)),
               adapters=[GitleaksAdapter()], profile="quick")
    assert run.failures == [], f"{runtime} could not run the scanner"

    written = [p for p in (workspace / ".security-scan").rglob("*") if p.is_file()]
    assert written

    mine = os.getuid()
    wrong = [p.name for p in written if p.stat().st_uid != mine]
    assert wrong == [], f"{runtime}: files not owned by the invoking user: {wrong}"


@pytest.mark.e2e
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_a_scan_finds_the_same_things_on_every_runtime(workspace, runtime):  # F10.1
    """Portability is not just about permissions: the answer must match too."""
    run = scan(workspace, runner=ContainerRunner(runtime=_available(runtime)),
               adapters=[GitleaksAdapter()], profile="quick")

    # Assert completeness first. Without this the test conflates "found nothing"
    # with "could not run", and CI proved the difference matters: podman keeps its
    # own image store, so it could not see a docker-built image, gitleaks was
    # recorded as failed, and the scan completed cleanly with zero findings.
    assert run.failures == [], (
        f"{runtime} could not complete the scan: "
        f"{[f'{f.tool}: {f.reason}' for f in run.failures]}"
    )
    assert "aws-access-token" in [f.rule for f in run.findings]


# ------------------------------------------------------------- 8.2 isolation

@pytest.mark.e2e
def test_the_container_cannot_write_to_the_workspace(workspace):
    """F1.1 — the mount IS the jail. Not a check we perform, a thing that cannot happen."""
    import subprocess

    runner = ContainerRunner()
    result = subprocess.run(
        [runner.runtime, "run", "--rm", "-v", f"{workspace}:/workspace:ro",
         "--entrypoint", "sh", runner.image, "-c", "touch /workspace/EVIDENCE"],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode != 0
    assert not (workspace / "EVIDENCE").exists()


@pytest.mark.e2e
def test_a_workspace_path_containing_spaces_scans_correctly(mountable_tmp):
    from conftest import FIXTURES

    awkward = mountable_tmp / "my project (v2)" / "the repo"
    shutil.copytree(FIXTURES / "broken-repo", awkward)

    run = scan(awkward, runner=ContainerRunner(), adapters=[GitleaksAdapter()],
               profile="quick")

    assert run.findings


@pytest.mark.e2e
def test_a_symlink_pointing_outside_the_workspace_reaches_nothing(mountable_tmp):
    """The interesting case is not that symlinks work — it is that escape is
    structurally impossible. The link's target is simply not in the mount."""
    import subprocess

    from conftest import FIXTURES

    workspace = mountable_tmp / "ws"
    shutil.copytree(FIXTURES / "broken-repo", workspace)
    secret = mountable_tmp / "outside-secret.txt"
    secret.write_text("AKIAV7Q2XR4TVBN6WLKJ\n")
    (workspace / "escape.txt").symlink_to(secret)

    runner = ContainerRunner()
    result = subprocess.run(
        [runner.runtime, "run", "--rm", "-v", f"{workspace}:/workspace:ro",
         "--entrypoint", "sh", runner.image, "-c", "cat /workspace/escape.txt"],
        capture_output=True, text=True, check=False,
    )

    assert "AKIAV7Q2XR4TVBN6WLKJ" not in result.stdout


# --------------------------------------------------- 8.2.9 runtime detection

def test_runtime_detection_finds_installs_that_are_not_on_path(monkeypatch):
    """Podman Desktop puts a working runtime at /opt/podman/bin and leaves PATH
    alone. Telling that user to install what they already have is the worst kind of
    first-run failure.

    Wherever the runtime really is, that directory stands in for /opt/podman/bin:
    this used to look only in the macOS locations, so on a Linux runner with
    docker in /usr/bin it skipped — and the CI guard read the skip as "parity
    unverified" and went red on the first run that ever reached it (22.B.1)."""
    real = _available("podman") or _available("docker")
    if real is None:
        pytest.skip("no runtime installed anywhere")

    monkeypatch.delenv("VALVUR_RUNTIME", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("valvur.runner._EXTRA_LOCATIONS", (str(Path(real).parent),))

    assert Path(detect_runtime()).is_file()


def test_no_runtime_produces_actionable_remediation(monkeypatch):
    """F1.5 — an error message is a usability surface."""
    from valvur.runner import NoContainerRuntime

    monkeypatch.delenv("VALVUR_RUNTIME", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("valvur.runner._EXTRA_LOCATIONS", ())

    with pytest.raises(NoContainerRuntime) as excinfo:
        detect_runtime()

    message = str(excinfo.value)
    assert "brew install" in message
    assert "valvur scan" in message, "the message must name the exact next command"


# ------------------------------------------------- 8.3 version compatibility

def test_a_mismatched_shim_and_image_are_refused(monkeypatch):
    """F1.9 — ADR-0001 accepted two artifacts on condition this check existed.

    Without it, a stale image silently produces output a newer shim cannot parse, and
    the failure surfaces as a confusing parse error rather than the version mismatch
    it actually is.
    """
    from valvur import compat

    monkeypatch.setattr(compat, "shim_version", lambda: "0.3.0")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.1.0")

    with pytest.raises(compat.IncompatibleImage) as excinfo:
        compat.check("docker", "valvur:dev")

    message = str(excinfo.value)
    assert "0.3.0" in message and "0.1.0" in message, "both versions must be named"
    assert "pip install -U" in message, "the message must name the exact next command"


def test_a_patch_difference_is_compatible(monkeypatch):
    from valvur import compat

    monkeypatch.setattr(compat, "shim_version", lambda: "0.1.4")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.1.9")

    compat.check("docker", "valvur:dev")


def test_a_minor_difference_breaks_compatibility_while_below_1_0(monkeypatch):
    """Semver lets 0.x minor bumps break things, and we are in 0.x."""
    from valvur import compat

    monkeypatch.setattr(compat, "shim_version", lambda: "0.1.0")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.2.0")

    with pytest.raises(compat.IncompatibleImage):
        compat.check("docker", "valvur:dev")


def test_a_minor_difference_is_compatible_once_past_1_0(monkeypatch):
    from valvur import compat

    monkeypatch.setattr(compat, "shim_version", lambda: "1.1.0")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "1.4.2")

    compat.check("docker", "valvur:dev")


def test_an_image_without_the_label_is_not_refused(monkeypatch):
    """Predates the check. Refusing would break every image built before it existed."""
    from valvur import compat

    monkeypatch.setattr(compat, "image_version", lambda r, i: None)

    compat.check("docker", "valvur:dev")


@pytest.mark.e2e
def test_the_real_image_declares_a_version_the_shim_accepts():
    from valvur import compat

    runner = ContainerRunner()
    assert compat.image_version(runner.runtime, runner.image) is not None
    runner.verify_compatible()


# ------------------------------------------------ 8.4 air-gapped operation

def test_a_mirrored_database_registry_is_passed_to_trivy(monkeypatch):
    """F10.5 — the hardest enterprise requirement. An air-gapped organisation
    mirrors the DB internally rather than granting egress to ghcr.io."""
    from valvur.runner import _db_repository_flags

    monkeypatch.setenv("VALVUR_DB_REPOSITORY", "registry.internal/mirror/trivy-db")

    assert _db_repository_flags() == [
        "--db-repository", "registry.internal/mirror/trivy-db",
    ]


def test_no_mirror_configured_adds_no_flag(monkeypatch):
    """The default path must stay exactly as it was."""
    from valvur.runner import _db_repository_flags

    monkeypatch.delenv("VALVUR_DB_REPOSITORY", raising=False)
    monkeypatch.delenv("VALVUR_DB_INSECURE", raising=False)

    assert _db_repository_flags() == []


def test_a_plain_http_mirror_needs_the_insecure_flag_and_gets_it_only_when_asked(monkeypatch):
    """Measured 2026-09-12 (22.B.3), the first time F10.5 was exercised: against an
    internal `registry:2`, the documented setting alone fails with "server gave HTTP
    response to HTTPS client". Trivy's `--insecure` is the switch, and it is never
    applied to the default ghcr.io path, where TLS is the point."""
    from valvur.runner import _db_repository_flags

    monkeypatch.setenv("VALVUR_DB_REPOSITORY", "mirror.internal:5000/trivy-db")
    monkeypatch.setenv("VALVUR_DB_INSECURE", "1")
    assert _db_repository_flags() == [
        "--db-repository", "mirror.internal:5000/trivy-db", "--insecure",
    ]

    monkeypatch.delenv("VALVUR_DB_REPOSITORY")
    assert "--insecure" not in _db_repository_flags()


def test_a_container_network_applies_only_to_networked_containers(monkeypatch, tmp_path):
    """An air-gapped site's mirror may live on a user-defined network — or an
    `--internal` one, which is how 22.B.3 proved the gap structurally. The update
    container joins it. A scan container never does: `--network=none` is not a
    default this setting can override."""
    import subprocess

    from valvur import cache
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []

    def capture(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(subprocess, "run", capture)
    monkeypatch.setenv("VALVUR_CONTAINER_NETWORK", "airgap")
    runner = ContainerRunner(runtime="/usr/local/bin/docker")

    runner.update_db()
    runner.run_gitleaks(tmp_path)

    update, scan = launched
    assert "--network=airgap" in update and "--network=none" not in update
    assert "--network=none" in scan and "--network=airgap" not in scan


def test_kev_is_fetched_from_the_mirror_when_one_is_named(monkeypatch, tmp_path, capsys):
    """The third thing `valvur update` fetches, and the third thing an air-gapped site
    has to mirror. One JSON file; any static server; plain http accepted because the
    URL is the operator's, never a Workspace's."""
    import io
    import json
    import urllib.request

    from valvur import cache, cli

    seen: list[str] = []
    catalog = json.dumps({"catalogVersion": "2026.09.11", "vulnerabilities": [
        {"cveID": "CVE-2026-1", "knownRansomwareCampaignUse": "Known", "dateAdded": "2026-09-01"},
    ]}).encode()

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.close()

    def fake(request, timeout=None):
        seen.append(request if isinstance(request, str) else request.full_url)
        return Response(catalog)

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setattr(cache, "root", lambda: tmp_path)
    monkeypatch.setenv(cli.KEV_URL_ENV, "http://mirror.internal:8080/kev.json")

    cli._refresh_kev()

    assert seen == ["http://mirror.internal:8080/kev.json"]
    assert json.loads((tmp_path / "kev.json").read_text())["count"] == 1
    assert "KEV refreshed: 1 entries" in capsys.readouterr().out


def test_a_kev_mirror_that_is_not_http_is_refused_softly(monkeypatch, tmp_path, capsys):
    from valvur import cache, cli

    monkeypatch.setattr(cache, "root", lambda: tmp_path)
    monkeypatch.setenv(cli.KEV_URL_ENV, "file:///etc/passwd")

    cli._refresh_kev()

    assert "skipped" in capsys.readouterr().out
    assert not (tmp_path / "kev.json").exists()


def test_an_unreadable_workspace_is_refused_not_reported_clean(workspace, monkeypatch):
    """The failure mode CI exposed, and the one no Scanner can detect.

    From inside the container an unreadable directory and an empty one are identical.
    Every Scanner reads nothing, exits 0, and valvur would report a clean scan of a
    vulnerable repository — the worst possible failure for this product.
    """
    import subprocess

    from valvur.runner import ContainerRunner, WorkspaceUnreadable

    runner = ContainerRunner()

    class Empty:
        # The container ran successfully and saw nothing — which is the case this
        # test exists for, and is distinct from the container failing to start.
        returncode = 0
        stdout = "0"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Empty())

    with pytest.raises(WorkspaceUnreadable) as excinfo:
        runner.verify_workspace_readable(workspace)

    message = str(excinfo.value)
    assert "cannot read the workspace" in message
    assert "indistinguishable from a clean one" in message


@pytest.mark.e2e
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_the_container_can_read_the_workspace_on_every_runtime(workspace, runtime):
    ContainerRunner(runtime=_available(runtime)).verify_workspace_readable(workspace)


# ------------------------------------------- dev dependencies on the quick profile

@pytest.mark.e2e
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_the_offline_profile_finds_dev_dependency_vulnerabilities(mountable_tmp, runtime):
    """The quick profile's whole claim is useful results with no network.

    Measured on a real Electron app: Trivy's default excludes dev dependencies, so
    quick reported a repository with 24 CVEs as clean while standard found all 24
    over the network. A profile that returns false negatives makes "no network
    required" worth nothing — this test is the reason that claim is true.
    """
    from conftest import FIXTURES

    from valvur.adapters import TrivyAdapter

    ws = mountable_tmp / "pnpm"
    shutil.copytree(FIXTURES / "pnpm-dev-repo", ws)

    run = scan(ws, runner=ContainerRunner(runtime=_available(runtime)),
               adapters=[TrivyAdapter()], profile="quick")

    packages = {f.dependency.package for f in run.findings if f.dependency}
    assert "lodash" in packages, "dev-only transitive dependency was not scanned"
    assert all(f.dependency.scope == "development"
               for f in run.findings if f.dependency and f.dependency.package == "lodash")
