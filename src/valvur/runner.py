"""The container-runtime boundary. Everything beyond this line is someone else's process."""

from __future__ import annotations

import functools as _functools
import platform
import sys
import uuid as _uuid
from contextlib import suppress as _suppress
from pathlib import Path

from . import cache, compat, egress, locking, osv_offline, owner
from . import settings as _settings
from .adapters.trivy import database_fetch
from .invocation import NOTHING_TO_SCAN, Invocation, ScannerOutput, nothing_to_scan
from .selinux import RELABEL_ENV, selinux_enforcing
from .settings import ENVIRONMENT as _ENVIRONMENT
from .version import __version__, default_image

__all__ = ["NOTHING_TO_SCAN", "RELABEL_ENV", "Invocation", "ScannerOutput", "selinux_enforcing"]
# The egress settings lived here until 26.2.2; readers moved to `egress`.
DB_REPOSITORY_ENV = egress.DB_REPOSITORY_ENV
DB_INSECURE_ENV = egress.DB_INSECURE_ENV
DEFAULT_DB_REPOSITORY = egress.DEFAULT_DB_REPOSITORY
NETWORK_ENV = egress.NETWORK_ENV
CONTAINER_NETWORK_ENV = egress.CONTAINER_NETWORK_ENV
db_repository = egress.db_repository

# The published image. A fresh install has no local build, so this must be pullable
# by anyone — pointing at a local tag would make the first run fail for every user
# who is not us.
IMAGE = _settings.get("image") or default_image()
#: `VALVUR_DEBUG=1`: every container command echoed to stderr as it runs (28.3.6).
DEBUG_ENV = _ENVIRONMENT["debug"]


_VERSION = __version__

_RUNTIMES = ("docker", "podman", "nerdctl")


class NoContainerRuntime(RuntimeError):
    """Raised with remediation text — an error message is a usability surface (F1.5)."""

    #: A precondition `doctor` checks (R1.5).
    doctor_may_help = True


class ImagePullFailed(RuntimeError):
    """The image is not local and could not be fetched. The runtime's own words are
    in the message: a private package, no network, a typo in `VALVUR_IMAGE`."""

    #: A precondition `doctor` checks (R1.5).
    doctor_may_help = True


# Installers that do not touch PATH. Podman Desktop on macOS is the common case:
# it puts a perfectly good runtime at /opt/podman/bin and leaves PATH alone, so
# `shutil.which` finds nothing and we would tell a user to install what they already
# have — the worst kind of first-run failure.
_EXTRA_LOCATIONS = (
    "/opt/podman/bin",                                   # Podman Desktop, macOS
    "/opt/homebrew/bin",                                 # Homebrew, Apple silicon
    "/usr/local/bin",                                    # Homebrew Intel, Docker
    "/Applications/Docker.app/Contents/Resources/bin",   # Docker Desktop, macOS
    "~/.local/bin",
)


def detect_runtime() -> str:
    import os
    import shutil

    override = _settings.get("runtime")
    if override:
        return override

    for candidate in _RUNTIMES:
        found = shutil.which(candidate)
        if found:
            return found
        for location in _EXTRA_LOCATIONS:
            path = Path(location).expanduser() / candidate
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
    raise NoContainerRuntime(
        "No container runtime found. valvur needs Docker or Podman.\n"
        "  macOS:  brew install --cask docker   (or: brew install podman && podman machine start)\n"
        "  Linux:  install docker or podman from your distribution\n"
        "Then re-run: valvur scan"
    )


def _user_flags(runtime: str) -> list[str]:
    """Map the invoking user into the container — differently per runtime.

    Docker (rootful) needs an explicit --user, or files land owned by root.

    Rootless Podman needs --userns=keep-id INSTEAD. Passing --user there makes the
    bind-mounted workspace unreadable inside the container, and the failure is
    silent: the scanner reads an empty tree, exits 0, and reports a clean scan of a
    vulnerable repository. CI found this; it is exactly the class of runtime
    difference ADR-0001 exists for.
    """
    import os

    if os.name != "posix":
        return []
    uid, gid = os.getuid(), os.getgid()
    if "podman" in runtime:
        # Rootless Podman needs BOTH. keep-id maps the host user into the namespace;
        # without --user the image's own USER (10001) still applies and maps to a
        # subuid that cannot write the scratch mount — so the scanner runs, writes
        # nothing, and exits 0.
        return ["--userns=keep-id", "--user", f"{uid}:{gid}"]
    return ["--user", f"{uid}:{gid}"]


def unsupported_platform_warning() -> str:
    """What to say on a platform valvur has never been tested on.

    Decided in task 13.3. Native Windows is **not claimed** — the user-mapping flags
    are skipped there (`os.name != "posix"`), bind-mount path translation is
    Docker Desktop's rather than ours, and no test has ever run on it. It may work.
    That is not the same as supported, and the difference is the whole point of this
    project.

    A hard refusal would be wrong, because it might genuinely work and we do not
    know. Silence would be worse, because silence reads as "supported". So: proceed,
    and say plainly which it is. Under WSL2 valvur is running on Linux and this does
    not fire.
    """
    import platform

    if platform.system() != "Windows":
        return ""
    return (
        "valvur has never been tested on native Windows and does not claim to "
        "support it. It may work; nobody has checked, and results are unverified.\n"
        "  Recommended: run valvur inside WSL2, where it is running on Linux and is "
        "tested on every commit.\n"
        "  If you do run it here and it works — or does not — please tell us: "
        "https://github.com/MaverickHQ/valvur/issues"
    )


# Containers this process started, so an interrupt can stop them (task 16.2).
#
# Measured 2026-09-05: `docker run` does NOT stop its container on SIGINT, nor when
# the CLI is SIGKILLed — the daemon owns the lifecycle, so killing the client changes
# nothing. Letting signals propagate is therefore not an available design. `docker
# kill` by name takes 0.24s, but valvur passed no `--name` and no `--cidfile`, so
# there was no handle at all: a cancelled scan kept working, and the scratch mount
# holding raw output with live credentials (F5.7) stayed alive with it.
#: The ceiling on every container this process starts (task 28.0.3, F3). Sized
#: from N1.4's measurement — 528 MiB peak on CI for the whole `full` fleet — with
#: swap equal to memory, which is no swap at all: a container past the ceiling is
#: killed (exit 137) rather than swapping the host while the budget counts down.
#: 512 PIDs is ten times the widest fleet member (Checkov's worker pool).
#: no-new-privileges closes setuid inside a `--cap-drop=ALL` box. One tuple, so 2g
#: is 2g everywhere and a change is one diff — the way `egress.py` holds the
#: network flag. Until 28.0.3 the fleet had a read-only root, no capabilities and
#: no network, and could still take every byte of memory the host had.
RESOURCE_LIMITS: tuple[str, ...] = (
    "--memory=2g", "--memory-swap=2g", "--pids-limit=512", "--security-opt=no-new-privileges",
)


#: The two of those a rootless Podman on cgroup v1 refuses outright ("cgroup v1
#: rootless: memory limit not supported") — refusing to start the container at
#: all, which would turn a safety flag into a scan that cannot run.
_MEMORY_LIMITS = tuple(flag for flag in RESOURCE_LIMITS if flag.startswith("--memory"))


def _cgroup_v2() -> bool:
    """Whether this Linux host runs cgroup v2, the one rootless Podman can apply a
    memory limit under. macOS and Windows run a VM that is v2; only a Linux host
    can answer no."""
    if platform.system() != "Linux":
        return True
    return Path("/sys/fs/cgroup/cgroup.controllers").exists()


@_functools.lru_cache(maxsize=8)
def runtime_resources(runtime: str) -> tuple[int | None, int | None]:
    """The runtime's memory in bytes and its CPUs, from `info` — Docker's
    `MemTotal`/`NCPU`, Podman's `Host.MemTotal`/`Host.CPUs` — or (None, None)
    when it cannot say. Cached per runtime path: `docker info` costs 0.9 s on
    Docker Desktop, and the answer does not change under a process."""
    import subprocess

    template = ("{{.Host.MemTotal}} {{.Host.CPUs}}" if "podman" in runtime
                else "{{.MemTotal}} {{.NCPU}}")
    try:
        proc = subprocess.run([runtime, "info", "--format", template],  # noqa: S603
                              capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, None
    parts = proc.stdout.split()
    if proc.returncode != 0 or len(parts) < 2 or not all(p.isdigit() for p in parts[:2]):
        return None, None
    return int(parts[0]), int(parts[1])


def memory_ceiling_note(runtime: str) -> str | None:
    """The one case the memory half of the ceiling is dropped, said in one line
    for `doctor` and the run report — or None when the whole ceiling applies."""
    if "podman" in runtime and not _cgroup_v2():
        return ("memory ceiling not applied: rootless Podman on cgroup v1 refuses --memory; "
                "the PID limit and no-new-privileges still hold")
    return None


def _resource_flags(runtime: str) -> list[str]:
    if memory_ceiling_note(runtime) is not None:
        return [flag for flag in RESOURCE_LIMITS if flag not in _MEMORY_LIMITS]
    return list(RESOURCE_LIMITS)


#: The Scan Container's memory ceiling (ADR-0022 point 6, D4): every Scanner now
#: shares one container, so its ceiling is the whole scan's.
SCAN_CEILING_BYTES = 3 * 2**30


def scan_resource_flags(runtime: str) -> list[str]:
    """The ceiling for a Scan Container: 3 GiB, or three quarters of the
    runtime's memory when that is less, so a scan never takes a small Docker
    Desktop VM whole. The same flags as `RESOURCE_LIMITS`, resized, and dropped
    where rootless Podman on cgroup v1 refuses them."""
    flags = _resource_flags(runtime)
    if memory_ceiling_note(runtime) is not None:
        return flags
    memory, _ = runtime_resources(runtime)
    ceiling = SCAN_CEILING_BYTES if memory is None else min(SCAN_CEILING_BYTES, memory * 3 // 4)
    size = f"{ceiling // 2**20}m"
    return [f"{flag.partition('=')[0]}={size}" if flag in _MEMORY_LIMITS else flag
            for flag in flags]


def launch_flags(runtime: str, *, generation: str | None, name: str, scratch: str | Path,
                 network: bool, interactive: bool = False, landing: tuple[str, ...] = (),
                 osv: bool = False, resources: list[str] | None = None) -> list[str]:
    """`<runtime> run …` up to the image, for every container valvur starts (D52e):
    the Scan Container and the database fetch alike, so what they share is written
    once. F10.2, with the Dockerfile's USER 10001: non-root, a read-only root
    filesystem, every capability dropped. The source is never mounted (ADR-0022);
    every mount is valvur's own, labelled on an enforcing SELinux host (F1.6), where
    an unlabelled mount is denied. Whether there is an interface at all is egress's
    decision, which the kernel enforces (N2.1)."""
    db, names = cache.trivy_db(), cache.name_index()
    for directory in (db, names):
        directory.mkdir(parents=True, exist_ok=True)
    z = ":z" if selinux_enforcing() else ""
    flags = [
        runtime, "run", *(["-i"] if interactive else []), "--rm", *owner.labels(generation),
        "--name", name,
        *_user_flags(runtime),
        "--read-only", "--cap-drop=ALL",
        # The memory, PID and privilege ceiling (28.0.3).
        *(resources if resources is not None else _resource_flags(runtime)),
        # Scratch space the read-only root still needs: in memory, gone with the
        # container, nosuid, and noexec for every tool (D54a): Opengrep's core is
        # unpacked in the image, so nothing needs to run from here.
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",  # noqa: S108
        *landing,
        "-v", f"{scratch}:/results{z}",
        "-v", f"{db}:/cache/trivy{z}",                  # ADR-0012: the DB outside the image
        # ADR-0018: the package-name index, read-only, since the Check only asks it.
        "-v", f"{names}:/cache/names:ro{z and ',z'}",
    ]
    if osv:
        offline = osv_offline.directory()
        offline.mkdir(parents=True, exist_ok=True)
        # OSV's offline database (R4.6), read-only like the index.
        flags += ["-v", f"{offline}:{osv_offline.MOUNT}:ro{z and ',z'}"]
    return flags + egress.Egress(network=network).container_flags()


def _container_name() -> str:
    return f"valvur-{_uuid.uuid4().hex[:16]}"


#: The exit code a Scanner's output carries when its timeout fired and the
#: runner stopped it (29.0.2) — `timeout(1)`'s convention.
TIMED_OUT = 124


class _ScannerTimedOut(Exception):
    """Raised inside `_launch` when the per-Scanner timeout fires, after the
    container has been stopped: what `run` turns into an output that says so."""

    def __init__(self, seconds: float, stderr: str):
        super().__init__(f"timed out after {seconds:g}s and was stopped")
        self.seconds = seconds
        self.stderr = stderr


def _wait_gone(runtime: str | None, name: str, timeout: float = 15.0) -> bool:
    """Poll the runtime until it no longer lists the container, or `timeout`
    passes. `docker kill` returns when the signal is sent; `--rm` removes the
    container a moment later, and the point of stopping it is that nothing is
    left behind."""
    import subprocess
    import time

    binary = runtime or detect_runtime()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _suppress(Exception):
            listed = subprocess.run(  # noqa: S603
                [binary, "ps", "-a", "-q", "--filter", f"name=^{name}$"],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout.strip()
            if not listed:
                return True
        time.sleep(0.25)
    return False


def _text(raw) -> str:
    """`TimeoutExpired.stderr` is bytes even in text mode (CPython 3.12)."""
    if raw is None:
        return ""
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)


def database_size_mb() -> int | None:
    """What fetching the vulnerability database will cost, from the registry Trivy
    will pull it from, or None if it cannot say (24.1)."""
    # deferred: startup; the registry client and the TLS stack load only for a pull.
    from . import oci

    size = oci.image_size(egress.db_repository() or egress.DEFAULT_DB_REPOSITORY,
                          insecure=_settings.get("db_insecure") == "1")
    return None if size is None else max(1, round(size / 1_000_000))


class ContainerRunner:
    """What a scan needs from the image before its Scan Container starts, and the
    database fetch (ADR-0022): the image present, pulled, checked against this
    shim; the database fetched by Trivy inside it. Every Scanner runs in the Scan
    Container (`engine_host.ContainerRuntime`), which never mounts the source."""

    def __init__(self, image: str = IMAGE, runtime: str | None = None):
        self.image = image
        self._runtime = runtime
        #: The Scan Run's generation, carried by every container this runner
        #: starts (R3.6); none for a fetch outside a scan.
        self.generation: str | None = None

    def verify_compatible(self) -> None:
        compat.check(self.runtime, self.image)

    def build_provenance(self) -> tuple[str | None, str | None]:
        """(the tree this shim was built beside, the tree the image was built
        from) — either None when unrecorded (23.4.4). Compared by the scan and
        reported, never refused."""
        return compat.shim_inputs(), compat.image_inputs(self.runtime, self.image)

    # ------------------------------------------------------- the image itself

    def image_present(self) -> bool:
        """Whether the runtime already holds the image — asked before the first
        launch, because `run` on a missing image pulls it silently, and a first
        scan that sits for a minute with no output looks hung (10.2 claim 4)."""
        proc = self._launch(
            [self.runtime, "image", "inspect", self.image],
            capture_output=True, text=True, timeout=60, check=False,
        )
        return proc.returncode == 0

    def pull_size_mb(self) -> int | None:
        """What the pull will cost, from the registry, or None if it cannot say."""
        # deferred: startup; the registry client and the TLS stack load only for a pull.
        from . import oci

        size = oci.image_size(self.image)
        return None if size is None else max(1, round(size / 1_000_000))

    def db_size_mb(self) -> int | None:
        return database_size_mb()

    def pull_image(self, on_line=None) -> ScannerOutput:
        """`<runtime> pull <image>`, its output line by line to `on_line` when given
        (the terminal, for `valvur update`) and captured otherwise (a scan started
        over MCP, whose status line says what is happening instead)."""
        import subprocess

        cmd = [self.runtime, "pull", self.image]
        if on_line is None:
            proc = self._launch(cmd, capture_output=True, text=True, timeout=1800, check=False)
            return ScannerOutput("pull", "", proc.stdout, proc.stderr, proc.returncode)
        with subprocess.Popen(  # noqa: S603 — the runtime found by detect_runtime
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        ) as proc:
            lines: list[str] = []
            for line in proc.stdout or []:
                lines.append(line)
                on_line(line.rstrip("\n"))
            code = proc.wait(timeout=1800)
        return ScannerOutput("pull", "", "".join(lines), "", code)

    @property
    def runtime(self) -> str:
        if self._runtime is None:
            self._runtime = detect_runtime()
        return self._runtime

    def _launch(self, cmd, **kwargs):
        """Run a container command; one past its timeout is stopped by name."""
        import subprocess

        if _settings.get("debug") == "1":
            # What is about to run, as it will run (28.3.6): the one line a bug
            # report about a container needs. Stderr, so a client reading stdout
            # over MCP never sees it.
            print("valvur: " + " ".join(str(part) for part in cmd), file=sys.stderr, flush=True)
        name = cmd[cmd.index("--name") + 1] if "--name" in cmd else None
        try:
            return subprocess.run(cmd, **kwargs)  # noqa: S603
        except subprocess.TimeoutExpired as exc:
            # `subprocess.run` killed the CLIENT, `docker run`; the container is
            # the daemon's and runs on — measured at the first gate (29.0.2): a
            # Gitleaks container 401 s past its 300 s timeout, a Checkov one at
            # 92 % CPU 90 s after the server had exited. Stop it by the name it
            # was given, wait until the runtime no longer lists it, then say so.
            if name:
                with _suppress(Exception):
                    subprocess.run([self.runtime, "kill", name],  # noqa: S603
                                   capture_output=True, timeout=30, check=False)
                _wait_gone(self.runtime, name)
            raise _ScannerTimedOut(exc.timeout, _text(exc.stderr)) from exc

    def update_db(self) -> ScannerOutput:
        """Fetch the vulnerability DB out of band, so scans never need network."""
        # Exclusive, and it waits: readers finish, then new ones queue behind us
        # (task 16.3). trivy.db is a 1.35GB BoltDB and Trivy takes no lock of its
        # own — measured, there is no lock file anywhere in the cache directory.
        with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
            return self._update_db_locked()

    def _update_db_locked(self) -> ScannerOutput:
        # The one place the runner asks an adapter for a command: the database is
        # Trivy's, fetched by Trivy, and the adapter knows how (26.2.1).
        return self.run(database_fetch())

    def run(self, invocation: Invocation) -> ScannerOutput:
        """Run one Invocation — any Scanner's — and read its report from the
        scratch mount. The container concerns are this method's; the tool's are
        the Invocation's (26.2.1). `check=False` throughout: a Scanner exiting
        non-zero because it found issues is a successful run (F2.4), and the exit
        code is interpreted by the caller."""
        import tempfile

        tool, version = invocation.tool, invocation.version
        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            # What the adapter asked to find beside its report (29.0.1): written
            # here, read by the tool at /results/<name>, gone with the scratch.
            for name, text in invocation.files:
                (Path(scratch) / name).write_text(text, encoding="utf-8")
            cmd = [
                *launch_flags(self.runtime, generation=self.generation,
                              name=_container_name(), scratch=scratch,
                              network=invocation.network),
                *[flag for key, value in invocation.env for flag in ("--env", f"{key}={value}")],
                self.image, *invocation.argv,
            ]
            try:
                proc = self._launch(
                    cmd, capture_output=True, text=True, timeout=invocation.timeout, check=False
                )
            except _ScannerTimedOut as stopped:
                # Its own outcome (29.0.2): the record says timed out and stopped,
                # with the stderr read so far, never the argv as the reason.
                return ScannerOutput(tool, version, "", stopped.stderr, TIMED_OUT,
                                     argv=invocation.argv, stopped_after=stopped.seconds)
            report = Path(scratch) / invocation.report if invocation.report else None
            if (report is not None and not report.exists()
                    and nothing_to_scan(proc.stderr, invocation.empty_when)):
                # Nothing to analyse: an empty result, honestly earned.
                return ScannerOutput(tool, version, "", "", 0, argv=invocation.argv)
            if report is not None and not report.exists():
                # The Scanner was asked for a report and produced none. Exiting 0
                # while writing nothing means it could not write, not that it found
                # nothing — and treating those alike reports a vulnerable repository
                # as clean. Surfaced as a failure so the run is marked incomplete.
                return ScannerOutput(
                    tool, version, "",
                    f"{tool} produced no report at {invocation.report}. "
                    f"stderr: {proc.stderr.strip()[:300]}",
                    proc.returncode or 99, argv=invocation.argv,
                )
            stdout = report.read_text(encoding="utf-8") if report is not None else proc.stdout
        return ScannerOutput(tool, version, stdout, proc.stderr, proc.returncode,
                             argv=invocation.argv)
