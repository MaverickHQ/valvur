"""The container-runtime boundary. Everything beyond this line is someone else's process."""

from __future__ import annotations

import os as _os
import threading as _threading
import uuid as _uuid
from contextlib import suppress as _suppress
from dataclasses import dataclass
from pathlib import Path

from .version import __version__, default_image


@dataclass(frozen=True)
class ScannerOutput:
    tool: str
    version: str
    stdout: str
    stderr: str
    exit_code: int


# The published image. A fresh install has no local build, so this must be pullable
# by anyone — pointing at a local tag would make the first run fail for every user
# who is not us.
IMAGE = _os.environ.get("VALVUR_IMAGE") or default_image()

# A Scanner that finds nothing to analyse has not failed. OSV-Scanner reads lockfiles
# only, so a project with a pyproject.toml and no lockfile makes it exit 128 saying
# "No package sources found" — a normal condition we were reporting as a failure,
# which marked the whole scan incomplete and made every lockfile-less project look
# broken. The mirror of the Phase 8 lesson: there, missing output WAS a failure.
NOTHING_TO_SCAN = (
    "no package sources found",
    "no such file or directory",
    "no files to scan",
)


def _is_nothing_to_scan(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(phrase in lowered for phrase in NOTHING_TO_SCAN)
_VERSION = __version__

# Air-gapped operation (F10.5). Enterprises mirror Trivy's DB into an internal OCI
# registry rather than granting egress to ghcr.io. ADR-0012 already made this
# reachable by keeping the DB out of the image, so mirroring needs no special build.
DB_REPOSITORY_ENV = "VALVUR_DB_REPOSITORY"
#: Where Trivy fetches its database from when no mirror is named — the first of its
#: own two defaults (`trivy image --help`, 0.74: this, then ghcr.io), and what a
#: first scan sizes its "fetching" line from (24.1). Both answered 118.5MB in under
#: a second, anonymously, measured 2026-09-13.
DEFAULT_DB_REPOSITORY = "mirror.gcr.io/aquasec/trivy-db:2"
#: A mirror that speaks plain HTTP, or HTTPS with a certificate the container does
#: not trust. Measured 2026-09-12 (22.B.3): against an internal `registry:2` the
#: documented VALVUR_DB_REPOSITORY alone fails with "server gave HTTP response to
#: HTTPS client", because Trivy (go-containerregistry underneath) assumes TLS for
#: any host that is not localhost or a private-range IP literal. Trivy's own
#: `--insecure` is the switch; this is how it is reached from a shim with no flags.
DB_INSECURE_ENV = "VALVUR_DB_INSECURE"
#: The runtime network a NETWORKED container joins — the update, and `full`'s
#: Scanners. Unset, the runtime's default bridge. An air-gapped site whose mirror
#: registry lives on a user-defined network (or an `--internal` one, which is how
#: 22.B.3 proves the air gap structurally) names it here. Never applied to a
#: container launched without a network: `--network=none` is not negotiable.
CONTAINER_NETWORK_ENV = "VALVUR_CONTAINER_NETWORK"


def db_repository() -> str | None:
    import os

    return os.environ.get(DB_REPOSITORY_ENV) or None
_RUNTIMES = ("docker", "podman", "nerdctl")

_INDEX_REFUSAL = (
    "Package-name index not present, so dependency existence cannot be checked "
    "offline. Fetch it once with:\n"
    "  valvur update\n"
    "Scans then verify package names against the cached index (ADR-0018)."
)


class WorkspaceUnreadable(RuntimeError):
    """The container cannot see the source. Never downgraded to a clean result."""


#: Opt-in, and an environment variable rather than a CLI flag: MCP is the primary
#: interface (ADR-0015) and has no command line, so a flag would fix this for the
#: second-choice path only.
RELABEL_ENV = "VALVUR_SELINUX_RELABEL"
#: Set inside a container launched WITH a network, and only then (ADR-0018).
NETWORK_ENV = "VALVUR_NETWORK"

#: Named so a test can point it somewhere real. Patching `Path.read_text` wholesale
#: could not tell "enforcing" from "SELinux is absent" — both end up False — so the
#: test proved only one of the two directions it claimed to.
SELINUX_ENFORCE = Path("/sys/fs/selinux/enforce")


def selinux_enforcing() -> bool:
    """Whether the HOST kernel is enforcing SELinux.

    The host, not the container, because the mount sources are host paths and it is
    the host's labels that decide whether the container may read them.

    `permissive` returns False deliberately: it logs the denial and allows the access,
    so relabelling would be a write to someone's tree in exchange for nothing.
    """
    try:
        return SELINUX_ENFORCE.read_text().strip() == "1"
    except OSError:
        return False          # not Linux, or SELinux absent


def _relabel_workspace() -> bool:
    """Whether the developer has asked us to relabel their source tree.

    **Off by default, and that is a deliberate cost.** `:z` rewrites the SELinux
    context of every file in the Workspace to `container_file_t`, which persists after
    the scan. CLAUDE.md section 10 prohibits any feature that writes to the scanned
    source tree without explicit owner approval, and a security tool whose first
    promise is that it cannot touch your code should not quietly rewrite its labels.

    valvur's OWN directories — the scratch mount and the database cache — are
    relabelled unconditionally on an enforcing host. They are a temporary directory we
    created and a cache we own; nothing about them is the developer's, and without the
    label the container cannot write its results at all.
    """
    return _os.environ.get(RELABEL_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _selinux_hint(workspace) -> str:
    """What to do about it, in the reader's terms.

    Every claim here was measured on Fedora CoreOS 44, xfs, SELinux enforcing, both
    rootful and rootless Podman (task 20.1).
    """
    return "\n".join([
        "SELinux is enforcing on this host, and the container may not read the "
        "workspace.",
        "  A directory under $HOME is labelled user_home_t or admin_home_t, which a",
        "  container process is not permitted to read.",
        "",
        "  valvur does not relabel your source tree unless you ask it to: that is a "
        "write",
        "  to the code it is scanning. Choose one:",
        "",
        f"    {RELABEL_ENV}=1 valvur scan {workspace}",
        "      Adds :z to the mount. The tree is relabelled container_file_t; the "
        "label",
        "      persists after the scan, and is shared, so other containers can read "
        "it too.",
        "",
        f"    chcon -R -t container_file_t {workspace}",
        "      The same change, made by you, once.",
        f"      Undo with: restorecon -R -F {workspace}",
        "      The -F is required. container_file_t is a customizable type, and",
        "      restorecon skips those unless forced - measured, plain restorecon -R",
        "      leaves the relabelled tree exactly as it was.",
        "",
        "  :Z is deliberately not offered. It stamps a private MCS category, and "
        "valvur",
        "  runs its Scanners concurrently against one mount - measured, the second",
        "  container is denied.",
    ])


def _unreadable_hint(runtime: str, workspace) -> str:
    """Say why, not just that. Podman on macOS runs a VM that shares only certain
    host paths, so a repository outside them mounts as an empty directory with no
    error from the runtime — the failure looks like a bug in us. Measured: a path
    under /var/folders mounts empty while /private/tmp works."""
    import platform

    # Checked before the macOS branch: an enforcing host is a far more specific
    # diagnosis than "check your mount permissions", and it is the one a RHEL user
    # needs. Task 20.2.
    if selinux_enforcing():
        return _selinux_hint(workspace)

    if "podman" not in runtime or platform.system() != "Darwin":
        return (
            "Check the path exists and that your container runtime is permitted to "
            "mount it."
        )
    return (
        "On macOS, Podman runs inside a VM and can only mount host paths that VM "
        "shares. A path it does not share appears as an empty directory.\n"
        f"  Path scanned: {workspace}\n"
        "  Fix: scan a repository under your home directory, or share this path:\n"
        "    podman machine stop\n"
        "    podman machine set --volume /your/path:/your/path\n"
        "    podman machine start\n"
        "  Docker Desktop shares more paths by default and is unaffected."
    )


class ContainerStartFailed(RuntimeError):
    """The runtime could not start the container at all.

    Distinct from an unreadable Workspace, and the distinction matters: the probe
    used to discard stderr, so a failed image pull was reported as "the container
    cannot read the workspace" and sent the reader to check mount permissions. The
    runtime already said exactly what was wrong; we were throwing it away.
    """


class NoContainerRuntime(RuntimeError):
    """Raised with remediation text — an error message is a usability surface (F1.5)."""


class BatchUnsupported(RuntimeError):
    """The image predates the Checks batch (23.4.2): its entry point answered
    `usage:` and exit 2. The fleet runs the Checks one by one instead — a pinned
    older image keeps working, slower, rather than failing three Scanners."""


class ImagePullFailed(RuntimeError):
    """The image is not local and could not be fetched. The runtime's own words are
    in the message: a private package, no network, a typo in `VALVUR_IMAGE`."""


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

    override = os.environ.get("VALVUR_RUNTIME")
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


def _db_repository_flags() -> list[str]:
    import os

    mirror = db_repository()
    if not mirror:
        return []
    flags = ["--db-repository", mirror]
    if os.environ.get(DB_INSECURE_ENV) == "1":
        flags.append("--insecure")
    return flags


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
_live_containers: set[str] = set()
_live_lock = _threading.Lock()


def _container_name() -> str:
    return f"valvur-{_uuid.uuid4().hex[:16]}"


def kill_running(runtime: str | None = None) -> int:
    """Stop every container this process started. Returns how many were signalled.

    Best effort by construction: a container that has already exited is not an error,
    and refusing to exit because cleanup was imperfect would be worse than the mess.
    """
    with _live_lock:
        names = sorted(_live_containers)
    return _kill(runtime, names)


def _kill(runtime: str | None, names: list[str]) -> int:
    """One `kill` for all of them: the runtime signals each and reports the ones
    already gone without stopping — measured, one call per container cost an
    agent's cancel six seconds for seven containers (23.3.3)."""
    import subprocess

    if not names:
        return 0
    binary = runtime or detect_runtime()
    with _suppress(Exception):
        subprocess.run(  # noqa: S603
            [binary, "kill", *names],
            capture_output=True, timeout=30, check=False,
        )
    return len(names)


class ContainerRunner:
    """Invokes the scanner image. The Workspace is mounted read-only (ADR-0001)."""

    def __init__(self, image: str = IMAGE, runtime: str | None = None):
        self.image = image
        self._runtime = runtime
        #: Containers THIS runner launched, so a cancel from one MCP job stops its
        #: own fleet and not another workspace's (23.3.3). `kill_running` is the
        #: process-wide version, for Ctrl-C.
        self._mine: set[str] = set()
        #: Set by `kill`. The scan checks it before it writes anything (F1.11).
        self.cancelled = False

    def kill(self) -> int:
        """Stop the containers this runner started, and remember that the scan
        was cancelled. Returns how many were signalled."""
        self.cancelled = True
        return self.stop_containers()

    def stop_containers(self) -> int:
        """Stop the containers this runner started — without cancelling the scan.
        What the budget does (23.3.7): the Scanners that finished are a result."""
        with _live_lock:
            names = sorted(self._mine & _live_containers)
        runtime = None
        with _suppress(Exception):
            runtime = self.runtime
        return _kill(runtime, names)

    def verify_workspace_readable(self, workspace: Path) -> None:
        """Confirm the container can actually see the Workspace before trusting a
        clean result.

        Found by CI: on rootless Podman the wrong user-mapping flag made the bind
        mount unreadable, so every Scanner read an empty tree, exited 0, and valvur
        reported a CLEAN SCAN OF A VULNERABLE REPOSITORY. No Scanner can detect this
        — from inside, an unreadable directory and an empty one are identical.
        """
        import tempfile

        host_entries = sum(1 for _ in workspace.iterdir())
        if host_entries == 0:
            return                     # genuinely empty; nothing to verify

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                *self._base_flags(workspace, scratch),
                "--entrypoint", "sh", self.image,
                "-c", "ls -A /workspace | wc -l",
            ]
            proc = self._launch(
                cmd, capture_output=True, text=True, timeout=120, check=False
            )

        seen = proc.stdout.strip()
        if proc.returncode != 0 or not seen.isdigit():
            raise ContainerStartFailed(
                "The container did not run, so the workspace could not be checked.\n"
                "This is not a problem with your code — the scan never started.\n"
                f"Runtime: {self.runtime}\n"
                f"Image:   {self.image}\n"
                f"{Path(self.runtime).name} said:\n"
                f"  {(proc.stderr.strip() or '(no error text)')[:500]}\n"
                f"If the image is missing, fetch it with:\n"
                f"  {Path(self.runtime).name} pull {self.image}"
            )
        if int(seen) == 0:
            raise WorkspaceUnreadable(
                f"The container cannot read the workspace: {workspace} has "
                f"{host_entries} entries, the container sees {seen or 'none'}.\n"
                "Refusing to report a scan — an unreadable workspace is "
                "indistinguishable from a clean one, and reporting it as clean would "
                "be the worst possible failure.\n"
                f"Runtime: {self.runtime}\n" + _unreadable_hint(self.runtime, workspace)
            )

    def verify_compatible(self) -> None:
        from . import compat

        compat.check(self.runtime, self.image)

    def build_provenance(self) -> tuple[str | None, str | None]:
        """(the tree this shim was built beside, the tree the image was built
        from) — either None when unrecorded (23.4.4). Compared by the scan and
        reported, never refused."""
        from . import compat

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
        from . import oci

        size = oci.image_size(self.image)
        return None if size is None else max(1, round(size / 1_000_000))

    def db_size_mb(self) -> int | None:
        """What fetching the vulnerability database will cost, from the registry
        Trivy will pull it from, or None if it cannot say (24.1)."""
        import os

        from . import oci

        size = oci.image_size(db_repository() or DEFAULT_DB_REPOSITORY,
                              insecure=os.environ.get(DB_INSECURE_ENV) == "1")
        return None if size is None else max(1, round(size / 1_000_000))

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
        """Run a container command, tracking it so an interrupt can stop it."""
        import subprocess

        name = cmd[cmd.index("--name") + 1] if "--name" in cmd else None
        if name:
            with _live_lock:
                _live_containers.add(name)
                self._mine.add(name)
        try:
            return subprocess.run(cmd, **kwargs)  # noqa: S603
        finally:
            if name:
                with _live_lock:
                    _live_containers.discard(name)

    def _base_flags(
        self, workspace: Path, scratch: str, *, network: bool = False, allow_exec: bool = False
    ) -> list[str]:
        from . import cache

        db = cache.trivy_db()
        db.mkdir(parents=True, exist_ok=True)
        names = cache.name_index()
        names.mkdir(parents=True, exist_ok=True)
        enforcing = selinux_enforcing()
        own_label = ":z" if enforcing else ""
        ws_label = ",z" if enforcing and _relabel_workspace() else ""
        flags = [
            self.runtime, "run", "--rm",
            "--name", _container_name(),
            *_user_flags(self.runtime),
            # F10.2, with the Dockerfile's USER 10001: non-root, read-only root
            # filesystem, every capability dropped.
            "--read-only",
            # A read-only root filesystem still needs scratch space. This tmpfs is in
            # memory, non-persistent and nosuid. `exec` is granted only to Scanners
            # that genuinely need it (Opengrep unpacks and runs opengrep-core), never
            # to the whole fleet — least privilege per Scanner.
            "--tmpfs",
            f"/tmp:rw,{'exec' if allow_exec else 'noexec'},nosuid,size=512m",  # noqa: S108
            "--cap-drop=ALL",
            # SELinux mount labelling (F1.6, task 20.2). Measured on an enforcing
            # host: without a label EVERY one of these three mounts is denied — the
            # source unreadable, the results unwritable, the cache unwritable.
            #
            # The two valvur owns are relabelled unconditionally. The developer's
            # source tree is not, unless they ask: `:z` persists after the scan, and
            # section 10 prohibits writing to the scanned tree without approval.
            "-v", f"{workspace}:/workspace:ro{ws_label}",   # F1.1 - source read-only
            "-v", f"{scratch}:/results{own_label}",
            "-v", f"{db}:/cache/trivy{own_label}",  # ADR-0012 - DB outside the image
            # ADR-0018 - the package-name index, beside the database and for the
            # same reason. Read-only: the Check only ever asks it questions.
            "-v", f"{names}:/cache/names:ro{own_label and ',z'}",
        ]
        if not network:
            flags.append("--network=none")           # N2.1 - no interface at all
        else:
            # Told, not probed. The dependency-reality Check asks a registry only
            # when this is set, and it is set in exactly the case `--network=none`
            # is omitted — one decision, read by the Check and enforced by the kernel.
            flags += ["--env", f"{NETWORK_ENV}=1"]
            mirror = db_repository()
            if mirror:
                flags += ["--env", f"{DB_REPOSITORY_ENV}={mirror}"]
            joined = _os.environ.get(CONTAINER_NETWORK_ENV)
            if joined:
                flags.append(f"--network={joined}")
        return flags

    def update_db(self) -> ScannerOutput:
        """Fetch the vulnerability DB out of band, so scans never need network."""
        from . import cache, locking

        # Exclusive, and it waits: readers finish, then new ones queue behind us
        # (task 16.3). trivy.db is a 1.35GB BoltDB and Trivy takes no lock of its
        # own — measured, there is no lock file anywhere in the cache directory.
        with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
            return self._update_db_locked()

    def _update_db_locked(self) -> ScannerOutput:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                *self._base_flags(Path.cwd(), scratch, network=True),
                self.image,
                "trivy", "image", "--download-db-only", "--cache-dir", "/cache/trivy",
                *_db_repository_flags(),
            ]

            # externally-derived value is a path passed as a single argv element.
            proc = self._launch(
                cmd, capture_output=True, text=True, timeout=900, check=False
            )
        return ScannerOutput("trivy-db", "", proc.stdout, proc.stderr, proc.returncode)

    def run_trivy(self, workspace: Path) -> ScannerOutput:
        import tempfile

        from . import cache

        if not cache.db_present():
            raise RuntimeError(
                "Trivy vulnerability database not present. Fetch it once with:\n"
                "  valvur update\n"
                "Scans then run fully offline against the cached database."
            )

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                *self._base_flags(workspace, scratch),
                self.image,
                "trivy", "fs", "/workspace",
                "--cache-dir", "/cache/trivy",
                *_db_repository_flags(),
                "--skip-db-update", "--skip-java-db-update",
                "--format", "json", "--output", "/results/trivy.json",
                "--quiet", "--scanners", "vuln",
                # Trivy excludes dev dependencies by default; OSV-Scanner includes
                # them. Measured on a real Electron app: without this the quick
                # profile found 0 CVEs and standard found 24 — the same 24, in the
                # same lockfile, differing only by this flag. Build and test tooling
                # runs on the developer's machine and in CI, which is precisely the
                # supply-chain surface this product exists to cover.
                "--include-dev-deps",
            ]
            proc = self._launch(
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            report = Path(scratch) / "trivy.json"
            if not report.exists():
                return ScannerOutput(
                    "trivy", "0.74.0", "",
                    f"trivy produced no report. stderr: {proc.stderr.strip()[:300]}",
                    proc.returncode or 99,
                )
            stdout = report.read_text(encoding="utf-8")

        return ScannerOutput("trivy", "0.74.0", stdout, proc.stderr, proc.returncode)

    def _capture(self, workspace, argv, outfile, *, tool, version, network=False,
                 timeout=600, allow_exec=False):
        """Run one Scanner and read its report from the scratch mount."""
        import tempfile

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                *self._base_flags(workspace, scratch, network=network, allow_exec=allow_exec),
                self.image, *argv,
            ]
            proc = self._launch(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            report = Path(scratch) / outfile if outfile else None
            if report is not None and not report.exists() and _is_nothing_to_scan(proc.stderr):
                # Nothing to analyse: an empty result, honestly earned.
                return ScannerOutput(tool, version, "", "", 0)
            if report is not None and not report.exists():
                # The Scanner was asked for a report and produced none. Exiting 0
                # while writing nothing means it could not write, not that it found
                # nothing — and treating those alike reports a vulnerable repository
                # as clean. Surfaced as a failure so the run is marked incomplete.
                return ScannerOutput(
                    tool, version, "",
                    f"{tool} produced no report at {outfile}. "
                    f"stderr: {proc.stderr.strip()[:300]}",
                    proc.returncode or 99,
                )
            stdout = report.read_text(encoding="utf-8") if report is not None else proc.stdout
        return ScannerOutput(tool, version, stdout, proc.stderr, proc.returncode)

    def run_osv(self, workspace: Path) -> ScannerOutput:
        # OSV queries api.osv.dev, so it is a standard/deep Scanner only - it is
        # absent from the quick Profile, which must stay offline (N2.1).
        return self._capture(
            workspace,
            ["osv-scanner", "scan", "source", "--recursive",
             "--format", "json", "--output", "/results/osv.json", "/workspace"],
            "osv.json", tool="osv-scanner", version="2.2.4", network=True,
        )

    def run_checkov(self, workspace: Path) -> ScannerOutput:
        return self._capture(
            workspace,
            ["checkov", "--directory", "/workspace", "--output", "json",
             "--output-file-path", "/results", "--quiet", "--compact",
             # No network, ever: skip external data downloads outright.
             "--skip-download"],
            "results_json.json", tool="checkov", version="3.3.17",
        )

    def run_syft(self, workspace: Path) -> ScannerOutput:
        from . import exclusions

        # The SBOM is a release artifact, so a configured exclusion has to reach it,
        # not just the findings derived from it. Without this, valvur's own published
        # SBOM would list aws-helper-sdk and locktest — packages its test fixtures
        # invent precisely because they do not exist.
        excluded = [
            arg
            for prefix in exclusions.load_configured(workspace)
            for arg in ("--exclude", f"./{prefix}/**")
        ]
        return self._capture(
            workspace,
            ["syft", "scan", "dir:/workspace", "-o", "cyclonedx-json=/results/sbom.json",
             "-q", *excluded],
            "sbom.json", tool="syft", version="1.51.1",
        )

    def run_opengrep(self, workspace: Path) -> ScannerOutput:
        # Our own bundled rules only (ADR-0004). No registry fetch, so no network
        # and no licence question.
        return self._capture(
            workspace,
            ["opengrep", "scan", "--config", "/opt/valvur-rules",
             "--json", "--output", "/results/opengrep.json",
             "--quiet", "--no-git-ignore", "/workspace"],
            "opengrep.json", tool="opengrep", version="1.29.0",
            # Opengrep unpacks and execs opengrep-core. Granted only here: the root
            # filesystem stays read-only, the container stays non-root and
            # capability-less, and the exec surface is in-memory and non-persistent.
            allow_exec=True,
        )

    def run_check(self, name: str, workspace: Path, *, network: bool = False) -> ScannerOutput:
        """Run one of valvur's own Checks inside the container (ADR-0013).

        `network` is decided by the Profile, never by the Check: `profiles.select`
        hands each adapter the Profile's permission, and only dependency-reality ever
        uses it — for first-publish age, on `full`. On `offline` the container has
        no interface, so F3.5's honest degradation is enforced by the kernel, not by
        a code path someone could later change.
        """
        from . import cache

        if name == "dependency-reality" and not network and not cache.name_index_present():
            # The same refusal Trivy gets without its database, decided here so the
            # message leads with the fix rather than arriving as a container's
            # stderr. The Check refuses too (in case the mount is empty or partial);
            # this is the version a first-time user actually reads.
            raise RuntimeError(_INDEX_REFUSAL)
        return self._capture(
            workspace,
            ["python", "-m", "valvur.checks", name, "/workspace"],
            None, tool=name, version=_VERSION, network=network,
        )

    def run_checks(self, names, workspace: Path, *, network: bool = False
                   ) -> dict[str, ScannerOutput]:
        """Run several of valvur's Checks in ONE container (23.4.2) and return each
        one's output under its own name, as `run_check` would have.

        The container carries the Profile's grant — `network` is True only when a
        Check in the batch was granted one, which is dependency-reality on `full` —
        and the batch runs that Check last. The same host-side refusal as
        `run_check` applies to it: without an index and without a network it is
        answered here, and the container is launched for the others.
        """
        import json

        from . import cache

        names = list(names)
        outputs: dict[str, ScannerOutput] = {}
        if "dependency-reality" in names and not network and not cache.name_index_present():
            outputs["dependency-reality"] = ScannerOutput(
                "dependency-reality", _VERSION, "", _INDEX_REFUSAL, 1)
            names.remove("dependency-reality")
        if not names:
            return outputs

        batch = self._capture(
            workspace, ["python", "-m", "valvur.checks", "batch", "/workspace", *names],
            None, tool="checks", version=_VERSION, network=network,
        )
        if batch.exit_code == 2 and "usage:" in batch.stderr:
            raise BatchUnsupported(
                f"{self.image} predates the Checks batch; running the Checks one by one")
        try:
            report = json.loads(batch.stdout) if batch.exit_code == 0 else None
            if not isinstance(report, dict):
                report = None
        except ValueError:
            report = None
        for name in names:
            if report is None:
                detail = batch.stderr.strip()[:300] or f"exit {batch.exit_code}"
                outputs[name] = ScannerOutput(
                    name, _VERSION, "",
                    f"the Checks container produced no batch report ({detail})",
                    batch.exit_code or 99,
                )
                continue
            entry = report.get(name) or {"ok": False, "findings": [],
                                         "error": "missing from the batch report"}
            outputs[name] = ScannerOutput(
                name, _VERSION, json.dumps(entry.get("findings") or []),
                entry.get("error") or "", 0 if entry.get("ok") else 1,
            )
        return outputs

    def run_gitleaks(self, workspace: Path) -> ScannerOutput:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                self.runtime, "run", "--rm",
                "--name", _container_name(),
                # Run as the invoking user so the scratch mount is writable.
                # Docker Desktop translates UIDs for us; rootful Linux Docker does
                # not, so without this the container cannot write its report and the
                # scan silently returns nothing. Found by CI on Linux, not locally.
                *_user_flags(self.runtime),
                "--network=none",                      # N2.1 — no interface at all
                "--read-only",
                "--cap-drop=ALL",
                "-v", f"{workspace}:/workspace:ro",    # F1.1 — source is read-only
                "-v", f"{scratch}:/results",
                self.image,
                "gitleaks", "dir", "/workspace",
                "--report-format", "json",
                "--report-path", "/results/gitleaks.json",
                "--no-banner", "--exit-code", "0",
            ]
            # check=False: a scanner exiting non-zero because it found issues is a
            # successful run (F2.4). We interpret exit codes ourselves.
            proc = self._launch(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            report = Path(scratch) / "gitleaks.json"
            if not report.exists():
                return ScannerOutput(
                    "gitleaks", "8.30.1", "",
                    f"gitleaks produced no report. stderr: {proc.stderr.strip()[:300]}",
                    proc.returncode or 99,
                )
            stdout = report.read_text(encoding="utf-8")

        return ScannerOutput(
            tool="gitleaks", version="8.30.1",
            stdout=stdout, stderr=proc.stderr, exit_code=proc.returncode,
        )
