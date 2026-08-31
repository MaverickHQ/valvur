"""The container-runtime boundary. Everything beyond this line is someone else's process."""

from __future__ import annotations

import os as _os
from dataclasses import dataclass
from pathlib import Path


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
IMAGE = _os.environ.get("VALVUR_IMAGE") or "ghcr.io/maverickhq/valvur:0.1.0rc1"

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
_VERSION = "0.1.0rc1"

# Air-gapped operation (F10.5). Enterprises mirror Trivy's DB into an internal OCI
# registry rather than granting egress to ghcr.io. ADR-0012 already made this
# reachable by keeping the DB out of the image, so mirroring needs no special build.
DB_REPOSITORY_ENV = "VALVUR_DB_REPOSITORY"


def db_repository() -> str | None:
    import os

    return os.environ.get(DB_REPOSITORY_ENV) or None
_RUNTIMES = ("docker", "podman", "nerdctl")


class WorkspaceUnreadable(RuntimeError):
    """The container cannot see the source. Never downgraded to a clean result."""


class NoContainerRuntime(RuntimeError):
    """Raised with remediation text — an error message is a usability surface (F1.5)."""


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
    mirror = db_repository()
    return ["--db-repository", mirror] if mirror else []


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


class ContainerRunner:
    """Invokes the scanner image. The Workspace is mounted read-only (ADR-0001)."""

    def __init__(self, image: str = IMAGE, runtime: str | None = None):
        self.image = image
        self._runtime = runtime

    def verify_workspace_readable(self, workspace: Path) -> None:
        """Confirm the container can actually see the Workspace before trusting a
        clean result.

        Found by CI: on rootless Podman the wrong user-mapping flag made the bind
        mount unreadable, so every Scanner read an empty tree, exited 0, and valvur
        reported a CLEAN SCAN OF A VULNERABLE REPOSITORY. No Scanner can detect this
        — from inside, an unreadable directory and an empty one are identical.
        """
        import subprocess
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
            proc = subprocess.run(  # noqa: S603
                cmd, capture_output=True, text=True, timeout=120, check=False
            )

        seen = proc.stdout.strip()
        if not seen.isdigit() or int(seen) == 0:
            raise WorkspaceUnreadable(
                f"The container cannot read the workspace: {workspace} has "
                f"{host_entries} entries, the container sees {seen or 'none'}.\n"
                "Refusing to report a scan — an unreadable workspace is "
                "indistinguishable from a clean one, and reporting it as clean would "
                "be the worst possible failure.\n"
                f"Runtime: {self.runtime}"
            )

    def verify_compatible(self) -> None:
        from . import compat

        compat.check(self.runtime, self.image)

    @property
    def runtime(self) -> str:
        if self._runtime is None:
            self._runtime = detect_runtime()
        return self._runtime

    def _base_flags(
        self, workspace: Path, scratch: str, *, network: bool = False, allow_exec: bool = False
    ) -> list[str]:
        from . import cache

        db = cache.trivy_db()
        db.mkdir(parents=True, exist_ok=True)
        flags = [
            self.runtime, "run", "--rm",
            *_user_flags(self.runtime),
            "--read-only",
            # A read-only root filesystem still needs scratch space. This tmpfs is in
            # memory, non-persistent and nosuid. `exec` is granted only to Scanners
            # that genuinely need it (Opengrep unpacks and runs opengrep-core), never
            # to the whole fleet — least privilege per Scanner.
            "--tmpfs",
            f"/tmp:rw,{'exec' if allow_exec else 'noexec'},nosuid,size=512m",  # noqa: S108
            "--cap-drop=ALL",
            "-v", f"{workspace}:/workspace:ro",     # F1.1 - source is read-only
            "-v", f"{scratch}:/results",
            "-v", f"{db}:/cache/trivy",             # ADR-0012 - DB outside the image
        ]
        if not network:
            flags.append("--network=none")           # N2.1 - no interface at all
        else:
            mirror = db_repository()
            if mirror:
                flags += ["--env", f"{DB_REPOSITORY_ENV}={mirror}"]
        return flags

    def update_db(self) -> ScannerOutput:
        """Fetch the vulnerability DB out of band, so scans never need network."""
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                *self._base_flags(Path.cwd(), scratch, network=True),
                self.image,
                "trivy", "image", "--download-db-only", "--cache-dir", "/cache/trivy",
                *_db_repository_flags(),
            ]

            # externally-derived value is a path passed as a single argv element.
            proc = subprocess.run(  # noqa: S603
                cmd, capture_output=True, text=True, timeout=900, check=False
            )
        return ScannerOutput("trivy-db", "", proc.stdout, proc.stderr, proc.returncode)

    def run_trivy(self, workspace: Path) -> ScannerOutput:
        import subprocess
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
            ]
            proc = subprocess.run(  # noqa: S603 - argument-list form, no shell
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
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                *self._base_flags(workspace, scratch, network=network, allow_exec=allow_exec),
                self.image, *argv,
            ]
            proc = subprocess.run(  # noqa: S603 - argument-list form, no shell
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
            "results_json.json", tool="checkov", version="3.2.517",
        )

    def run_syft(self, workspace: Path) -> ScannerOutput:
        return self._capture(
            workspace,
            ["syft", "scan", "dir:/workspace", "-o", "cyclonedx-json=/results/sbom.json", "-q"],
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

        `network` is opt-in per Check. Only dependency-reality needs it, and on the
        quick Profile it is denied regardless — so F3.5's honest degradation is
        enforced by the container, not by a code path someone could later change.
        """
        return self._capture(
            workspace,
            ["python", "-m", "valvur.checks", name, "/workspace"],
            None, tool=name, version=_VERSION, network=network,
        )

    def run_gitleaks(self, workspace: Path) -> ScannerOutput:
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory(prefix="valvur-") as scratch:
            cmd = [
                self.runtime, "run", "--rm",
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
            proc = subprocess.run(  # noqa: S603
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
