"""The container-runtime boundary. Everything beyond this line is someone else's process."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScannerOutput:
    tool: str
    version: str
    stdout: str
    stderr: str
    exit_code: int


IMAGE = "valvur:dev"
_RUNTIMES = ("docker", "podman", "nerdctl")


class NoContainerRuntime(RuntimeError):
    """Raised with remediation text — an error message is a usability surface (F1.5)."""


def detect_runtime() -> str:
    import os
    import shutil

    override = os.environ.get("VALVUR_RUNTIME")
    if override:
        return override
    for candidate in _RUNTIMES:
        if shutil.which(candidate):
            return candidate
    raise NoContainerRuntime(
        "No container runtime found. valvur needs Docker or Podman.\n"
        "  macOS:  brew install --cask docker   (or: brew install podman && podman machine start)\n"
        "  Linux:  install docker or podman from your distribution\n"
        "Then re-run: valvur scan"
    )


def _user_flags() -> list[str]:
    import os

    if os.name != "posix":
        return []
    return ["--user", f"{os.getuid()}:{os.getgid()}"]


class ContainerRunner:
    """Invokes the scanner image. The Workspace is mounted read-only (ADR-0001)."""

    def __init__(self, image: str = IMAGE, runtime: str | None = None):
        self.image = image
        self._runtime = runtime

    @property
    def runtime(self) -> str:
        if self._runtime is None:
            self._runtime = detect_runtime()
        return self._runtime

    def _base_flags(self, workspace: Path, scratch: str, *, network: bool = False) -> list[str]:
        from . import cache

        db = cache.trivy_db()
        db.mkdir(parents=True, exist_ok=True)
        flags = [
            self.runtime, "run", "--rm",
            *_user_flags(),
            "--read-only",
            # A read-only root filesystem still needs scratch space. tmpfs keeps it
            # in memory and non-persistent, so the hardening stands.

            # path. It is in memory, non-persistent, noexec and nosuid.
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",  # noqa: S108
            "--cap-drop=ALL",
            "-v", f"{workspace}:/workspace:ro",     # F1.1 - source is read-only
            "-v", f"{scratch}:/results",
            "-v", f"{db}:/cache/trivy",             # ADR-0012 - DB outside the image
        ]
        if not network:
            flags.append("--network=none")           # N2.1 - no interface at all
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
                "--skip-db-update", "--skip-java-db-update",
                "--format", "json", "--output", "/results/trivy.json",
                "--quiet", "--scanners", "vuln",
            ]
            proc = subprocess.run(  # noqa: S603 - argument-list form, no shell
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            report = Path(scratch) / "trivy.json"
            stdout = report.read_text(encoding="utf-8") if report.exists() else ""

        return ScannerOutput("trivy", "0.74.0", stdout, proc.stderr, proc.returncode)

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
                *_user_flags(),
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
            stdout = report.read_text(encoding="utf-8") if report.exists() else "[]"

        return ScannerOutput(
            tool="gitleaks", version="8.30.1",
            stdout=stdout, stderr=proc.stderr, exit_code=proc.returncode,
        )
