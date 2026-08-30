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
                "dir", "/workspace",
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
