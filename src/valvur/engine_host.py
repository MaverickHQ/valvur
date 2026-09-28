"""The host's side of the Scan Container (ADR-0022, task R3).

The host builds a Snapshot of the File Set, writes the plan beside where the reports
will land, runs the in-image engine through a runtime, and reads the manifest back.
Two runtimes: the container one, and `LocalRuntime`, which runs the same engine as a
host process — the one boundary the tests fake (tasks.md §3).
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from .engine import CACHE_ENV, RESULTS_ENV, WORKSPACE_ENV
from .invocation import Invocation
from .selinux import selinux_enforcing


def snapshot(root: Path, files: Iterable[str]) -> bytes:
    """The File Set as a tar, each entry under its repo-relative path."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for rel in sorted(files):
            archive.add(root / rel, arcname=rel, recursive=False)
    return buffer.getvalue()


def plan_entry(invocation: Invocation) -> dict:
    return {"tool": invocation.tool, "version": invocation.version,
            "argv": list(invocation.argv), "report": invocation.report,
            "timeout": invocation.timeout, "env": [list(e) for e in invocation.env],
            "files": [list(f) for f in invocation.files],
            "empty_when": list(invocation.empty_when)}


#: How long past its budget the engine may take to stop its tools and write the
#: manifest before the host kills it (R3.5).
GRACE_S = 20.0
#: How long a stopped engine has to stop its own tools before its group is killed.
STOP_WAIT_S = 5.0


def _signal_group(process: subprocess.Popen, signum: int) -> None:
    import contextlib

    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signum)


def _stop_group(process: subprocess.Popen, finished: threading.Event) -> None:
    """SIGTERM, so the engine stops every tool it started (each in a process group
    of its own, which no signal to the engine's reaches); SIGKILL if it has not
    gone within `STOP_WAIT_S`."""
    import signal

    _signal_group(process, signal.SIGTERM)
    if not finished.wait(STOP_WAIT_S):
        _signal_group(process, signal.SIGKILL)


def stream(command: list[str], tar: bytes, env: dict | None,
           on_event: Callable[[dict], None] | None, *,
           deadline_s: float | None = None,
           kill: Callable[[], None] | None = None,
           stop: threading.Event | None = None) -> int:
    """Run the engine, feeding it the Snapshot and handing each progress line to
    `on_event` as it arrives, not after the run (R3.4): what a status line and an
    MCP progress notification are built from. Past `deadline_s`, or once `stop`
    is set (a cancel), the host stops it: `kill` when given (a container is the
    daemon's, not this process's child), and the engine's whole process group
    either way (R3.5)."""
    process = subprocess.Popen(command, stdin=subprocess.PIPE,  # noqa: S603
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
                               start_new_session=True)
    finished = threading.Event()

    def enforce() -> None:
        limit = None if deadline_s is None else time.monotonic() + deadline_s
        while not finished.wait(0.1):
            cancelled = stop is not None and stop.is_set()
            if cancelled or (limit is not None and time.monotonic() >= limit):
                if kill is not None:
                    kill()
                _stop_group(process, finished)
                return

    enforcer = threading.Thread(target=enforce, daemon=True)
    enforcer.start()

    def feed() -> None:
        try:
            if process.stdin is not None:
                process.stdin.write(tar)
                process.stdin.close()
        except BrokenPipeError:
            pass                      # the engine stopped reading: its exit code says why

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    if process.stderr is not None:
        for raw in process.stderr:
            line = raw.decode("utf-8", "replace").strip()
            if on_event is not None and line.startswith("{"):
                try:
                    on_event(json.loads(line))
                except ValueError:
                    pass
    writer.join()
    code = process.wait()
    finished.set()
    return code


def write_plan(scratch: Path, plan: list[Invocation], budget_s: float | None = None,
               jobs: int | None = None) -> None:
    (scratch / "plan.json").write_text(
        json.dumps({"tools": [plan_entry(i) for i in plan], "budget_s": budget_s,
                    "jobs": jobs}),
        encoding="utf-8")


#: Where the Scanners ran, as `run.json` states it: the Scan Container, which has
#: no network interface on `offline` (ADR-0022), unless a job's container (R8.1).
SCAN_CONTAINER = "the Scan Container"


def job_boundary(net: Path = Path("/sys/class/net")) -> str:
    """The job's container, and whether it has a network: any interface but the
    loopback is one. The Scanners run with their offline flags either way; only a
    job started with no network makes that structural."""
    try:
        interfaces = sorted(p.name for p in net.iterdir() if p.name != "lo")
    except OSError:
        return "this job's container, its network unknown"
    if not interfaces:
        return "this job's container, with no network"
    return f"this job's container, with a network: {', '.join(interfaces)}"


class _Runtime:
    """What both runtimes share: one engine at a time, and one way to stop it.

    `kill` is the cancel (F1.11): it marks the runtime cancelled, which `api`
    reads before and after the engine runs, and stops the engine if one is
    running. `wait_stopped` is the confirmation CANCELLED waits for (R3.5)."""

    #: What `api` asks to choose the Scan Container's path (ADR-0022).
    engine = True

    def __init__(self) -> None:
        #: Set by `kill`. The scan checks it before it writes anything (F1.11).
        self.cancelled = False
        self._stop = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        #: Engines running now: `full` runs two at once, one per network boundary.
        self._running = 0
        self._count = threading.Lock()
        #: The Scan Run's generation, carried by the Scan Container (R3.6).
        self.generation: str | None = None

    def boundary(self) -> str:
        """Where the Scanners run, for `run.json` (R8.1)."""
        return SCAN_CONTAINER

    def kill(self) -> int:
        """Stop the engine, and remember that the scan was cancelled. Returns 1
        when an engine was running, 0 when none had started."""
        self.cancelled = True
        self._stop.set()
        return 0 if self._idle.is_set() else 1

    def wait_stopped(self, timeout: float = 15.0) -> bool:
        """True once no engine this runtime started is running; False if
        `timeout` passed first."""
        return self._idle.wait(timeout)

    def _engine(self, command: list[str], tar: bytes, env: dict | None,
                on_event: Callable[[dict], None] | None, budget_s: float | None,
                kill: Callable[[], None] | None = None) -> int:
        with self._count:
            self._running += 1
            self._idle.clear()
        try:
            return stream(command, tar, env, on_event,
                          deadline_s=budget_s + GRACE_S if budget_s else None,
                          kill=kill, stop=self._stop)
        finally:
            with self._count:
                self._running -= 1
                if self._running == 0:
                    self._idle.set()


class LocalRuntime(_Runtime):
    """Runs the engine as a process, with `tools_dir` first on its PATH and the
    container's `/cache` at `cache` when one is given."""

    def __init__(self, tools_dir: Path | None = None, cache: Path | None = None):
        super().__init__()
        self.tools_dir = tools_dir
        self.cache = cache

    def run(self, plan: list[Invocation], tar: bytes, scratch: Path,
            on_event: Callable[[dict], None] | None = None,
            budget_s: float | None = None, jobs: int | None = None) -> int:
        write_plan(scratch, plan, budget_s, jobs)
        workspace = scratch.parent / f"{scratch.name}-workspace"
        env = {**os.environ, WORKSPACE_ENV: str(workspace), RESULTS_ENV: str(scratch)}
        if self.cache is not None:
            env[CACHE_ENV] = str(self.cache)
        if self.tools_dir is not None:
            env["PATH"] = f"{self.tools_dir}{os.pathsep}{env.get('PATH', '')}"
        return self._engine([sys.executable, "-m", "valvur.engine"], tar, env, on_event,
                            budget_s)


#: Up to this size the Snapshot lands in a tmpfs, in memory and gone with the
#: container; beyond it, in a per-scan volume removed after the scan (ADR-0022).
TMPFS_LIMIT = 512 * 2**20


class ContainerRuntime(_Runtime):
    """One Scan Container (ADR-0022): the Snapshot on stdin, into an in-memory
    `/workspace`; the plan and the reports in a scratch directory mounted at
    `/results`; the source tree never mounted."""

    def __init__(self, image: str | None = None, runtime: str | None = None):
        from .runner import IMAGE

        super().__init__()
        self.image = image or IMAGE
        self._runtime = runtime
        #: Every Scan Container this runtime started, for `wait_stopped`.
        self._names: set[str] = set()

    # What a scan does before the Scan Container starts (24.1, 23.2.4, F1.9,
    # 23.4.4): the image and the data, fetched when absent, and the pair checked.
    # The fleet's runner already does each; this runtime asks it.

    @property
    def _fetcher(self):
        from .runner import ContainerRunner

        if self.__dict__.get("_runner") is None:
            self.__dict__["_runner"] = ContainerRunner(self.image, self._runtime)
        return self.__dict__["_runner"]

    def image_present(self) -> bool:
        return self._fetcher.image_present()

    def pull_size_mb(self):
        return self._fetcher.pull_size_mb()

    def pull_image(self, on_line=None):
        return self._fetcher.pull_image(on_line)

    def db_size_mb(self):
        return self._fetcher.db_size_mb()

    def update_db(self):
        return self._fetcher.update_db()

    def verify_compatible(self) -> None:
        return self._fetcher.verify_compatible()

    def build_provenance(self):
        return self._fetcher.build_provenance()

    def wait_stopped(self, timeout: float = 15.0) -> bool:
        """True once the `docker run` client has returned AND the runtime no
        longer lists the container: `docker kill` returns before `--rm` removes
        it, and the second gate saw CANCELLED with a container still up (R1.1)."""
        deadline = time.monotonic() + timeout
        if not super().wait_stopped(timeout):
            return False
        while self._names and self._names & self._listed():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.25)
        return True

    def _listed(self) -> set[str]:
        """The Scan Containers the runtime lists, running or not."""
        return set(subprocess.run(  # noqa: S603
            [self.runtime, "ps", "-a", "--filter", "name=valvur-", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=30, check=False).stdout.split())

    @property
    def runtime(self) -> str:
        from .runner import detect_runtime

        if self._runtime is None:
            self._runtime = detect_runtime()
        return self._runtime

    def _kill(self, name: str, confirm_s: float = 15.0) -> None:
        """Stop the Scan Container by name: killing `docker run` would leave it
        running, because the daemon owns it (16.2, 29.0.2). Then wait until the
        runtime no longer lists it: `--rm` removes it after the kill returns, and
        `run` returning is the host's word that the container is gone (R3.5)."""
        subprocess.run([self.runtime, "kill", name],  # noqa: S603
                       capture_output=True, check=False, timeout=30)
        deadline = time.monotonic() + confirm_s
        while name in self._listed() and time.monotonic() < deadline:
            time.sleep(0.25)

    def command(self, scratch: Path, *, network: bool = False, name: str | None = None,
                snapshot_bytes: int = 0) -> list[str]:
        import uuid

        from . import cache, egress, osv_offline, owner
        from .runner import _user_flags, scan_resource_flags

        db, names, osv = cache.trivy_db(), cache.name_index(), osv_offline.directory()
        for directory in (db, names, osv):
            directory.mkdir(parents=True, exist_ok=True)
        name = name or f"valvur-{uuid.uuid4().hex[:16]}"
        # F1.6: on an enforcing host every mount valvur owns is labelled, or the
        # plan, the reports and the cache are denied. The source is not mounted.
        z = ":z" if selinux_enforcing() else ""
        if snapshot_bytes > TMPFS_LIMIT:
            # Past the tmpfs: a volume named for this scan, removed after it.
            landing = ["-v", f"{name}-snapshot:/workspace{z}"]
        else:
            # In memory, gone with the container.
            landing = ["--tmpfs", "/workspace:rw,nosuid,size=512m,mode=1777"]
        return [
            self.runtime, "run", "-i", "--rm", *owner.labels(self.generation),
            "--name", name,
            *_user_flags(self.runtime),
            "--read-only", "--cap-drop=ALL", *scan_resource_flags(self.runtime),
            # Opengrep's one-file binary unpacks 243 MB into $HOME, here, and execs
            # it, on every scan; unpacking it in the image is in tasks.md §8.
            "--tmpfs", "/tmp:rw,exec,nosuid,size=512m",   # noqa: S108 — the container's
            *landing,
            "-v", f"{scratch}:/results{z}",
            "-v", f"{db}:/cache/trivy{z}",
            "-v", f"{names}:/cache/names:ro{z and ',z'}",
            # OSV's offline database (R4.6), read-only like the index.
            "-v", f"{osv}:{osv_offline.MOUNT}:ro{z and ',z'}",
            *egress.Egress(network=network).container_flags(),
            self.image, "python", "-m", "valvur.engine",
        ]

    def run(self, plan: list[Invocation], tar: bytes, scratch: Path,
            on_event: Callable[[dict], None] | None = None,
            budget_s: float | None = None, jobs: int | None = None) -> int:
        import uuid

        write_plan(scratch, plan, budget_s, jobs)
        network = any(i.network for i in plan)
        name = f"valvur-{uuid.uuid4().hex[:16]}"
        self._names.add(name)
        try:
            return self._engine(self.command(scratch, network=network, name=name,
                                             snapshot_bytes=len(tar)), tar, None, on_event,
                                budget_s, kill=lambda: self._kill(name))
        finally:
            if len(tar) > TMPFS_LIMIT:
                subprocess.run([self.runtime, "volume", "rm", "-f",  # noqa: S603
                                f"{name}-snapshot"], capture_output=True, check=False)


#: Set by the image (R8.1): this process is the image's own, so a scan runs its
#: engine here rather than starting a container from inside one.
IN_IMAGE_ENV = "VALVUR_IN_IMAGE"


class ImageRuntime(LocalRuntime):
    """The image as a pipeline step (R8.1, D15): no runtime to start a container
    from, so the engine runs as a process in the image, with the job's cache at
    `/cache`. The image is present by definition, and the shim is the image's own,
    so there is nothing to pull and no second tree to compare. The network is the
    job's: the Scanners run with their offline flags on `offline`, and only a job
    started with no network makes that structural."""

    image = "this image"
    runtime = None

    def __init__(self) -> None:
        from . import cache

        super().__init__(cache=cache.root())

    def image_present(self) -> bool:
        return True

    def boundary(self) -> str:
        return job_boundary()

    def pull_size_mb(self) -> None:
        return None

    def verify_compatible(self) -> None:
        return None

    def build_provenance(self) -> tuple[str | None, str | None]:
        from .compat import IMAGE_INPUTS_FILE

        try:
            own = Path(IMAGE_INPUTS_FILE).read_text(encoding="utf-8").strip() or None
        except OSError:
            own = None
        return own, own

    def db_size_mb(self) -> int | None:
        from .runner import database_size_mb

        return database_size_mb()

    def update_db(self):
        """Trivy's own fetch, run here, into the job's cache (ADR-0012)."""
        from . import cache, locking
        from .adapters.trivy import database_fetch
        from .engine import RESULTS, WORKSPACE, _mapped
        from .invocation import ScannerOutput

        fetch = database_fetch()
        root = cache.root()
        (root / "trivy").mkdir(parents=True, exist_ok=True)
        argv = tuple(_mapped(a, Path(WORKSPACE), Path(RESULTS), root) for a in fetch.argv)
        with locking.held(locking.cache_lock(root), exclusive=True, wait=True):
            try:
                done = subprocess.run(argv, capture_output=True, text=True,  # noqa: S603
                                      timeout=fetch.timeout, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return ScannerOutput(fetch.tool, fetch.version, "", str(exc), 1, argv=argv)
        return ScannerOutput(fetch.tool, fetch.version, done.stdout, done.stderr,
                             done.returncode, argv=argv)


def in_image() -> bool:
    return os.environ.get(IN_IMAGE_ENV) == "1"


def for_scan() -> ContainerRuntime | ImageRuntime:
    """The runtime every scan uses (R3.9): the CLI, MCP, the corpus; inside the image,
    the engine as a process there (R8.1). A function, so a test can hand in
    `LocalRuntime`."""
    return ImageRuntime() if in_image() else ContainerRuntime()
