"""Task 24.1 — a first `scan` fetches what is absent, and says so.

Measured 2026-09-13 against the published 0.2.0: over MCP, with an empty cache, the
first `scan` finished `complete: False` — Trivy and the dependency-reality Check both
failed, each naming `valvur update`, a shell command the agent has no tool for and
the README's snippet never mentions. Task 14.2's rule that valvur never updates by
itself was about STALENESS. Without the database and the index there is no scan at
all, and 23.2.4 already fetches the absent image from inside `scan`. So: absent →
fetched here, announced on `scan_status` the way the image is; stale → untouched, the
warning stands and the user decides.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from conftest import LegacyDispatch, write_name_index
from fake_registry import FakeRegistry

from valvur import api, cache, locking, name_index, oci
from valvur.adapters import GitleaksAdapter, TrivyAdapter
from valvur.runner import ScannerOutput

# ------------------------------------------------------------------ fixtures


@pytest.fixture
def host_cache(tmp_path, monkeypatch):
    """An empty host cache — no database, no index — with the lock file beside them,
    as on a machine that has just done `pip install valvur`."""
    root = tmp_path / "cache"
    monkeypatch.setattr(cache, "root", lambda: root)
    monkeypatch.setattr(cache, "trivy_db", lambda: root / "trivy")
    monkeypatch.setattr(cache, "name_index", lambda: root / "names")
    monkeypatch.setenv("VALVUR_NAME_INDEX", str(root / "names"))
    monkeypatch.delenv(name_index.reader.MIRROR_ENV, raising=False)
    monkeypatch.delenv(name_index.reader.INDEX_REPOSITORY_ENV, raising=False)
    return root


def _write_db(root: Path, *, age_days: float = 0.5) -> None:
    """What Trivy leaves in the cache: the database and its metadata."""
    db = root / "trivy" / "db"
    db.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    (db / "trivy.db").write_bytes(b"bolt")
    (db / "metadata.json").write_text(json.dumps({
        "Version": 2,
        "UpdatedAt": (now - timedelta(days=age_days)).isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(days=age_days - 1)).isoformat().replace("+00:00", "Z"),
    }))


def _write_index(root: Path, *, built_at: str | None = None) -> Path:
    return write_name_index(root / "names", pip=["requests"], npm=["react"], gem=["rack"],
                            composer=["monolog/monolog"], cargo=["serde"], built_at=built_at)


TRIVY_REFUSAL = (
    "Trivy vulnerability database not present. Fetch it once with:\n"
    "  valvur update\n"
    "Scans then run fully offline against the cached database."
)


class _Runner(LegacyDispatch):
    """A runtime that has the image and can fetch the database, recording what it
    was asked. `update_db` does what Trivy does: the database appears in the cache."""

    image = "ghcr.io/maverickhq/valvur:9.9.9"
    runtime = "/usr/local/bin/docker"

    def __init__(self, root: Path, *, db_exit: int = 0, db_size: int | None = 118):
        self.root = root
        self.db_exit = db_exit
        self.db_size = db_size
        self.calls: list[str] = []

    def image_present(self) -> bool:
        self.calls.append("inspect")
        return True

    def db_size_mb(self):
        self.calls.append("size")
        return self.db_size

    def update_db(self) -> ScannerOutput:
        self.calls.append("db")
        if self.db_exit == 0:
            _write_db(self.root)
        return ScannerOutput(
            "trivy-db", "", "",
            "FATAL failed to download vulnerability DB: dial tcp: lookup ghcr.io: no such host",
            self.db_exit,
        )

    def run_gitleaks(self, workspace: Path) -> ScannerOutput:
        self.calls.append("gitleaks")
        return ScannerOutput("gitleaks", "8.30.1", "[]", "", 0)

    def run_trivy(self, workspace: Path) -> ScannerOutput:
        self.calls.append("trivy")
        if not cache.db_present():
            raise RuntimeError(TRIVY_REFUSAL)     # the real runner's refusal, verbatim
        return ScannerOutput("trivy", "0.74.0", '{"Results": []}', "", 0)


def _scan(workspace, runner, **kwargs):
    said: list[str] = []
    run = api.scan(workspace, runner=runner, adapters=[GitleaksAdapter(), TrivyAdapter()],
                   on_progress=said.append, **kwargs)
    return run, said


# ------------------------------------------------------- absent: fetched, and said


def test_an_absent_database_is_fetched_by_the_first_scan_and_the_line_says_so(
    workspace, host_cache
):
    _write_index(host_cache)
    runner = _Runner(host_cache)

    run, said = _scan(workspace, runner)

    assert runner.calls == ["inspect", "size", "db", "gitleaks", "trivy"] or \
        runner.calls == ["inspect", "size", "db", "trivy", "gitleaks"]
    assert said[0] == "fetching the vulnerability database (118MB) — the first run only"
    assert said[1].startswith("database fetched (")
    assert not run.failures
    assert cache.db_present()


def test_a_size_the_registry_cannot_state_is_left_out_rather_than_invented(
    workspace, host_cache
):
    _write_index(host_cache)

    _, said = _scan(workspace, _Runner(host_cache, db_size=None))

    assert said[0] == "fetching the vulnerability database — the first run only"


def test_an_absent_index_is_pulled_by_the_first_scan_under_the_exclusive_lock(
    workspace, host_cache, monkeypatch
):
    """The same pull `valvur update` does (23.2.1), under the same lock: a scan in
    another process reading the index waits for the rename and never sees half of
    one. Proven by asking for the shared lock while the fetch runs."""
    _write_db(host_cache)
    source = write_name_index(host_cache.parent / "source", pip=["requests", "flask"],
                              npm=["react"], gem=["rack"], composer=["monolog/monolog"],
                              cargo=["serde"], built_at="2026-09-12T02:00:00Z")
    monkeypatch.setattr(name_index.reader, "MINIMUM_NAMES",
                        dict.fromkeys(name_index.reader.FILES, 1))
    monkeypatch.setattr(oci.shutil, "which", lambda _: None)      # no cosign here
    held_shared_during_fetch: list[bool] = []
    real_fetch = name_index.published.fetch_published

    def fetch_and_probe(*args, **kwargs):
        # flock is per open file description, and `held` opens the file afresh, so
        # a second holder in this process conflicts exactly as another process would.
        try:
            with locking.held(locking.cache_lock(cache.root()), exclusive=False, wait=False):
                held_shared_during_fetch.append(True)
        except locking.Busy:
            held_shared_during_fetch.append(False)
        return real_fetch(*args, **kwargs)

    monkeypatch.setattr(name_index.published, "fetch_published", fetch_and_probe)
    with FakeRegistry() as registry:
        monkeypatch.setenv(name_index.reader.INDEX_INSECURE_ENV, "1")
        registry.push_index("acme/idx", "latest", source)
        monkeypatch.setenv(name_index.reader.INDEX_REPOSITORY_ENV, registry.reference("acme/idx"))

        run, said = _scan(workspace, _Runner(host_cache))

    assert held_shared_during_fetch == [False], "the fetch ran without the exclusive lock"
    assert (host_cache / "names" / "npm.txt").read_text() == "react\n"
    assert cache.name_index_present()
    assert said[0].startswith("fetching the package-name index")
    assert "— the first run only" in said[0]
    assert said[1].startswith("index fetched (")
    assert not run.failures


def test_the_index_size_comes_from_the_registry_and_a_static_mirror_has_none(
    monkeypatch, tmp_path
):
    source = write_name_index(tmp_path / "source", pip=["requests"], npm=["react"],
                              gem=["rack"], composer=["monolog/monolog"], cargo=["serde"])
    monkeypatch.delenv(name_index.reader.MIRROR_ENV, raising=False)
    with FakeRegistry() as registry:
        monkeypatch.setenv(name_index.reader.INDEX_INSECURE_ENV, "1")
        registry.push_index("acme/idx", "latest", source)
        monkeypatch.setenv(name_index.reader.INDEX_REPOSITORY_ENV, registry.reference("acme/idx"))

        assert name_index.published.published_size_mb() == 1     # five tiny gzip layers, rounded up

        monkeypatch.setenv(name_index.reader.MIRROR_ENV, "http://mirror.internal/idx")
        assert name_index.published.published_size_mb() is None


def test_the_database_size_comes_from_the_repository_trivy_will_use(monkeypatch, tmp_path):
    """A plain artifact — one manifest, layers, no platforms — sized like the image
    is (23.2.4). The operator's mirror and its insecure switch are honoured, since
    the size is asked of the registry the download will come from."""
    from valvur import runner as runner_module
    from valvur.runner import ContainerRunner

    source = write_name_index(tmp_path / "db", pip=["requests"], npm=["react"],
                              gem=["rack"], composer=["monolog/monolog"], cargo=["serde"])
    with FakeRegistry() as registry:
        registry.push_index("aquasec/trivy-db", "2", source)   # any layered artifact
        monkeypatch.setenv(runner_module.DB_REPOSITORY_ENV,
                           registry.reference("aquasec/trivy-db", "2"))
        monkeypatch.setenv(runner_module.DB_INSECURE_ENV, "1")

        assert ContainerRunner(image="x/y:1", runtime="/bin/false").db_size_mb() == 1

    monkeypatch.setenv(runner_module.DB_REPOSITORY_ENV, "registry.invalid/nowhere/db:2")
    assert ContainerRunner(image="x/y:1", runtime="/bin/false").db_size_mb() is None

    # Loopback is insecure whatever the switch says, so the switch itself is pinned
    # by what reaches the client rather than by a registry the suite cannot run.
    asked: list[tuple[str, bool]] = []
    monkeypatch.setattr(oci, "image_size",
                        lambda reference, *, insecure=False: asked.append((reference, insecure)))
    ContainerRunner(image="x/y:1", runtime="/bin/false").db_size_mb()
    monkeypatch.delenv(runner_module.DB_INSECURE_ENV)
    ContainerRunner(image="x/y:1", runtime="/bin/false").db_size_mb()
    monkeypatch.setenv(name_index.reader.INDEX_INSECURE_ENV, "1")
    monkeypatch.setenv(name_index.reader.INDEX_REPOSITORY_ENV, "registry.internal/mirror/idx")
    monkeypatch.delenv(name_index.reader.MIRROR_ENV, raising=False)
    name_index.published.published_size_mb()
    assert asked == [("registry.invalid/nowhere/db:2", True),
                     ("registry.invalid/nowhere/db:2", False),
                     ("registry.internal/mirror/idx", True)]


def test_both_absent_means_image_then_database_then_index_then_the_scanners(
    workspace, host_cache, monkeypatch
):
    """The database is fetched by Trivy INSIDE the image, so the image comes first;
    the index needs neither. All three before `verify_compatible`, which inspects an
    image and passes vacuously on a missing one (23.2.4)."""
    order: list[str] = []

    class Runner(_Runner):
        def image_present(self):
            order.append("inspect")
            return False

        def pull_size_mb(self):
            return 240

        def pull_image(self, on_line=None):
            order.append("pull")
            return ScannerOutput("pull", "", "", "", 0)

        def update_db(self):
            order.append("db")
            return super().update_db()

        def verify_compatible(self):
            order.append("compat")
            raise RuntimeError("stop here")

    monkeypatch.setattr(name_index.build, "refresh",
                        lambda directory, **k: order.append("index") or {})

    with pytest.raises(RuntimeError, match="stop here"):
        _scan(workspace, Runner(host_cache))

    assert order == ["inspect", "pull", "db", "index", "compat"]


def test_a_cancel_during_the_fetches_is_honoured_at_the_next_boundary(
    workspace, host_cache, monkeypatch
):
    """26.0.2 (c). A cancel that lands during a first run's fetches — up to ~45s of
    image, database and index — set the runner's flag and was honoured only at the
    fleet, after every fetch had finished. Now it is honoured before the next one:
    the database fetch flips the flag here, and the index is never fetched."""
    order: list[str] = []

    class Runner(_Runner):
        cancelled = False

        def update_db(self):
            order.append("db")
            result = super().update_db()
            self.cancelled = True                # `kill()` landed mid-fetch
            return result

        def kill(self):
            self.cancelled = True
            return 0

    monkeypatch.setattr(name_index.build, "refresh",
                        lambda directory, **k: order.append("index") or {})

    with pytest.raises(api.ScanCancelled, match="fetches"):
        _scan(workspace, Runner(host_cache))

    assert order == ["db"], order
    assert not (workspace / ".security-scan" / "run.json").exists()


# ------------------------------------------------------ stale: untouched (14.2)


def test_a_stale_database_is_never_refreshed_by_a_scan(workspace, host_cache):
    """Decided in 14.2, and 24.1 keeps it: a download inside a scan the user asked to
    be fast is hostile; refreshing on `full` alone would make the Profiles scan
    different data; and refreshing on the user's behalf is the same move as fixing
    on their behalf, which section 4 refuses. Absence is the one exception, and this
    is the line between them."""
    _write_db(host_cache, age_days=45)
    _write_index(host_cache)
    runner = _Runner(host_cache)

    run, said = _scan(workspace, runner)

    assert "db" not in runner.calls and "size" not in runner.calls
    # The fleet's own announcements (29.0.4) are not fetches; what must be absent
    # is any fetch line, so only the Scanners' ends are counted here.
    ends = [line for line in said if not line.startswith(("fleet: ", "workspace: "))
            and not line.endswith(": started")]
    assert sorted(line.split(":")[0] for line in ends) == ["gitleaks", "trivy"]
    assert all(": ok (" in line for line in ends), said
    assert run.db_age_days is not None and run.db_age_days > cache.DB_STALE_AFTER_DAYS
    assert not run.failures


def test_a_stale_index_is_never_refreshed_by_a_scan(workspace, host_cache, monkeypatch):
    _write_db(host_cache)
    _write_index(host_cache, built_at="2026-01-01T00:00:00Z")
    monkeypatch.setattr(name_index.build, "refresh",
                        lambda *a, **k: pytest.fail("the index was refreshed"))

    run, said = _scan(workspace, _Runner(host_cache))

    assert not any(line.startswith("fetching") for line in said)
    assert run.name_index_age_days is not None
    assert run.name_index_age_days > cache.NAME_INDEX_STALE_AFTER_DAYS


def test_a_runner_without_the_ability_is_left_alone(workspace, host_cache):
    """The fake runners in the suite have no `update_db`; a scan through them must
    not reach for a registry — the rule `_ensure_image` applies to `image_present`."""
    from conftest import FakeRunner

    said: list[str] = []
    api.scan(workspace, runner=FakeRunner(), adapters=[GitleaksAdapter()],
             on_progress=said.append)

    assert not cache.db_present()
    ends = [line for line in said if not line.startswith(("fleet: ", "workspace: "))
            and not line.endswith(": started")]
    assert len(ends) == 1 and ends[0].startswith("gitleaks: ok (")


# -------------------------------------------- could not be fetched: said, not hidden


def test_a_database_that_could_not_be_fetched_costs_trivy_and_the_reason_names_why(
    workspace, host_cache
):
    """One broken fetch must not cost the other Scanners (F2.5): the run is
    incomplete, and Trivy's failure says the fetch was tried and what went wrong —
    not only `valvur update`, as though nothing had been."""
    _write_index(host_cache)
    runner = _Runner(host_cache, db_exit=1)

    run, said = _scan(workspace, runner)

    assert said[1] == ("database not fetched: FATAL failed to download vulnerability DB: "
                       "dial tcp: lookup ghcr.io: no such host")
    assert run.failures
    [failure] = run.failures
    assert failure.tool == "trivy"
    assert failure.reason.startswith("the vulnerability database could not be fetched: "
                                     "FATAL failed to download")
    assert "valvur update" in failure.reason
    assert [s.tool for s in run.scanners if s.ok] == ["gitleaks"]


def test_an_index_that_could_not_be_fetched_is_said_and_the_check_is_told(
    workspace, host_cache, monkeypatch
):
    _write_db(host_cache)

    def unavailable(directory, **kwargs):
        raise name_index.reader.IndexUnavailable("ghcr.io: connection refused")

    monkeypatch.setattr(name_index.build, "refresh", unavailable)

    run, said = _scan(workspace, _Runner(host_cache))

    assert said[1] == "index not fetched: ghcr.io: connection refused"
    assert not run.failures, "no dependency-reality adapter here; the failure is only recorded"


def test_an_index_fetch_inside_a_scan_never_walks_the_registries(
    workspace, host_cache, monkeypatch
):
    """`valvur update` falls back to walking the five registries — seven minutes and
    700MB (23.2.1). That is the download 14.2 called hostile inside a scan, and it
    stays out of one: the Check fails naming `valvur update`, which walks."""
    _write_db(host_cache)
    monkeypatch.setattr(name_index.published, "fetch_published",
                        lambda *a, **k: (_ for _ in ()).throw(
                            name_index.reader.IndexUnavailable("ghcr.io: connection refused")))
    monkeypatch.setattr(name_index.build, "walk",
                        lambda *a, **k: pytest.fail("walked the registries inside a scan"))

    _, said = _scan(workspace, _Runner(host_cache))

    assert said[1] == "index not fetched: ghcr.io: connection refused"
    assert not cache.name_index_present()


def test_a_refused_signature_stops_the_scan(workspace, host_cache, monkeypatch):
    """Never softened (23.2.1): an index whose signature cosign refused is not used,
    and the scan does not proceed to report against whatever else it might find."""
    _write_db(host_cache)

    def refused(directory, **kwargs):
        raise oci.SignatureInvalid("no matching signatures")

    monkeypatch.setattr(name_index.build, "refresh", refused)

    with pytest.raises(oci.SignatureInvalid):
        _scan(workspace, _Runner(host_cache))


def test_the_index_fetch_failure_reaches_the_dependency_reality_reason(host_cache):
    """The annotation itself, on the Scanner it costs — without a container."""
    from valvur.provenance import ScannerRun

    annotated = api._say_why_unfetched(
        [ScannerRun("dependency-reality", ok=False, reason="Package-name index not present."),
         ScannerRun("trivy", ok=False, reason="exited 1"),
         ScannerRun("gitleaks", ok=True)],
        {"dependency-reality": "the package-name index could not be fetched: refused"},
    )

    assert [s.reason for s in annotated] == [
        "the package-name index could not be fetched: refused. Package-name index not present.",
        "exited 1", "",
    ]


# ------------------------------------------------------------- the MCP surface


def test_scan_status_says_what_is_being_fetched_while_it_is(tmp_path, monkeypatch):
    """The line an agent reads on the first run: not "starting" for a minute, but
    which fetch, its size, and that this is the first run only — each in turn, each
    gone once it is over (10.2 claim 4, extended to the data)."""
    from valvur.mcp import jobs
    from valvur.operations import scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    def work(workspace, profile, progress):
        progress("pulling ghcr.io/maverickhq/valvur:0.2.0 (243MB) — the first run only; "
                 "the runtime keeps it")
        progress("image pulled (30s)")
        progress("fetching the vulnerability database (118MB) — the first run only")
        time.sleep(0.6)
        progress("database fetched (25s)")
        progress("fetching the package-name index (34MB) — the first run only")
        time.sleep(0.6)
        progress("index fetched (8s)")
        progress("trivy: ok")
        time.sleep(0.6)
        return "done"

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)
    database = scan_status({"workspace": str(tmp_path)})
    time.sleep(0.6)
    index = scan_status({"workspace": str(tmp_path)})
    time.sleep(0.6)
    after = scan_status({"workspace": str(tmp_path)})
    jobs.reset()

    assert "Now: fetching the vulnerability database (118MB) — the first run only." in database
    assert "Completed so far: image pulled (30s)" in database
    assert "Now: fetching the package-name index (34MB) — the first run only." in index
    assert "Completed so far: image pulled (30s), database fetched (25s)" in index
    assert "Now:" not in after
    assert "database fetched (25s), index fetched (8s), trivy: ok" in after


def test_a_failed_fetch_is_not_a_now_line_but_stays_in_the_record(tmp_path, monkeypatch):
    from valvur.mcp import jobs
    from valvur.operations import scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    def work(workspace, profile, progress):
        progress("fetching the vulnerability database (118MB) — the first run only")
        progress("database not fetched: FATAL no such host")
        time.sleep(0.5)
        return "done"

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)
    status = scan_status({"workspace": str(tmp_path)})
    jobs.reset()

    assert "Now:" not in status
    assert "Completed so far: database not fetched: FATAL no such host" in status


# -------------------------------------------------------------------- the CLI


def test_the_cli_prints_each_fetch_to_stderr(workspace, host_cache, capsys, monkeypatch):
    from conftest import FakeRunner

    from valvur import cli

    class Runner(FakeRunner):
        image = _Runner.image
        image_present = _Runner.image_present
        db_size_mb = _Runner.db_size_mb
        update_db = _Runner.update_db
        root = host_cache
        db_exit = 0
        db_size = 118
        calls: ClassVar[list[str]] = []

    monkeypatch.setattr(name_index.build, "refresh",
                        lambda directory, **k: _write_index(host_cache))

    assert cli.main(["scan", str(workspace), "--offline"], runner=Runner()) == 0

    err = capsys.readouterr().err
    assert "  fetching the vulnerability database (118MB) — the first run only\n" in err
    assert "  database fetched (" in err
    assert "  fetching the package-name index" in err
    assert "  index fetched (" in err


# ------------------------------------------ the fetches are in the record (28.0.4)


def _written(workspace: Path) -> tuple[dict, dict, str]:
    import json

    folder = workspace / ".security-scan"
    return (json.loads((folder / "run.json").read_text()),
            json.loads((folder / "findings.json").read_text()),
            (folder / "SUMMARY.md").read_text())


def test_a_fetched_database_is_in_the_record(workspace, host_cache):
    """28.0.4. A first run on `offline` pulls the image, the database and the index
    — announced live on `scan_status` and, until this, absent from `run.json`,
    which said `network.used: false`, `what_left_the_machine: nothing` and listed
    no fetch. True in the sentence's sense (nothing of the workspace left) and
    unable to tell a first run from a steady-state one. Now each fetch is a record:
    what, from where, how large, how long."""
    _write_index(host_cache)
    run, _ = _scan(workspace, _Runner(host_cache))

    [fetched] = run.fetched
    assert fetched["what"] == "vulnerability database"
    assert fetched["source"] == "mirror.gcr.io/aquasec/trivy-db:2", "the host Trivy was sent to"
    assert fetched["size_mb"] == 118
    assert isinstance(fetched["seconds"], float)
    provenance, findings, summary = _written(workspace)
    assert provenance["network"]["fetched"] == run.fetched
    assert provenance["network"]["used"] is False, "the Profile's own network is still offline"
    assert findings["fetched"] == run.fetched
    assert "fetched the vulnerability database from `mirror.gcr.io/aquasec/trivy-db:2`" in summary
    assert "**This was a first run.**" in summary


def test_a_fetched_index_records_the_signature_it_was_pulled_under(
    workspace, host_cache, monkeypatch
):
    _write_db(host_cache)
    monkeypatch.setattr(oci.shutil, "which", lambda _: None)
    def refresh(directory, **k):
        _write_index(directory)
        return {"ecosystems": {"pip": {"published": {
            "repository": "ghcr.io/maverickhq/valvur-index", "digest": "sha256:abc",
            "signature": "not verified: cosign is not installed"}}}}

    monkeypatch.setattr(name_index.build, "refresh", refresh)

    run, _ = _scan(workspace, _Runner(host_cache))

    [fetched] = run.fetched
    assert fetched["what"] == "package-name index"
    assert fetched["source"] == name_index.published.repository()
    assert fetched["signature"].startswith("not verified: cosign is not installed")


def test_all_three_fetches_are_recorded_in_the_order_they_happen(
    workspace, host_cache, monkeypatch
):
    class Runner(_Runner):
        def image_present(self):
            return False

        def pull_size_mb(self):
            return 240

        def pull_image(self, on_line=None):
            return ScannerOutput("pull", "", "", "", 0)

    def refresh(directory, **k):
        _write_index(directory)
        return {"ecosystems": {}}

    monkeypatch.setattr(name_index.build, "refresh", refresh)

    run, _ = _scan(workspace, Runner(host_cache))

    assert [f["what"] for f in run.fetched] == [
        "image", "vulnerability database", "package-name index"]
    assert run.fetched[0]["source"] == "ghcr.io/maverickhq/valvur:9.9.9"
    assert run.fetched[0]["size_mb"] == 240


def test_a_steady_state_run_records_no_fetch(workspace, host_cache):
    """The common case says so explicitly — an empty list, not an absent key — so
    a reader can tell "nothing fetched" from "a valvur that did not record."""
    _write_db(host_cache)
    _write_index(host_cache)

    run, said = _scan(workspace, _Runner(host_cache))

    assert run.fetched == []
    provenance, findings, summary = _written(workspace)
    assert provenance["network"]["fetched"] == []
    assert findings["fetched"] == []
    assert "fetched" not in summary.lower()
    assert not any(line.startswith("fetching") for line in said)


def test_a_failed_fetch_is_not_recorded_as_one(workspace, host_cache):
    """The record is of what arrived. A fetch that failed is already on the
    Scanner it cost (24.1's reason line); it is not also a fetch."""
    _write_index(host_cache)

    run, _ = _scan(workspace, _Runner(host_cache, db_exit=1))

    assert run.fetched == []
    assert any("could not be fetched" in s.reason for s in run.scanners if s.failed)
