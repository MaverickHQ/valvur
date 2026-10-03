"""What a scan fetches before its Scanners start (24.1, ADR-0025): the image, the
vulnerability database, the package-name index, the malicious list, KEV, EPSS and
OSV's offline databases, each when absent or past the age the datasets table gives
(D52a). Each fetch is announced as an event and recorded under `network.fetched`:
data comes in, nothing of the Workspace leaves. `fetch = never` turns it all off.
"""

from __future__ import annotations

import dataclasses
import time
from typing import TYPE_CHECKING

from . import cache as _cache
from . import datasets as _datasets
from . import egress as _egress
from . import events as _events
from .fleet import stop_if_cancelled
from .scanner_run import ScannerRun

if TYPE_CHECKING:
    from .engine_host import Runtime


def ensure_image(runner: Runtime, on_progress) -> dict | None:
    """Pull the image when absent (23.2.4). Returns the fetch record, or None."""
    from .runner import ImagePullFailed

    if runner.image_present():
        return None
    size = runner.pull_size_mb()
    if on_progress is not None:
        on_progress(_events.fetch_started("image", name=runner.image, size_mb=size,
                                          age_days=None))
    started = time.monotonic()
    result = runner.pull_image()
    if result.exit_code != 0:
        detail = (result.stderr.strip() or result.stdout.strip() or "(no output)")[-400:]
        raise ImagePullFailed(
            f"The image {runner.image} is not available locally and could not be pulled.\n"
            f"The runtime said:\n  {detail}\n"
            f"Fetch it yourself with: {runner.runtime} pull {runner.image}"
        )
    seconds = time.monotonic() - started
    if on_progress is not None:
        on_progress(_events.fetch_ended("image", seconds=seconds))
    return fetch_record("image", runner.image, size, seconds)


def fetch_record(what: str, source: str, size_mb: int | None, seconds: float,
                  **extra) -> dict:
    """One fetch, for the record (28.0.4): what arrived, from where, how large as
    the source stated it, how long. `seconds` rounded to a tenth like every other
    duration `run.json` carries."""
    return {"what": what, "source": source, "size_mb": size_mb,
            "seconds": round(seconds, 1), **extra}


def ensure_data(runner: Runtime, on_progress, *, workspace=None, adapters=(),
                 context=None) -> tuple[list[dict], dict[str, str]]:
    """The vulnerability database, the package-name index and OSV's offline
    databases, when absent (24.1) or stale (ADR-0025, R6.6).

    Task 14.2 decided valvur never refreshes on its own; 24.1 fetched absent data,
    because without it there is no scan at all; ADR-0025 refreshes stale data too,
    because the primary path, an agent over MCP, has no terminal, and a database a
    week old left every nil result `inconclusive` with no way out (the review's N3).
    Each fetch is announced and recorded under `network.fetched`: data comes in,
    nothing of the Workspace leaves. `fetch = never` turns all of it off.

    Runs BEFORE `scan` takes the shared cache lock: both fetches take it
    exclusively, and a shared lock already held on another descriptor of the same
    file in this process would deadlock them. Returns what could not be fetched, by
    the Scanner it costs, so that Scanner's failure says the fetch was tried and why
    it failed rather than only naming `valvur update`.
    """
    from . import settings

    if not runner.fetches:
        return [], {}      # a process runtime has no image to fill and no fetch to run
    if settings.fetch() == settings.NEVER:
        # Air-gapped (ADR-0025): nothing is fetched, absent or stale. An absent
        # database fails its Scanner with the reason; a stale one makes a nil
        # result `inconclusive`, and the verdict names the setting.
        return [], {}
    say = on_progress if on_progress is not None else (lambda _: None)
    fetched: list[dict] = []
    unfetched: dict[str, str] = {}

    _ensure_database(runner, say, fetched, unfetched)
    stop_if_cancelled(runner, "during the first run's fetches")
    _ensure_index(say, fetched, unfetched)
    stop_if_cancelled(runner, "during the first run's fetches")
    _ensure_malicious(say, fetched)
    _ensure_kev(say, fetched)
    _ensure_epss(say, fetched)
    if workspace is not None and any(not a.network for a in adapters
                                     if a.name == "osv-scanner"):
        stop_if_cancelled(runner, "during the first run's fetches")
        _ensure_osv(workspace, say, fetched, unfetched, context)
    return fetched, unfetched


def _ensure_database(runner: Runtime, say, fetched: list[dict],
                     unfetched: dict[str, str]) -> None:
    """The vulnerability database, absent or past a week: Trivy's own fetch, in the
    image. A failure costs Trivy alone, with the reason."""
    db_age = _datasets.DATABASE.age()
    if _datasets.DATABASE.due(db_age):
        # Absent since 24.1; stale since ADR-0025 (R6.6), reversing 14.2: an agent has
        # no terminal, and a week-old database left it `inconclusive` with no way out.
        db_size = runner.db_size_mb()
        say(_events.fetch_started("database", age_days=db_age, size_mb=db_size))
        started = time.monotonic()
        result = runner.update_db()
        if result.exit_code != 0:
            detail = (result.stderr.strip() or result.stdout.strip() or "(no output)")[-300:]
            unfetched["trivy"] = f"the vulnerability database could not be fetched: {detail}"
            say(_events.fetch_ended("database", ok=False, detail=detail))
        else:
            seconds = time.monotonic() - started
            say(_events.fetch_ended("database", seconds=seconds))
            fetched.append(fetch_record(
                "vulnerability database",
                _egress.db_repository() or _egress.DEFAULT_DB_REPOSITORY, db_size, seconds))


def _ensure_index(say, fetched: list[dict], unfetched: dict[str, str]) -> None:
    """The package-name index, absent or past two days, pulled as published and
    never built inside a scan. A failure costs dependency-reality, with the reason."""
    index_age = _datasets.NAME_INDEX.age()
    # Past two days, not thirty (D24): the index is published daily, and a real
    # package published since the last pull read as hallucinated, at high.
    if _datasets.NAME_INDEX.due(index_age):
        from . import locking, name_index

        index_size = name_index.published.published_size_mb()
        say(_events.fetch_started("index", age_days=index_age, size_mb=index_size))
        started = time.monotonic()
        try:
            with locking.held(locking.cache_lock(_cache.root()), exclusive=True, wait=True):
                # `oci.SignatureInvalid` is deliberately not caught: a refused
                # signature on a supply-chain artifact stops the scan (23.2.1).
                metadata = name_index.build.refresh(_cache.name_index(), fallback=False)
        except name_index.IndexUnavailable as exc:
            unfetched["dependency-reality"] = (
                f"the package-name index could not be fetched: {exc}")
            say(_events.fetch_ended("index", ok=False, detail=str(exc)))
        else:
            seconds = time.monotonic() - started
            say(_events.fetch_ended("index", seconds=seconds))
            fetched.append(fetch_record(
                "package-name index", name_index.published.repository(), index_size, seconds,
                signature=_index_signature(metadata)))


def _ensure_malicious(say, fetched: list[dict]) -> None:
    """The known-malicious list absent or past two days (D24, D26, R11.5), pulled as
    published and never built inside a scan. A failure keeps the list in use and
    costs no Scanner: OSV-Scanner still reports what its database knows."""
    from . import locking, updating
    from .name_index import malicious

    if not _cache.name_index_present():
        return                       # nothing to put it beside; the index said why
    age = _datasets.MALICIOUS.age()
    if not _datasets.MALICIOUS.due(age):
        return
    say(_events.fetch_started("malicious", age_days=age))
    started = time.monotonic()
    with locking.held(locking.cache_lock(_cache.root()), exclusive=True, wait=True):
        refreshed = updating.refresh_malicious(lambda line: say(_events.note(line)))
    seconds = time.monotonic() - started
    if not refreshed:
        say(_events.fetch_ended("malicious", ok=False))
        return
    say(_events.fetch_ended("malicious", seconds=seconds))
    from . import settings

    fetched.append(fetch_record(
        "malicious list", settings.get("name_index_url") or malicious.reference(), None,
        seconds))


def _ensure_kev(say, fetched: list[dict]) -> None:
    """KEV past two days (D24, R11.3): a scan never refreshed it, so a machine that
    had not run `valvur update` ranked with the image's snapshot for ever. A failed
    refresh keeps the catalog in use, which says why; it costs no Scanner, since
    KEV ranks findings and finds none."""
    from . import enrichment, updating

    age = _datasets.KEV.age()
    if not _datasets.KEV.due(age):
        return
    say(_events.fetch_started("kev", age_days=age))
    started = time.monotonic()
    if updating.refresh_kev(lambda line: say(_events.fetch_ended("kev", said=line))):
        from . import settings

        fetched.append(fetch_record(
            "KEV catalog", settings.get("kev_url") or enrichment.KEV_URL, None,
            time.monotonic() - started))


def _ensure_epss(say, fetched: list[dict]) -> None:
    """EPSS absent or past two days (D24, D25, R11.4), as KEV: a failure keeps the
    scores in use, or ranks without EPSS, and costs no Scanner."""
    from . import epss, settings, updating

    age = _datasets.EPSS.age()
    if not _datasets.EPSS.due(age):
        return
    say(_events.fetch_started("epss", age_days=age))
    started = time.monotonic()
    if updating.refresh_epss(lambda line: say(_events.fetch_ended("epss", said=line))):
        fetched.append(fetch_record(
            "EPSS scores", settings.get("epss_url") or epss.URL,
            max(1, round(epss.path().stat().st_size / 1_000_000)),
            time.monotonic() - started))


def _ensure_osv(workspace, say, fetched: list[dict], unfetched: dict[str, str],
                context=None) -> None:
    """OSV's offline database for each ecosystem the File Set holds a lockfile for,
    when absent (R4.6, 24.1): announced, recorded, and a failure costs OSV-Scanner
    alone, with the reason."""
    from . import fileset, osv_offline
    from .refusal import Refusal

    try:
        files = context.files if context is not None else fileset.build(workspace).files
    except Refusal:
        return                       # the scan refuses the walk itself, with the reason
    records, failed = osv_offline.ensure(files, say, due=_datasets.OSV.due)
    fetched += records
    if failed:
        unfetched["osv-scanner"] = ("the OSV offline database could not be fetched: "
                                    + "; ".join(failed))


def _index_signature(metadata: object) -> str:
    """The verdict the pull recorded, from any ecosystem's entry — they are one
    artifact, verified once (23.2.1)."""
    ecosystems = metadata.get("ecosystems") if isinstance(metadata, dict) else None
    for entry in (ecosystems or {}).values():
        published = entry.get("published") if isinstance(entry, dict) else None
        if isinstance(published, dict) and published.get("signature"):
            return str(published["signature"])
    return "not recorded"


def say_why_unfetched(scanners: list[ScannerRun], unfetched: dict[str, str]) -> list[ScannerRun]:
    """A Scanner that failed for want of data this run tried to fetch says so, ahead
    of the runner's own refusal — which names `valvur update`, still the right fix
    for a person, but not the whole story once a fetch has been tried (24.1)."""
    return [
        dataclasses.replace(s, reason=f"{unfetched[s.tool]}. {s.reason}")
        if s.failed and s.tool in unfetched else s
        for s in scanners
    ]
