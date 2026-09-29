"""What `valvur update` and the `update` MCP tool do (F10.8, ADR-0025, R6.6): the
image if absent, the vulnerability database, the KEV catalog and the package-name
index, each step said through `say`, so the terminal prints it and the MCP call
sends it as progress, and never on the JSON-RPC channel by accident.

Moved from `cli.py`, where it printed, so both surfaces run one implementation
(F9.3).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .enrichment import KEV_URL, KEV_URL_ENV

Say = Callable[[str], None]


@dataclass
class Updated:
    ok: bool
    #: What was fetched, in the order it was, in the words the reply uses.
    fetched: list[str] = field(default_factory=list)


def database_due() -> bool:
    """Whether an update is worth doing, decided without touching the network.

    Trivy stamps `NextUpdate` in its own metadata, so being past due is knowable for
    free, and `UpdatedAt` says when the data was built: both, because a mirror can
    serve old data with a forward-dated `NextUpdate` (2026-09-05)."""
    from . import cache

    if not cache.db_present():
        return True
    overdue = cache.db_overdue_days()
    if overdue is None or overdue > 0:
        return True
    age = cache.db_age_days()
    return age is None or age > cache.DB_STALE_AFTER_DAYS


def index_due() -> bool:
    """Absent, unreadable, past the threshold that makes a scan `inconclusive`, or
    missing an ecosystem this version indexes (ADR-0018)."""
    from . import cache, name_index

    age = cache.name_index_age_days()
    if age is None or age > cache.NAME_INDEX_STALE_AFTER_DAYS:
        return True
    directory = cache.name_index()
    return any(not (directory / filename).is_file() for filename in name_index.FILES.values())


def refresh_index(say: Say, *, build: bool = False) -> bool:
    """The package-name index into the host cache (ADR-0018): the published one, one
    signed pull, or the registries when it is unreachable or `build` says so. Under
    the cache's exclusive lock. False on failure, having said why; what was on disk
    is still there and still valid."""
    from . import cache, locking, name_index, oci

    if build:
        say("Building the package-name index from the registries (PyPI, npm, RubyGems, "
            "Packagist and crates.io; about 550MB the first time, a few MB after)...")
    else:
        say("Fetching the package-name index (about 40MB, published daily; the registries "
            "are walked only if it is unreachable)...")
    try:
        with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
            name_index.build.refresh(cache.name_index(), published=not build,
                                     progress=lambda msg: say(f"  {msg}"))
    except oci.SignatureInvalid as exc:
        # Not softened into the fallback and not swallowed: a refused signature on a
        # supply-chain artifact is the one failure that must stop the command.
        say(f"Name index refresh REFUSED: {exc}")
        say("To build the index from the registries directly instead: "
            "valvur update --build-index")
        return False
    except name_index.IndexUnavailable as exc:
        say(f"Name index refresh failed: {exc}")
        if cache.name_index_present():
            say("The previous index remains in use; its age is reported in run.json.")
        else:
            say("Without it, the dependency-reality Check cannot verify package "
                "existence offline and will report that rather than a clean result.")
        return False
    return True


def ensure_image(runner, say: Say) -> bool:
    """Pull the image if the runtime does not have it, saying what and how much."""
    present = getattr(runner, "image_present", None)
    if present is None or present():
        return True
    size = runner.pull_size_mb()
    say(f"Pulling the image {runner.image}{f' (about {size}MB)' if size else ''} — "
        "the first time only; the runtime keeps it...")
    result = runner.pull_image(on_line=lambda line: say(f"  {line}"))
    if result.exit_code != 0:
        say(f"Image pull failed: {(result.stderr or result.stdout).strip()[-300:]}")
        say(f"Fetch it yourself with: {runner.runtime} pull {runner.image}")
        return False
    return True


def refresh_kev(say: Say) -> bool:
    """CISA KEV into the host cache. The image ships a snapshot as an offline floor;
    exploitation data changes daily and image releases do not (ADR-0012). True when
    a fresh catalog was written; a skip is said, and the snapshot stays."""
    import urllib.error
    import urllib.request

    # One JSON file, so an air-gapped mirror is any static server holding a copy
    # (22.B.3). Plain HTTP is accepted because the URL is set by an operator,
    # never derived from anything in a Workspace.
    from . import cache, settings

    url = settings.get("kev_url") or KEV_URL
    if not url.startswith(("https://", "http://")):
        say(f"KEV refresh skipped ({KEV_URL_ENV} is not an http(s) URL); "
            "the bundled snapshot remains in use.")
        return False
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 — checked above
            raw = json.load(response)
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        say(f"KEV refresh skipped ({exc}); the bundled snapshot remains in use.")
        return False

    entries = {
        v["cveID"]: {"r": v.get("knownRansomwareCampaignUse") == "Known",
                     "d": v.get("dateAdded", "")}
        for v in raw.get("vulnerabilities", [])
    }
    root = cache.root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "kev.json").write_text(json.dumps({
        "source": url,
        "catalogVersion": raw.get("catalogVersion", ""),
        # The catalog's own date, which is its age (D23, F6.12): the file's time is
        # when it was fetched, not what it knows.
        "dateReleased": raw.get("dateReleased", ""),
        "count": len(entries),
        "entries": entries,
    }, separators=(",", ":")), encoding="utf-8")
    say(f"KEV refreshed: {len(entries)} entries (catalog {raw.get('catalogVersion', '?')}).")
    return True


def refresh_osv(say: Say, workspace: Path | None, updated: Updated) -> None:
    """OSV's databases for the lockfiles in `workspace`, when absent or stale (R8.2):
    a pipeline fetches with a network and scans with none, and only a project says
    which ecosystems it needs."""
    if workspace is None:
        return
    from . import fileset, osv_offline

    records, failed = osv_offline.ensure(fileset.build(workspace).files, say)
    updated.fetched += [record["what"] for record in records]
    if failed:
        updated.ok = False


def run(say: Say, runner, *, build_index: bool = False, if_stale: bool = False,
        workspace: Path | None = None) -> Updated:
    """Every step, in order: what `valvur update` and the `update` tool both run;
    with `workspace`, OSV's databases for its lockfiles as well (R8.2)."""
    from . import cache

    if if_stale:
        database, index = database_due(), index_due()
        if not database and not index:
            age = cache.db_age_days()
            say(f"Database is {age:.1f} days old and current enough.")
            updated = Updated(ok=True)
            refresh_osv(say, workspace, updated)
            if not updated.fetched and updated.ok:
                say("Nothing to do.")
            return updated
        if not database:
            # The database is fine and only the index is due: do that one thing.
            # A 116MB download to refresh a 4MB list is not what --if-stale means.
            ok = refresh_index(say, build=build_index)
            updated = Updated(ok=ok, fetched=["package-name index"] if ok else [])
            refresh_osv(say, workspace, updated)
            return updated

    updated = Updated(ok=True)
    # The image first (23.2.4): the database update runs Trivy inside it.
    had_image = getattr(runner, "image_present", lambda: True)()
    if not ensure_image(runner, say):
        return Updated(ok=False)
    if not had_image:
        updated.fetched.append("image")
    # 116 MB compressed, measured 2026-09-05 against the published artifact.
    say("Fetching the vulnerability database (about 116MB)...")
    result = runner.update_db()
    if result.exit_code != 0:
        say(f"Update failed: {result.stderr.strip()[-300:]}")
        updated.ok = False
        return updated
    updated.fetched.append("vulnerability database")
    if refresh_kev(say):
        updated.fetched.append("KEV catalog")
    # The index is part of what "updated" means (ADR-0018): a scan without it fails
    # its dependency check loudly, so its failure fails the update, unlike KEV,
    # which has a bundled snapshot to fall back on.
    if refresh_index(say, build=build_index):
        updated.fetched.append("package-name index")
    else:
        updated.ok = False
    refresh_osv(say, workspace, updated)
    say(f"Database ready at {cache.trivy_db()}. Scans now run offline.")
    return updated
