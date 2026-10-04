"""What `valvur update` and the `update` MCP tool do (F10.8, ADR-0025, R6.6): the
image if absent, the vulnerability database, the KEV catalog, EPSS scores and the
package-name index, each step said through `say`, so the terminal prints it and the
MCP call sends it as progress, and never on the JSON-RPC channel by accident.

Moved from `cli.py`, where it printed, so both surfaces run one implementation
(F9.3).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import cache, datasets, epss, fileset, locking, name_index, oci, osv_offline, settings
from .enrichment import KEV_URL, KEV_URL_ENV
from .name_index import malicious

Say = Callable[[str], None]


@dataclass
class Updated:
    ok: bool
    #: What was fetched, in the order it was, in the words the reply uses.
    fetched: list[str] = field(default_factory=list)


def database_due() -> bool:
    """Whether the database is absent or past the age a scan refreshes it at (D24),
    decided without touching the network: Trivy stamps `UpdatedAt` in its own
    metadata, the data's build time, which a mirror cannot forward-date."""
    return datasets.DATABASE.due(datasets.DATABASE.age())


def index_due() -> bool:
    """Absent, past the age a scan refreshes it at, or missing an ecosystem this
    version indexes (ADR-0018)."""
    if datasets.NAME_INDEX.due(datasets.NAME_INDEX.age()):
        return True
    directory = cache.name_index()
    return any(not (directory / filename).is_file() for filename in name_index.FILES.values())


def due() -> list[str]:
    """What a scan would fetch or refresh now, by dataset (D52a): what `update
    --if-stale` refreshes. OSV's databases depend on a project's lockfiles, and are
    refreshed for the project `update` is given."""
    wanted = [d.key for d in datasets.ALL if d.key != "osv" and d.due(d.age())]
    if "name_index" not in wanted and index_due():
        wanted.append("name_index")
    return wanted


def refresh_index(say: Say, *, build: bool = False, malicious: bool = True) -> bool:
    """The package-name index into the host cache (ADR-0018): the published one, one
    signed pull, or the registries when it is unreachable or `build` says so. Under
    the cache's exclusive lock. False on failure, having said why; what was on disk
    is still there and still valid."""
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
            if malicious:
                refresh_malicious(say, build=build, fallback=True)
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


def refresh_malicious(say: Say, *, build: bool = False, fallback: bool = False) -> bool:
    """The known-malicious list beside the index (D26, R11.5), with it. It adds to
    what OSV's database already reports, so a failure is said and costs the index
    nothing. `fallback` builds it from its source when it is not published, as
    `valvur update` does until `index.yml` publishes it from `main`; a scan never
    does. The caller holds the cache lock. A refused signature is not caught."""
    try:
        malicious.refresh(cache.name_index(), build=build, fallback=fallback,
                          progress=lambda msg: say(f"  {msg}"))
    except name_index.IndexUnavailable as exc:
        say(f"  malicious list not refreshed ({exc}); "
            + ("the previous list remains in use." if malicious.age_days(cache.name_index())
               is not None else "OSV's database still reports malicious packages."))
        return False
    return True


def ensure_image(runner, say: Say) -> bool:
    """Pull the image if the runtime does not have it, saying what and how much."""
    if runner.image_present():
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


def refresh_epss(say: Say) -> bool:
    """FIRST's EPSS scores into the host cache (D25, R11.4): one public file a day,
    read on every Profile, so no scan sends a CVE identifier anywhere. True when a
    fresh copy was written; a skip is said, and the copy in use, if any, stays."""
    import urllib.error

    url = settings.get("epss_url") or epss.URL
    if not url.startswith(("https://", "http://")):
        say(f"EPSS refresh skipped ({epss.URL_ENV} is not an http(s) URL); "
            "findings rank without EPSS until it is fetched.")
        return False
    try:
        count, day = epss.fetch(url)
    except (urllib.error.URLError, OSError, TimeoutError, epss.NotTheFile) as exc:
        kept = epss.scored()
        say(f"EPSS refresh skipped ({exc}); "
            + (f"the scores of {kept} remain in use." if kept
               else "findings rank without EPSS until it is fetched."))
        return False
    say(f"EPSS refreshed: {count:,} scores (scored {day}).")
    return True


def refresh_osv(say: Say, workspace: Path | None, updated: Updated) -> None:
    """OSV's databases for the lockfiles in `workspace`, when absent or stale (R8.2):
    a pipeline fetches with a network and scans with none, and only a project says
    which ecosystems it needs."""
    if workspace is None:
        return

    records, failed = osv_offline.ensure(fileset.build(workspace).files,
                                         lambda event: say(str(event)), due=datasets.OSV.due)
    updated.fetched += [record["what"] for record in records]
    if failed:
        updated.ok = False


def run(say: Say, runner, *, build_index: bool = False, if_stale: bool = False,
        workspace: Path | None = None) -> Updated:
    """Every step, in order: what `valvur update` and the `update` tool both run;
    with `if_stale`, only the datasets a scan would refresh now (D52a); with
    `workspace`, OSV's databases for its lockfiles as well (R8.2)."""
    wanted = set(due()) if if_stale else {d.key for d in datasets.ALL}
    updated = Updated(ok=True)
    if if_stale and not wanted:
        age = datasets.DATABASE.age()
        say(f"Database is {age or 0:.1f} days old and current enough.")
        refresh_osv(say, workspace, updated)
        if not updated.fetched and updated.ok:
            say("Nothing to do.")
        return updated
    if "database" in wanted:
        # The image first (23.2.4): the database update runs Trivy inside it.
        had_image = runner.image_present()
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
    if "kev" in wanted and refresh_kev(say):
        updated.fetched.append("KEV catalog")
    # Like KEV, it only ranks: a failure is said and costs the update nothing.
    if "epss" in wanted and refresh_epss(say):
        updated.fetched.append("EPSS scores")
    # The index is part of what "updated" means (ADR-0018): a scan without it fails
    # its dependency check loudly, so its failure fails the update, unlike KEV,
    # which has a bundled snapshot to fall back on.
    if "name_index" in wanted:
        if refresh_index(say, build=build_index, malicious="malicious" in wanted):
            updated.fetched.append("package-name index")
        else:
            updated.ok = False
    elif "malicious" in wanted:
        with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
            if refresh_malicious(say, build=build_index, fallback=True):
                updated.fetched.append("malicious list")
    refresh_osv(say, workspace, updated)
    if "database" in wanted:
        say(f"Database ready at {cache.trivy_db()}. Scans now run offline.")
    return updated
