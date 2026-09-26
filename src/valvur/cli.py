"""Command line interface."""

from __future__ import annotations

import argparse
import contextlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import coverage as _coverage
from . import gate as _gate
from . import locking as _locking
from . import profiles as _profiles
from .api import FETCH_ENDED, FETCH_STARTED, scan
from .version import __version__


def _positive(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("--jobs must be at least 1")
    return value


def _positive_seconds(raw: str) -> float:
    value = float(raw)
    if not value > 0:
        raise argparse.ArgumentTypeError("--budget must be a positive number of seconds")
    return value


def _stop_on_interrupt(runner) -> None:
    """Make Ctrl-C mean stop (F1.11, task 16.2).

    Without this the shim exits and the Scanner containers run to completion, because
    the daemon owns their lifecycle — measured, `docker run` forwards nothing useful.
    The developer cancels and the machine keeps working, with the scratch mount
    holding raw output and live credentials (F5.7) alive for the duration.

    Interruption is its OWN outcome. "A Scanner produced no report" is already a
    failure path (Phase 3), so an interrupted scan must not be reportable as a failed
    one — and no Results Folder is written at all, because exiting here happens long
    before results.write().
    """
    import signal

    from .runner import kill_running

    def handle(_signum, _frame):
        runtime = None
        with contextlib.suppress(Exception):
            runtime = runner.runtime
        stopped = kill_running(runtime)
        print(
            f"\n  ! interrupted — stopped {stopped} scanner(s)"
            if stopped
            else "\n  ! interrupted",
            file=sys.stderr,
        )
        print("  ! no results written", file=sys.stderr)
        # 130 is the shell convention for "terminated by SIGINT".
        raise SystemExit(130)

    with contextlib.suppress(ValueError):   # not the main thread; nothing to install
        signal.signal(signal.SIGINT, handle)


def _database_needs_refresh() -> bool:
    """Whether an update is worth doing, decided without touching the network.

    Trivy stamps `NextUpdate` in its own metadata, so being past due is knowable for
    free. That is what makes `--if-stale` cheap enough to run unconditionally in a
    hook or a cron entry: when the database is current it costs one file read.
    """
    from . import cache

    if not cache.db_present():
        return True

    # BOTH signals, because they can disagree and the disagreement is not academic.
    # `NextUpdate` is the database's own opinion of its shelf life; `UpdatedAt` is
    # when the data was actually built. A mirror serving old data with a forward-dated
    # NextUpdate makes the second say 45 days and the first say "not due" — and until
    # 2026-09-05 this used only the first, so `--if-stale` refused to fix the exact
    # condition that makes a scan report `inconclusive`. The command whose purpose is
    # to resolve staleness has to agree with the code that detects it.
    overdue = cache.db_overdue_days()
    if overdue is None or overdue > 0:
        return True
    age = cache.db_age_days()
    return age is None or age > cache.DB_STALE_AFTER_DAYS


def _name_index_needs_refresh() -> bool:
    """Absent, unreadable, past the threshold that makes a scan `inconclusive`, or
    missing an ecosystem this version indexes — a cache built before 23.2.2 has no
    Ruby, PHP or Rust list, and a scan of a Ruby project would fail for want of one.
    Decided from one directory listing, like the database's check above (ADR-0018)."""
    from . import cache, name_index

    age = cache.name_index_age_days()
    if age is None or age > cache.NAME_INDEX_STALE_AFTER_DAYS:
        return True
    directory = cache.name_index()
    return any(not (directory / filename).is_file() for filename in name_index.FILES.values())


def _refresh_name_index(*, build: bool = False) -> bool:
    """Refresh the package-name index into the host cache (ADR-0018).

    From the published index first — one signed pull, seconds (23.2.1) — and from
    the registries themselves when it is unreachable or when `build` says so.
    Under the same exclusive lock as the database: a scan reading the index waits
    for the rename, and never sees half of one. Returns False on failure, having
    said why — whatever was on disk before is still there and still valid.
    """
    from . import cache, locking, name_index, oci

    if build:
        print("Building the package-name index from the registries (PyPI, npm, RubyGems, "
              "Packagist and crates.io; about 550MB the first time, a few MB after)...")
    else:
        print("Fetching the package-name index (about 40MB, published daily; the registries "
              "are walked only if it is unreachable)...")
    try:
        with locking.held(locking.cache_lock(cache.root()), exclusive=True, wait=True):
            name_index.refresh(cache.name_index(), published=not build,
                               progress=lambda msg: print(f"  {msg}"))
    except oci.SignatureInvalid as exc:
        # Not softened into the fallback and not swallowed: a refused signature on a
        # supply-chain artifact is the one failure that must stop the command.
        print(f"Name index refresh REFUSED: {exc}")
        print("To build the index from the registries directly instead: "
              "valvur update --build-index")
        return False
    except name_index.IndexUnavailable as exc:
        print(f"Name index refresh failed: {exc}")
        if cache.name_index_present():
            print("The previous index remains in use; its age is reported in run.json.")
        else:
            print("Without it, the dependency-reality Check cannot verify package "
                  "existence offline and will report that rather than a clean result.")
        return False
    return True


def _print_cache(*, clear: bool, prune: bool = False) -> int:
    from . import cache

    root = cache.root()
    print(f"cache: {root}")
    entries = cache.inventory()
    for entry in entries:
        if not entry.present:
            print(f"  {entry.name:<9} absent")
            continue
        age = f"{entry.age_days:.1f} days old" if entry.age_days is not None else "age unknown"
        detail = f" — {entry.detail}" if entry.detail else ""
        print(f"  {entry.name:<9} {cache.human_size(entry.size):>9}  {age}{detail}")
    print(f"  {'total':<9} {cache.human_size(sum(e.size for e in entries)):>9}")
    if prune:
        _prune_cache(cache)
    if not clear:
        return 0
    removed = cache.clear()
    print(f"cleared: {', '.join(removed) or 'nothing (already empty)'}")
    print("The next scan fetches what it needs; `valvur update` fetches everything now.")
    return 0


def _prune_cache(cache) -> None:
    """`--prune` (28.3.7): what would go is listed before anything goes, and
    without the flag nothing ever does."""
    from . import runner

    try:
        images = cache.local_images(runner.detect_runtime())
    except Exception as exc:   # broad: no runtime is a reason, not a failure
        images = None
        print(f"  no container runtime found ({exc}); images not pruned")
    superseded = cache.superseded_images(images) if images is not None else []
    strays = cache.stray_index_files()
    if not superseded and not strays:
        print("prune: nothing to prune — only this shim's image and the files the index names")
        return
    for reference in superseded:
        print(f"  removing image {reference}")
    for path in strays:
        print(f"  removing file {path}")
    removed_images, removed_files = cache.prune(images)
    print(f"pruned: {len(removed_images)} image{'' if len(removed_images) == 1 else 's'}, "
          f"{len(removed_files)} file{'' if len(removed_files) == 1 else 's'}")


def _ensure_image_for_update(runner) -> bool:
    """Pull the image if the runtime does not have it, saying what and how much."""
    present = getattr(runner, "image_present", None)
    if present is None or present():
        return True
    size = runner.pull_size_mb()
    print(f"Pulling the image {runner.image}{f' (about {size}MB)' if size else ''} — "
          "the first time only; the runtime keeps it...")
    result = runner.pull_image(on_line=lambda line: print(f"  {line}"))
    if result.exit_code != 0:
        print(f"Image pull failed: {(result.stderr or result.stdout).strip()[-300:]}")
        print(f"Fetch it yourself with: {runner.runtime} pull {runner.image}")
        return False
    return True


def _warn_if_name_index_stale(run) -> None:
    """The index's counterpart to the warning above (ADR-0018). Its failure
    direction is the opposite — an old index overstates rather than misses — so it
    gets its own sentence rather than a copy of the database's."""
    from . import cache

    age = run.name_index_age_days
    if age is None or age <= cache.NAME_INDEX_STALE_AFTER_DAYS:
        return
    print(f"  ! the package-name index is {age:.0f} days old. Run `valvur update`.",
          file=sys.stderr)
    print("  ! dependency existence was checked against a list that predates anything "
          "registered since.", file=sys.stderr)


def _warn_if_database_stale(run) -> None:
    """Tell them in the terminal, not only in a file they may never open.

    Until 2026-09-05 the age of the database that decides whether findings exist was
    computed and reported nowhere at all.
    """
    from . import cache

    age = run.db_age_days
    if age is None or age <= cache.DB_STALE_AFTER_DAYS:
        return

    unsuppressed = [f for f in run.findings if not f.suppressed]
    print(f"  ! the vulnerability database is {age:.0f} days old", file=sys.stderr)
    if not unsuppressed:
        print(
            "  ! THIS SCAN FOUND NOTHING, AND THAT IS NOT EVIDENCE THERE IS NOTHING.",
            file=sys.stderr,
        )
        print(
            f"  ! roughly {age:.0f} days of advisories are missing. "
            "Run `valvur update` and rescan.",
            file=sys.stderr,
        )
    else:
        print(
            f"  ! the list is incomplete: roughly {age:.0f} days of advisories are "
            "missing. Run `valvur update`.",
            file=sys.stderr,
        )


def _print_suppression(args) -> int:
    """Print a suppression block. We never write the file (F8.7) — but nobody will
    hand-copy a 32-character hash out of findings.json either, so we print one (F8.8).
    """
    import json
    from datetime import timedelta

    workspace = Path(args.path).resolve()
    findings_file = workspace / ".security-scan" / "findings.json"
    if not findings_file.is_file():
        print(f"No findings.json at {findings_file}. Run `valvur scan` first.")
        return 1

    findings = json.loads(findings_file.read_text(encoding="utf-8"))["findings"]
    match = next((f for f in findings if f["fingerprint"] == args.fingerprint), None)
    if match is None:
        print(f"No finding with fingerprint {args.fingerprint}.")
        print("Fingerprints are listed in .security-scan/findings.json.")
        return 1

    expires = (datetime.now(UTC).date() + timedelta(days=args.days)).isoformat()
    reason = args.reason or "TODO: say why this risk is accepted, for the reviewer."

    print("# Append to .security-scan.toml in your project root, then commit it.")
    print("# valvur does not write this file; a suppression is your decision.")
    print()
    print("[[suppress]]")
    print(f'fingerprint = "{match["fingerprint"]}"')
    print(f'rule = "{match["rule"]}"')
    print(f'path = "{match["path"]}"')
    print(f"expires = {expires}")
    print(f'reason = "{reason}"')
    print()
    print(f"# {match['title'][:100]}")
    return 0


#: Owned by `enrichment`, which does the fetching (27.3.1); named here because
#: `_refresh_kev` below is `valvur update`'s third fetch and a reader of this file
#: should see what it reaches for.
from .enrichment import KEV_URL, KEV_URL_ENV  # noqa: E402 — beside its one user


def _refresh_kev() -> None:
    """Refresh CISA KEV into the host cache.

    The image ships a snapshot as an offline floor, but exploitation data changes
    daily and image releases do not — the ADR-0012 argument applied to a second
    dataset. A CVE added to KEV yesterday should be flagged today.
    """
    import json
    import os
    import urllib.error
    import urllib.request

    from . import cache

    # The third thing `valvur update` fetches, and the third thing an air-gapped site
    # has to mirror (22.B.3): the catalog is one JSON file, so the mirror is any
    # static server holding a copy of it. Plain HTTP is accepted here because the
    # URL is set by an operator, never derived from anything in a Workspace.
    url = os.environ.get(KEV_URL_ENV, "").strip() or KEV_URL
    if not url.startswith(("https://", "http://")):
        print(f"KEV refresh skipped ({KEV_URL_ENV} is not an http(s) URL); "
              "the bundled snapshot remains in use.")
        return
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 — checked above
            raw = json.load(response)
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"KEV refresh skipped ({exc}); the bundled snapshot remains in use.")
        return

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
        "count": len(entries),
        "entries": entries,
    }, separators=(",", ":")), encoding="utf-8")
    print(f"KEV refreshed: {len(entries)} entries (catalog {raw.get('catalogVersion','?')}).")


def main(argv: list[str] | None = None, *, runner=None) -> int:
    parser = argparse.ArgumentParser(prog="valvur", description=__doc__)
    # One issue template asks people to run this and it did not exist (task 16.4) —
    # the same class as the verification command found in 11.0, and found the same
    # way, by running what the documentation says. Reports the shim's version; the
    # image's is checked against it at scan time (F1.9).
    parser.add_argument(
        "--version", action="version", version=f"valvur {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="Scan a workspace")
    scan_cmd.add_argument("path", nargs="?", default=".", help="Workspace to scan")
    scan_cmd.add_argument(
        "--profile", default=_profiles.DEFAULT,
        # The retired 0.1.0rc1 names still resolve, so a script or agent config
        # written against the rc keeps working; they are not advertised.
        choices=[*_profiles.SCANNERS, *_profiles.ALIASES],
        metavar="{offline,full}",
        help="offline (default) runs every Scanner that works with --network=none. "
        "full adds osv-scanner and the dependency-reality Check, which send package "
        "names to public registries.",
    )
    scan_cmd.add_argument(
        "--offline",
        action="store_true",
        help="Force the offline Profile regardless of --profile. Checks needing a "
        "registry report as unverified rather than clean.",
    )
    scan_cmd.add_argument(
        "--budget", type=_positive_seconds, default=None, metavar="SECONDS",
        help="Stop the Scanners past this many seconds: nothing new starts, what is "
        "running is stopped, and the result is reported incomplete with the cut "
        "Scanners named. Default: none here (Ctrl-C is yours); 300 over MCP.",
    )
    scan_cmd.add_argument(
        "--jobs", type=_positive, default=None, metavar="N",
        help="How many Scanners run at once (default: all of them). Docker Desktop's "
        "default memory cannot always start eight containers together; two or "
        "three at a time trades speed for not being killed. VALVUR_JOBS sets the "
        "same default for the MCP server.",
    )

    update_cmd = sub.add_parser(
        "update",
        help="Pull the image if it is not local, and fetch the vulnerability database "
        "and the package-name index into the local cache",
    )
    update_cmd.add_argument(
        "--if-stale",
        action="store_true",
        help="Do nothing unless the database or the index is actually out of date. "
        "Cheap enough to put in a pre-commit hook, a cron entry or CI — the "
        "freshness check needs no network at all.",
    )
    update_cmd.add_argument(
        "--build-index",
        action="store_true",
        help="Build the package-name index from the registries themselves instead of "
        "pulling the published one. Minutes rather than seconds; what the daily "
        "workflow that publishes the index runs, and the fallback when it is "
        "unreachable.",
    )

    # The same operations the MCP tools expose, so the two surfaces cannot drift
    # (F9.3). Both call valvur.operations; there is no second implementation.
    findings_cmd = sub.add_parser("findings", help="List findings from the last scan")
    findings_cmd.add_argument("path", nargs="?", default=".")
    findings_cmd.add_argument("--status", choices=["new", "persisting", "regressed"])
    findings_cmd.add_argument("--limit", type=int)
    findings_cmd.add_argument("--include-suppressed", action="store_true")

    explain_cmd = sub.add_parser("explain", help="Explain one finding in full")
    explain_cmd.add_argument("fingerprint")
    explain_cmd.add_argument("path", nargs="?", default=".")

    status_cmd = sub.add_parser("status", help="What the last scan actually did")
    status_cmd.add_argument("path", nargs="?", default=".")

    doctor_cmd = sub.add_parser(
        "doctor",
        help="Check that this machine can scan — runtime, image, database, index, "
        "SELinux, TLS trust, MCP client configuration — and say what to fix",
    )
    doctor_cmd.add_argument("path", nargs="?", default=".", help="Workspace to check")
    doctor_cmd.add_argument(
        "--network", action="store_true",
        help="Also probe whether the registries a first run and the full profile need "
        "are reachable (one bounded TCP connect per host). Off by default: without it "
        "doctor opens no socket.",
    )
    doctor_cmd.add_argument(
        "--bundle", nargs="?", const=".", default=None, metavar="DIR",
        help="Also write a tarball for an issue into DIR (default: here): this report, "
        "the versions of everything involved, and the last scan's run.json. Never "
        "source, never raw output, never findings.",
    )

    gate_cmd = sub.add_parser(
        "gate",
        help="Exit 1 if the last scan's results should not ship: an incomplete run, a "
        "lapsed suppression, or an active finding at or above --fail-on. For CI.",
    )
    gate_cmd.add_argument("path", nargs="?", default=".", help="Workspace that was scanned")
    gate_cmd.add_argument(
        "--fail-on", default=_gate.DEFAULT_THRESHOLD, choices=_gate.THRESHOLDS,
        help="Lowest severity of an active finding that fails the gate (default: high). "
        "`any` is every active finding — what valvur's own release gate uses.",
    )
    gate_cmd.add_argument(
        "--no-inconclusive", action="store_true",
        help="Also fail an `inconclusive` scan: one whose data was too old to be "
        "evidence, or that never inspected part of the tree.",
    )

    cache_cmd = sub.add_parser(
        "cache", help="What is in the host cache, how old and how large; --clear removes it",
    )
    cache_cmd.add_argument(
        "--clear", action="store_true",
        help="Remove the vulnerability database, the package-name index and the KEV copy. "
        "Waits for a running scan. The next scan fetches them again.",
    )
    cache_cmd.add_argument(
        "--prune", action="store_true",
        help="Remove the published image's local tags that are not this shim's version, "
        "and index files the metadata no longer names — each listed first. Never the "
        "database, never this shim's image. Waits for a running scan.",
    )

    suppress_cmd = sub.add_parser(
        "suppress",
        help="Print a ready-to-paste suppression block for a finding (never writes)",
    )
    suppress_cmd.add_argument("fingerprint", help="Fingerprint from findings.json")
    suppress_cmd.add_argument("path", nargs="?", default=".", help="Workspace")
    suppress_cmd.add_argument("--days", type=int, default=90,
                              help="Days until the suppression expires (default: 90)")
    suppress_cmd.add_argument("--reason", default="", help="Why this risk is accepted")

    args = parser.parse_args(argv)

    if args.command in {"findings", "explain", "status"}:
        from . import operations

        handler = {
            "findings": operations.list_findings,
            "explain": operations.explain_finding,
            "status": operations.scan_status,
        }[args.command]
        payload = {"workspace": args.path}
        for field in ("status", "limit", "fingerprint"):
            if getattr(args, field, None) is not None:
                payload[field] = getattr(args, field)
        if getattr(args, "include_suppressed", False):
            payload["include_suppressed"] = True
        try:
            print(handler(payload))
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc))
            return 1
        return 0

    if args.command == "suppress":
        return _print_suppression(args)

    if args.command == "gate":
        import os

        verdict = _gate.evaluate(Path(args.path).resolve(), fail_on=args.fail_on,
                                 no_inconclusive=args.no_inconclusive)
        print(_gate.render(verdict, annotations=os.environ.get("GITHUB_ACTIONS") == "true"))
        return verdict.exit_code

    if args.command == "cache":
        return _print_cache(clear=args.clear, prune=args.prune)

    if args.command == "doctor":
        from . import doctor as _doctor

        workspace = Path(args.path).resolve()
        checks = _doctor.run(workspace, network=args.network)
        print(_doctor.render(checks, workspace))
        if args.bundle is not None:
            archive = _doctor.bundle(workspace, checks, Path(args.bundle))
            print(f"bundle: {archive} — the report above, the versions, the last "
                  "run.json; never source, never raw output. Attach it to an issue.")
        return 1 if _doctor.failed(checks) else 0

    if args.command == "update":
        from . import cache
        from .runner import ContainerRunner

        if getattr(args, "if_stale", False):
            database_due = _database_needs_refresh()
            index_due = _name_index_needs_refresh()
            if not database_due and not index_due:
                age = cache.db_age_days()
                print(f"Database is {age:.1f} days old and current enough. Nothing to do.")
                return 0
            if not database_due:
                # The database is fine and only the index is due: do that one thing.
                # A 116MB download to refresh a 4MB list is not what --if-stale means.
                return 0 if _refresh_name_index(build=args.build_index) else 1

        runner = runner or ContainerRunner()
        # The image first (23.2.4): the database update runs Trivy *inside* it, so
        # a missing image was being pulled here anyway — silently, under Trivy's
        # name, and again on the first scan if `update` was skipped. Said, sized
        # from the registry when it can be, and streamed to the terminal.
        if not _ensure_image_for_update(runner):
            return 1
        # 116 MB compressed, measured 2026-09-05 against the published artifact. The
        # help text said 1.2GB for months — that is the UNCOMPRESSED size on disk,
        # and quoting it discouraged exactly the update this tool depends on.
        print("Fetching the vulnerability database (about 116MB)...")
        result = runner.update_db()
        if result.exit_code != 0:
            print(f"Update failed: {result.stderr.strip()[-300:]}")
            return 1
        from . import cache

        _refresh_kev()
        # The index is part of what "updated" means now (ADR-0018): a scan without
        # it fails its dependency check loudly. So its failure fails the command —
        # unlike KEV, which has a bundled snapshot to fall back on.
        index_ok = _refresh_name_index(build=args.build_index)
        print(f"Database ready at {cache.trivy_db()}. Scans now run offline.")
        return 0 if index_ok else 1

    if runner is None:
        from .runner import ContainerRunner

        runner = ContainerRunner()

    _stop_on_interrupt(runner)

    from .runner import unsupported_platform_warning

    if warning := unsupported_platform_warning():
        print(warning, file=sys.stderr)

    workspace = Path(args.path).resolve()
    profile = _profiles.OFFLINE if getattr(args, "offline", False) else args.profile

    def progress(message: str) -> None:
        # The CLI prints its own per-Scanner lines already; what is worth a line here
        # is a first run fetching — the image (23.2.4), the database and the index
        # (24.1) — which otherwise looks like a hang.
        if message.startswith(FETCH_STARTED + FETCH_ENDED):
            print(f"  {message}", file=sys.stderr)

    try:
        run = scan(workspace, runner=runner, profile=profile, on_progress=progress,
                   jobs=args.jobs, budget_s=args.budget)
    except _locking.Busy as busy:
        # An expected condition, not a crash. A traceback here would read as a bug in
        # valvur when it is a second scan doing exactly what it should.
        print(f"  ! {busy}", file=sys.stderr)
        return 1

    for failure in run.failures:
        print(f"  ! {failure.tool} did not complete: {failure.reason}")
    if run.failures:
        print("  ! this scan is INCOMPLETE")

    # Task 14.2 — decided 2026-09-05: valvur does NOT update the database by itself,
    # on any Profile. Three reasons, in order of weight.
    #
    # It is a 1.2GB download. Starting one inside a scan the user asked to be fast
    # is hostile, and doing it silently is worse.
    #
    # It would make the Profiles disagree for a reason unrelated to coverage. If
    # `full` refreshed and `offline` could not, the two would scan different data
    # and the equivalence asserted in Phase 11 cycle 3 would break — not because
    # coverage differs, but because we introduced a difference.
    #
    # And updating on the user's behalf is the same move as fixing on their behalf,
    # which section 4 refuses. So: say it, loudly, and let them decide.
    #
    # All three are about STALENESS. An ABSENT database or index is fetched by the
    # scan itself, and said (24.1, `api._ensure_data`): without them there is no
    # scan at all, and the primary path has no shell to run `valvur update` in.
    _warn_if_database_stale(run)
    _warn_if_name_index_stale(run)

    # Active first, and counted separately (task 19.C.1). This line used to read
    # `findings: 4 finding(s)` for a scan whose four Findings were all accepted risks
    # recorded in a committed file — indistinguishable from four live problems, to the
    # reader most likely to act on it.
    parts = [f"{len(run.active)} active"]
    if run.suppressed:
        parts.append(f"{len(run.suppressed)} suppressed")
    if run.coverage_notes:
        parts.append(f"{len(run.coverage_notes)} not covered")
    print(f"{run.status}: {', '.join(parts)}")

    for note in run.coverage_notes:
        # Named in the terminal, not only in a file. This is the sentence that says
        # the scan could not help with part of the repository, and a reader who never
        # opens SUMMARY.md would otherwise see a bare "clean". A licence statement
        # is the other kind of note (23.5.5): could not read, rather than did not.
        label = "not checked" if note.rule in _coverage.DOUBT_RULES else "could not read"
        print(f"  · {label}: {note.title.replace(' were not checked for existence', '')}")

    print(f"results: {workspace / '.security-scan'}")

    # Findings never fail the run (N3.2). Only a failed Scan Run exits non-zero.
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
