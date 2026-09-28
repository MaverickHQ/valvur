"""Command line interface."""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Callable
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

    from . import owner

    def handle(_signum, _frame):
        runtime = None
        with contextlib.suppress(Exception):
            runtime = runner.runtime
        # By label, synchronously (R3.6): this handler runs on the thread that
        # reads the engine, so nothing may wait on that thread here.
        stopped = owner.kill_mine(runtime) if isinstance(runtime, str) else 0
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
        # A cancelled CI job sends SIGTERM (29.0.2); until then only Ctrl-C stopped
        # the fleet and a cancelled job left its containers to the daemon.
        signal.signal(signal.SIGTERM, handle)


def _database_needs_refresh() -> bool:
    from . import updating

    return updating.database_due()


def _name_index_needs_refresh() -> bool:
    from . import updating

    return updating.index_due()


def _refresh_name_index(*, build: bool = False) -> bool:
    from . import updating

    return updating.refresh_index(print, build=build)


def _print_cache(*, clear: bool, prune: bool = False) -> int:
    from . import cache

    root = cache.root()
    print(f"cache: {root}")
    entries = cache.inventory()
    for entry in entries:
        if not entry.present:
            # Absent is not the same thing twice (29.3.2): the KEV copy is a
            # fresher copy of what the image carries; the data is a first-scan
            # fetch.
            means = (cache.KEV_ABSENT_MEANS if entry.name == "kev"
                     else f"the first scan fetches it ({cache.fetch_note(entry.name)})")
            print(f"  {entry.name:<9} absent — {means}")
            continue
        age = f"{entry.age_days:.1f} days old" if entry.age_days is not None else "age unknown"
        notes = [entry.detail] if entry.detail else []
        if entry.name in cache.FETCH_MB:
            notes.append(cache.fetch_note(entry.name))
        if entry.name == "kev":
            notes.append(cache.KEV_PRESENT_MEANS)
        detail = f" — {' · '.join(notes)}" if notes else ""
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
    from . import updating

    return updating.ensure_image(runner, print)


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
    from .text import cut

    print(f"# {cut(match['title'], 100)}")
    return 0


def _refresh_kev() -> None:
    from . import updating

    updating.refresh_kev(print)


def _workspace(value: str) -> str:
    """The `path` argument's type (R1.2): an existing directory, or a usage
    error at parse time. On a shell a relative path means the current
    directory, as it always has; nothing is created for a path that is wrong."""
    import argparse

    from .operations import Refusal, resolve_workspace

    try:
        return str(resolve_workspace(str(Path(value).resolve())))
    except Refusal as refused:
        raise argparse.ArgumentTypeError(str(refused)) from None


def build_parser() -> argparse.ArgumentParser:
    """The nine commands and their arguments — what `valvur --help` prints, held
    byte for byte by `tests/test_cli_help_golden.py` across the move that made
    `main` a table (28.4.2)."""
    parser = argparse.ArgumentParser(prog="valvur", description=__doc__)
    parser = argparse.ArgumentParser(prog="valvur", description=__doc__)
    # One issue template asks people to run this and it did not exist (task 16.4) —
    # the same class as the verification command found in 11.0, and found the same
    # way, by running what the documentation says. Reports the shim's version; the
    # image's is checked against it at scan time (F1.9).
    parser.add_argument(
        "--version", action="version", version=f"valvur {__version__}"
    )
    # Seven commands (D12, R6.5); `explain` and `cache` still parse, for one
    # release, and say what replaced them.
    sub = parser.add_subparsers(
        dest="command", required=True,
        metavar="{scan,update,findings,status,doctor,gate,suppress,init}")
    scan_cmd = sub.add_parser("scan", help="Scan a workspace")
    scan_cmd.add_argument("path", nargs="?", default=".", type=_workspace, help="Workspace to scan")
    scan_cmd.add_argument(
        "--profile", default=_profiles.DEFAULT,
        # The retired 0.1.0rc1 names still resolve, so a script or agent config
        # written against the rc keeps working; they are not advertised.
        choices=[*_profiles.SCANNERS, *_profiles.ALIASES],
        metavar="{offline,full}",
        help="offline (default) runs every Scanner with --network=none. "
        + _profiles.FULL_ADDS,
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
        "three at a time trades speed for not being killed. `jobs` in "
        "~/.config/valvur/config.toml sets the same default for the MCP server.",
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
        "--prune", action="store_true",
        help="Fetch nothing; remove the published image's local tags that are not this "
        "shim's version, and index files the metadata no longer names, each listed "
        "first. Never the database, never this shim's image. `valvur doctor` shows "
        "what is cached.",
    )
    update_cmd.add_argument(
        "--clear", action="store_true",
        help="Fetch nothing; remove the vulnerability database, the package-name index "
        "and the KEV copy. Waits for a running scan. The next scan fetches them again.",
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
    findings_cmd = sub.add_parser(
        "findings", help="The last scan's findings, filtered; one in full by --fingerprint")
    findings_cmd.add_argument("path", nargs="?", default=".", type=_workspace)
    findings_cmd.add_argument("--fingerprint", help="One finding, in full")
    findings_cmd.add_argument("--group", help="A group's id, from findings.json")
    findings_cmd.add_argument("--rule")
    findings_cmd.add_argument("--path", dest="finding_path", metavar="PREFIX",
                              help="Findings under this path, on whole segments")
    findings_cmd.add_argument("--status", choices=["new", "persisting", "regressed"])
    findings_cmd.add_argument("--limit", type=int)
    findings_cmd.add_argument("--include-suppressed", action="store_true")

    explain_cmd = sub.add_parser("explain", help="Now `findings --fingerprint`")
    explain_cmd.add_argument("fingerprint")
    explain_cmd.add_argument("path", nargs="?", default=".", type=_workspace)

    status_cmd = sub.add_parser("status", help="What the last scan actually did")
    status_cmd.add_argument("path", nargs="?", default=".", type=_workspace)

    doctor_cmd = sub.add_parser(
        "doctor",
        help="Check that this machine can scan — runtime, image, database, index, "
        "SELinux, TLS trust, MCP client configuration — and say what to fix",
    )
    doctor_cmd.add_argument("path", nargs="?", default=".", type=_workspace,
                            help="Workspace to check")
    doctor_cmd.add_argument(
        "--network", action="store_true",
        help="Also probe whether the registries a first run and the full profile need "
        "are reachable (one bounded TCP connect per host). Off by default: without it "
        "doctor opens no socket.",
    )
    from .mcp.clients import CLIENTS as _CLIENTS

    doctor_cmd.add_argument(
        "--client", choices=[c.key for c in _CLIENTS], metavar="CLIENT",
        help="Print the file and the snippet for one MCP client, and nothing else: "
        + ", ".join(c.key for c in _CLIENTS),
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
    gate_cmd.add_argument("path", nargs="?", default=".", type=_workspace,
                          help="Workspace that was scanned")
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
        "cache", help="Now `doctor`, `update --prune` and `update --clear`",
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
    suppress_cmd.add_argument("path", nargs="?", default=".", type=_workspace, help="Workspace")
    suppress_cmd.add_argument("--days", type=int, default=90,
                              help="Days until the suppression expires (default: 90)")
    suppress_cmd.add_argument("--reason", default="", help="Why this risk is accepted")

    init_cmd = sub.add_parser(
        "init",
        help="Print each MCP client's block and a starter .security-scan.toml; "
        "writes nothing",
    )
    init_cmd.add_argument("path", nargs="?", default=".", type=_workspace,
                          help="The project")

    return parser


def _cmd_init(args: argparse.Namespace, runner=None) -> int:
    """`init` (D10): prints, never writes."""
    from . import initialize

    print(initialize.render(Path(args.path).resolve()), end="")
    return 0


def _cmd_read(args: argparse.Namespace, runner=None) -> int:
    """`findings`, `explain`, `status`: the same operations the MCP tools call (F9.3)."""
    from . import operations

    if args.command == "explain":
        # One release, then gone (D12): the old name says what replaced it, on
        # stderr, so a script reading stdout still reads the finding.
        print(f"`valvur explain` is now `valvur findings --fingerprint {args.fingerprint}`.",
              file=sys.stderr)
    handler = {
        "findings": operations.findings,
        "explain": operations.findings,
        "status": operations.scan_status,
    }[args.command]
    payload = {"workspace": args.path}
    for field, key in (("status", "status"), ("limit", "limit"),
                       ("fingerprint", "fingerprint"), ("group", "group"),
                       ("rule", "rule"), ("finding_path", "path")):
        if getattr(args, field, None) is not None:
            payload[key] = getattr(args, field)
    if getattr(args, "include_suppressed", False):
        payload["include_suppressed"] = True
    try:
        print(handler(payload))
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc))
        return 1
    return 0


def _cmd_suppress(args: argparse.Namespace, runner=None) -> int:
    """`suppress`: a ready-to-paste block; never writes."""
    return _print_suppression(args)


def _cmd_gate(args: argparse.Namespace, runner=None) -> int:
    """`gate`: exit 1 if the last scan should not ship."""
    import os

    verdict = _gate.evaluate(Path(args.path).resolve(), fail_on=args.fail_on,
                             no_inconclusive=args.no_inconclusive)
    print(_gate.render(verdict, annotations=os.environ.get("GITHUB_ACTIONS") == "true"))
    return verdict.exit_code


def _cmd_cache(args: argparse.Namespace, runner=None) -> int:
    """`cache`, kept through 1.x (D12): `doctor` shows the inventory, and `update
    --prune` and `update --clear` tidy it."""
    print("`valvur cache` is now `valvur doctor` for what is cached, and "
          "`valvur update --prune` or `valvur update --clear` to reclaim it.",
          file=sys.stderr)
    return _print_cache(clear=args.clear, prune=args.prune)


def _cmd_doctor(args: argparse.Namespace, runner=None) -> int:
    """`doctor`: every precondition a scan needs, and `--bundle`."""
    from . import doctor as _doctor

    if getattr(args, "client", None):
        # The snippet a person pastes (29.2.2), from the one table the README
        # renders from, so the two cannot disagree.
        from .mcp import clients as _clients

        entry = _clients.client(args.client)
        print(f"{entry.name} reads {' or '.join(entry.files)}:\n")
        print(_clients.snippet(entry))
        print(f"Then: {entry.after}. ({entry.verified}.)")
        return 0
    workspace = Path(args.path).resolve()
    checks = _doctor.run(workspace, network=args.network)
    print(_doctor.render(checks, workspace))
    if args.bundle is not None:
        archive = _doctor.bundle(workspace, checks, Path(args.bundle))
        print(f"bundle: {archive} — the report above, the versions, the last "
              "run.json; never source, never raw output. Attach it to an issue.")
    return 1 if _doctor.failed(checks) else 0


def _cmd_update(args: argparse.Namespace, runner=None) -> int:
    """`update`: the image, the database, the KEV copy and the index, as the MCP
    tool runs them (`updating.run`); or, with --prune or --clear, tidy the cache."""
    from . import engine_host, updating

    if getattr(args, "prune", False) or getattr(args, "clear", False):
        # What `cache` did (D12): tidy the host cache, and fetch nothing.
        return _print_cache(clear=args.clear, prune=args.prune)
    updated = updating.run(print, runner or engine_host.for_scan(),
                           build_index=args.build_index,
                           if_stale=getattr(args, "if_stale", False))
    return 0 if updated.ok else 1


def _cmd_scan(args: argparse.Namespace, runner=None) -> int:
    """`scan`: the Scan Run, from the terminal."""
    if runner is None:
        from . import engine_host

        # The Scan Container (ADR-0022): the only engine since R3.9.
        runner = engine_host.for_scan()

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

    for path, reason in run.not_read[:8]:
        # What the File Set left out, with why (R1.4, R3.9): a first-party
        # `mypkg/build/` once went unread and unnamed.
        print(f"  · not read: {path} ({reason})")
    if len(run.not_read) > 8:
        print(f"  · not read: {len(run.not_read) - 8} more, listed in run.json")

    print(f"results: {workspace / '.security-scan'}")

    # Findings never fail the run (N3.2). Only a failed Scan Run exits non-zero.
    return 0


#: One command, one function (28.4.2): `main` was 292 lines of parsers and an
#: `if args.command ==` chain, and the only way to find `doctor`'s behaviour was
#: to read past `update`'s. A test holds this table to the parser's subcommands.
COMMANDS: dict[str, Callable[[argparse.Namespace, object], int]] = {
    "findings": _cmd_read,
    "explain": _cmd_read,
    "status": _cmd_read,
    "suppress": _cmd_suppress,
    "gate": _cmd_gate,
    "cache": _cmd_cache,
    "doctor": _cmd_doctor,
    "update": _cmd_update,
    "scan": _cmd_scan,
    "init": _cmd_init,
}


def main(argv: list[str] | None = None, *, runner=None) -> int:
    args = build_parser().parse_args(argv)
    return COMMANDS[args.command](args, runner)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
