"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import profiles as _profiles
from .api import scan


def _database_needs_refresh() -> bool:
    """Whether an update is worth doing, decided without touching the network.

    Trivy stamps `NextUpdate` in its own metadata, so being past due is knowable for
    free. That is what makes `--if-stale` cheap enough to run unconditionally in a
    hook or a cron entry: when the database is current it costs one file read.
    """
    from . import cache

    if not cache.db_present():
        return True
    overdue = cache.db_overdue_days()
    return overdue is None or overdue > 0


def _warn_if_database_stale(run) -> None:
    """Tell them in the terminal, not only in a file they may never open.

    Until 2026-09-05 the age of the database that decides whether findings exist was
    computed and reported nowhere at all.
    """
    from . import cache

    age = getattr(run, "db_age_days", None)
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


def _refresh_kev() -> None:
    """Refresh CISA KEV into the host cache.

    The image ships a snapshot as an offline floor, but exploitation data changes
    daily and image releases do not — the ADR-0012 argument applied to a second
    dataset. A CVE added to KEV yesterday should be flagged today.
    """
    import json
    import urllib.error
    import urllib.request

    from . import cache

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
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

    update_cmd = sub.add_parser(
        "update", help="Fetch the vulnerability database into the local cache"
    )
    update_cmd.add_argument(
        "--if-stale",
        action="store_true",
        help="Do nothing unless the database is actually out of date. Cheap enough "
        "to put in a pre-commit hook, a cron entry or CI — the freshness check needs "
        "no network at all.",
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

    if args.command == "update":
        from . import cache
        from .runner import ContainerRunner

        if getattr(args, "if_stale", False) and not _database_needs_refresh():
            age = cache.db_age_days()
            print(f"Database is {age:.1f} days old and current enough. Nothing to do.")
            return 0

        # 116 MB compressed, measured 2026-09-05 against the published artifact. The
        # help text said 1.2GB for months — that is the UNCOMPRESSED size on disk,
        # and quoting it discouraged exactly the update this tool depends on.
        print("Fetching the vulnerability database (about 116MB)...")
        result = (runner or ContainerRunner()).update_db()
        if result.exit_code != 0:
            print(f"Update failed: {result.stderr.strip()[-300:]}")
            return 1
        from . import cache

        _refresh_kev()
        print(f"Database ready at {cache.trivy_db()}. Scans now run offline.")
        return 0

    if runner is None:
        from .runner import ContainerRunner

        runner = ContainerRunner()

    from .runner import unsupported_platform_warning

    if warning := unsupported_platform_warning():
        print(warning, file=sys.stderr)

    workspace = Path(args.path).resolve()
    profile = _profiles.OFFLINE if getattr(args, "offline", False) else args.profile
    run = scan(workspace, runner=runner, profile=profile)

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
    _warn_if_database_stale(run)

    print(f"{run.status}: {len(run.findings)} finding(s)")
    print(f"results: {workspace / '.security-scan'}")

    # Findings never fail the run (N3.2). Only a failed Scan Run exits non-zero.
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
