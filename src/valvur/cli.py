"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from .api import scan


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
    scan_cmd.add_argument("--profile", default="standard", choices=["quick", "standard", "deep"])
    scan_cmd.add_argument(
        "--offline",
        action="store_true",
        help="Never touch the network. Equivalent to --profile quick for network purposes; "
        "checks needing a registry report as unverified rather than clean.",
    )

    sub.add_parser("update", help="Fetch the vulnerability database into the local cache")

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
        from .runner import ContainerRunner

        print("Fetching the vulnerability database (about 1.2GB, once)...")
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

    workspace = Path(args.path).resolve()
    profile = "quick" if getattr(args, "offline", False) else args.profile
    run = scan(workspace, runner=runner, profile=profile)

    for failure in run.failures:
        print(f"  ! {failure.tool} did not complete: {failure.reason}")
    if run.failures:
        print("  ! this scan is INCOMPLETE")
    print(f"{run.status}: {len(run.findings)} finding(s)")
    print(f"results: {workspace / '.security-scan'}")

    # Findings never fail the run (N3.2). Only a failed Scan Run exits non-zero.
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
