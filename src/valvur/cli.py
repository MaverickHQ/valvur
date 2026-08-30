"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .api import scan


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

    args = parser.parse_args(argv)

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
