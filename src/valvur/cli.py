"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .api import scan


def main(argv: list[str] | None = None, *, runner=None) -> int:
    parser = argparse.ArgumentParser(prog="valvur", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="Scan a workspace")
    scan_cmd.add_argument("path", nargs="?", default=".", help="Workspace to scan")
    scan_cmd.add_argument("--profile", default="standard", choices=["quick", "standard", "deep"])

    args = parser.parse_args(argv)

    if runner is None:
        from .runner import ContainerRunner

        runner = ContainerRunner()

    workspace = Path(args.path).resolve()
    run = scan(workspace, runner=runner, profile=args.profile)

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
