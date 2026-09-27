#!/usr/bin/env python3
"""The acceptance harness (task R2.2): scan each acceptance repository, judge it
against its `expected.toml`, report.

    python3 scripts/acceptance.py [--set DIR] [--only N] [--generate] [--out DIR]

Every phase from R2 on is judged by this, on this Mac and on Linux (tasks.md §4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: An unexpected finding at these severities fails a repository (R2.2).
BLOCKING = frozenset({"high", "critical"})


@dataclass
class Verdict:
    ok: bool = True
    missing: list[str] = field(default_factory=list)
    #: Findings no `must` names, as "rule at path (severity)".
    unexpected: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)
    #: Expectations a later task delivers, while that task is open.
    pending: list[str] = field(default_factory=list)
    #: Finding paths under a `must_not` prefix.
    forbidden: list[str] = field(default_factory=list)
    incomplete: bool = False


def ticked(tasks_text: str) -> set[str]:
    """The task ids `tasks.md` has ticked."""
    return set(re.findall(r"^- \[[xX]\] \*\*(R\d+\.\d+)\*\*", tasks_text, re.M))


def _matches(rule: str, finding: dict) -> bool:
    found = str(finding.get("rule", ""))
    return found == rule or found.endswith(rule)


def judge(results: Path, expected: dict, tasks_text: str) -> Verdict:
    """What a scan wrote into `results`, against what the repository expects."""
    import json

    findings = json.loads((results / "findings.json").read_text())["findings"]
    verdict = Verdict()
    musts = expected.get("must", [])

    def named(finding: dict) -> bool:
        return any(_matches(m["rule"], finding)
                   and (m.get("path") is None or finding.get("path") == m.get("path"))
                   for m in musts)

    done = ticked(tasks_text)
    for must in musts:
        path = must.get("path")
        found = any(_matches(must["rule"], f) and (path is None or f.get("path") == path)
                    for f in findings)
        until = must.get("until")
        if until and until not in done:
            if not found:
                verdict.pending.append(f"{must['rule']} at {path or 'any path'} "
                                       f"(until {until})")
            continue
        if not found:
            verdict.missing.append(f"{must['rule']} at {path or 'any path'}")
    for forbid in expected.get("must_not", []):
        prefix = forbid["path_prefix"]
        verdict.forbidden += [f["path"] for f in findings
                              if str(f.get("path", "")).startswith(prefix)]
    run = json.loads((results / "run.json").read_text())
    verdict.incomplete = bool(expected.get("run", {}).get("complete")) and not run.get(
        "complete")
    allowed = expected.get("run", {}).get("unexpected") == "allowed"
    for finding in findings:
        if finding.get("suppressed") or named(finding):
            continue
        line = f"{finding.get('rule')} at {finding.get('path')} ({finding.get('severity')})"
        verdict.unexpected.append(line)
        if not allowed and str(finding.get("severity")) in BLOCKING:
            verdict.blocking.append(line)
    verdict.ok = not (verdict.missing or verdict.blocking or verdict.forbidden
                      or verdict.incomplete)
    return verdict


@dataclass
class RepoResult:
    name: str
    verdict: Verdict
    seconds: float
    containers_after: int

    @property
    def ok(self) -> bool:
        return self.verdict.ok and self.containers_after == 0


def _cli_scan(workspace: Path) -> None:
    """`valvur scan <workspace>` through the CLI, as a user runs it."""
    import subprocess
    import sys

    subprocess.run([sys.executable, "-c",  # noqa: S603 — this interpreter, the CLI
                    "from valvur.cli import main; raise SystemExit(main())",
                    "scan", str(workspace)], check=False, capture_output=True)


def _containers_alive() -> int:
    """How many `valvur-` containers the runtime still lists."""
    import subprocess

    out = subprocess.run(["docker", "ps", "--filter", "name=valvur-", "--format",
                          "{{.Names}}"], capture_output=True, text=True, check=False)
    return len(out.stdout.split())


def run_repo(root: Path, *, scan=_cli_scan, containers=_containers_alive,
             tasks_text: str | None = None) -> RepoResult:
    """Scan one acceptance repository and judge it (R2.2)."""
    import time
    import tomllib

    if tasks_text is None:
        tasks_text = (Path(__file__).resolve().parent.parent
                      / ".kiro/specs/valvur/tasks.md").read_text()
    started = time.monotonic()
    scan(root)
    seconds = time.monotonic() - started
    expected = tomllib.loads((root / "expected.toml").read_text())
    verdict = judge(root / ".security-scan", expected, tasks_text)
    return RepoResult(root.name, verdict, round(seconds, 1), containers())


def render_markdown(results: list[RepoResult], platform: dict) -> str:
    """One row per repository: verdict, seconds, containers left, then the counts of
    missing, pending and blocking-unexpected findings."""
    lines = [f"Platform: {platform.get('platform', 'unknown')}; host swap in use "
             f"{platform.get('swap_gb', '?')} GB.", "",
             "| repository | verdict | seconds | containers left | missing | pending "
             "| blocking |", "|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.name} | {'pass' if r.ok else 'FAIL'} | {r.seconds} | "
                     f"{r.containers_after} | {len(r.verdict.missing)} | "
                     f"{len(r.verdict.pending)} | {len(r.verdict.blocking)} |")
    return "\n".join(lines) + "\n"


def to_json(results: list[RepoResult], platform: dict) -> dict:
    return {"platform": platform, "repositories": [
        {"name": r.name, "ok": r.ok, "seconds": r.seconds,
         "containers_after": r.containers_after, "missing": r.verdict.missing,
         "pending": r.verdict.pending, "blocking": r.verdict.blocking,
         "forbidden": r.verdict.forbidden, "incomplete": r.verdict.incomplete,
         "unexpected": r.verdict.unexpected} for r in results]}


def platform_info() -> dict:
    """The machine the run measured: the OS, and host swap, which decides whether a
    Mac time threshold counts (D17)."""
    import platform
    import re as _re
    import subprocess

    info: dict = {"platform": f"{platform.system()} {platform.release()} "
                              f"{platform.machine()}", "swap_gb": None}
    if platform.system() == "Darwin":
        out = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True,
                             text=True, check=False).stdout
        used = _re.search(r"used = ([\d.]+)M", out)
        info["swap_gb"] = round(float(used.group(1)) / 1024, 1) if used else None
    elif Path("/proc/meminfo").exists():
        mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text()
                   .splitlines() if ":" in line)
        total = int(mem.get("SwapTotal", "0 kB").split()[0])
        free = int(mem.get("SwapFree", "0 kB").split()[0])
        info["swap_gb"] = round((total - free) / 2**20, 1)
    return info


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import os
    import sys

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    home = Path(os.environ.get("HOME", "~")) / ".cache" / "valvur-build"
    parser.add_argument("--set", type=Path, default=home / "acceptance",
                        help="where the repositories are (built there with --generate)")
    parser.add_argument("--only", help="one repository, by number or name")
    parser.add_argument("--generate", action="store_true", help="build the set first")
    parser.add_argument("--out", type=Path, default=home / "acceptance-report")
    parser.add_argument("--probes", action="store_true",
                        help="also stop a scan four ways and count what is left (R2.3)")
    parser.add_argument("--agent", action="store_true",
                        help="also ask `claude -p` to scan each repository (R2.4; costs "
                             "money, capped at $25 for the build)")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(Path(__file__).resolve().parent / "acceptance"))
    import generate  # type: ignore[import-not-found]

    repos = (generate.build(args.set, args.only) if args.generate else
             {p.name: p for p in sorted(args.set.iterdir())
              if p.is_dir() and not p.name.startswith(".")
              and (args.only is None or args.only in (p.name, p.name.split("-", 1)[0]))})
    results = [run_repo(root) for root in repos.values()]
    info = platform_info()
    args.out.mkdir(parents=True, exist_ok=True)
    report = to_json(results, info)
    table = render_markdown(results, info)
    probe_results = []
    if args.probes:
        import probes  # type: ignore[import-not-found]

        ticked_now = ticked((Path(__file__).resolve().parent.parent
                             / ".kiro/specs/valvur/tasks.md").read_text())
        target = probes.workspace(args.set)
        probe_results = [probes.probe(kind, target) for kind in probes.KINDS]
        report["probes"] = [{**vars(p), "ok": p.ok} for p in probe_results]
        table += "\n| probe | verdict | left after stop | left at next start | seconds |\n"
        table += "|---|---|---|---|---|\n"
        for p in probe_results:
            pending = p.until is not None and p.until not in ticked_now and not p.ok
            word = f"pending ({p.until})" if pending else ("pass" if p.ok else "FAIL")
            table += (f"| {p.kind} | {word} | {p.containers_left} | "
                      f"{p.left_at_next_start} | {p.seconds} |\n")
        probe_results = [p for p in probe_results
                         if not (p.until and p.until not in ticked_now)]
    if args.agent:
        import agent  # type: ignore[import-not-found]

        tasks_text = (Path(__file__).resolve().parent.parent
                      / ".kiro/specs/valvur/tasks.md").read_text()
        table += "\n| agent run | named all | turns | cost (USD) | seconds | left |\n"
        table += "|---|---|---|---|---|---|\n"
        report["agent"] = []
        for root in repos.values():
            scored = agent.run(root, tasks_text)
            if scored is None:
                table += f"| {root.name} | skipped: the ${agent.CAP_USD:g} cap is spent | | | | |\n"
                continue
            scored.containers_left = _containers_alive()
            report["agent"].append({"name": root.name, **vars(scored)})
            named = "yes" if scored.named_all else "no: " + ", ".join(scored.unnamed)
            table += (f"| {root.name} | {named} | {scored.turns} | {scored.cost_usd} | "
                      f"{scored.seconds} | {scored.containers_left} |\n")
        table += f"\nAgent scoring spent so far in this build: ${agent.spent():.2f}.\n"
    (args.out / "report.json").write_text(json.dumps(report, indent=2))
    (args.out / "report.md").write_text(table)
    print(table)
    return 0 if all(r.ok for r in results) and all(p.ok for p in probe_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
