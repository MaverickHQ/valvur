"""What valvur does, independent of how it is asked.

Both the MCP tools and the CLI call these functions, so the two surfaces cannot
drift (F9.3). Parity is structural rather than tested by comparing formatted output,
which would be brittle and would keep passing while the semantics diverged.

Each returns plain text: an agent reads it, and so does a person.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import profiles as _profiles
from .mcp import jobs
from .results import RESULTS_DIR

DEFAULT_LIMIT = 20
MAX_LIMIT = 100

def _results(workspace: str | None) -> Path:
    return Path(workspace or ".").resolve() / RESULTS_DIR


def _load(workspace: str | None) -> dict:
    path = _results(workspace) / "findings.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"No scan results at {path}. Run the `scan` tool first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _one_line(finding: dict) -> str:
    exploit = finding.get("exploit") or {}
    badge = ""
    if exploit.get("ransomware"):
        badge = " [KEV·RANSOMWARE]"
    elif exploit.get("kev"):
        badge = " [KEV]"
    elif exploit.get("epss") and exploit["epss"] >= 0.10:
        badge = f" [EPSS {exploit['epss']:.0%}]"
    suppressed = " [suppressed]" if finding.get("suppressed") else ""
    where = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
    return (
        f"{finding.get('rank', 0)}. [{finding.get('status', '?')}] {where} — "
        f"{finding['title']} ({finding['rule']}){badge}{suppressed}\n"
        f"   fingerprint: {finding['fingerprint']}"
    )


# ----------------------------------------------------------------- the tools

def _run_scan(workspace: Path, profile: str, progress) -> str:
    """The work a background job performs. Returns the summary it will report."""
    from .api import scan
    from .runner import ContainerRunner

    run = scan(workspace, runner=ContainerRunner(), profile=profile,
               on_progress=progress)

    lines = [f"{run.status}: {len(run.findings)} finding(s). {run.status_reason}."]
    if run.failures:
        lines += ["", "INCOMPLETE — these scanners did not run:"]
        lines += [f"  - {f.tool}: {f.reason}" for f in run.failures]
        lines.append("Findings are partial; do not treat this as a clean result.")
    if run.fixed:
        lines.append(f"Fixed since the last scan: {len(run.fixed)}")
    # The first thing an agent reads after `start_scan` completes. Saying
    # "inconclusive: 0 finding(s)" without the reason invites it to treat the number
    # as the answer.
    lines += _staleness_note(str(workspace), found_nothing=not run.findings)
    return "\n".join(lines)


def start_scan(args: dict) -> str:
    """Start a scan and return at once (F9.1).

    Always asynchronous, never "synchronous when fast": a contract that changes shape
    with project size is one an agent cannot reason about, and the slow case is
    exactly the repository that matters.
    """
    workspace = Path(args.get("workspace") or ".").resolve()
    profile = _profiles.resolve(args.get("profile") or _profiles.DEFAULT)

    existing = jobs.current(workspace)
    if existing and existing.state == "running":
        return (
            f"A {existing.profile} scan is already running here "
            f"({existing.elapsed:.0f}s so far). Poll `scan_status`."
        )

    jobs.start(workspace, profile, _run_scan)
    return (
        f"Started a {profile} scan of {workspace}.\n"
        "Scans take seconds to minutes depending on the project, so this returns "
        "immediately.\n\n"
        "Poll `scan_status` until it reports done, then use `list_findings`."
    )


def _provenance(workspace: str | None) -> dict:
    path = _results(workspace) / "run.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _staleness_note(workspace: str | None, *, found_nothing: bool) -> list[str]:
    """What an agent must be told when the database was too old to be evidence.

    Phase 14 taught the CLI, `SUMMARY.md` and `run.json` to say this. It did not
    teach the MCP surface — the one that reaches an agent's context with no file in
    between, and the one ADR-0015 makes primary. Measured 2026-09-05 on a 60-day-old
    database: `list_findings` said "No findings match" and pointed at `scan_status`
    for *incompleteness*, which was the wrong reason, because the scan had completed.

    An agent that reads "no findings" stops looking. Unlike a human it will not
    glance at `SUMMARY.md` for a caveat nobody told it to expect.
    """
    provenance = _provenance(workspace)
    database = provenance.get("database") or {}
    index = provenance.get("name_index") or {}
    if not database.get("stale") and not index.get("stale"):
        return []

    note = [""]
    if database.get("stale"):
        note.append(f"WARNING: the vulnerability database is {_age_text(database)}.")
    if index.get("stale"):
        # ADR-0018. Not a second copy of the database warning: the failure direction
        # differs, and an agent told "advisories are missing" would draw the wrong
        # conclusion about a dependency finding.
        note.append(
            f"WARNING: the package-name index is {_age_text(index)}. Dependency "
            "existence was checked against a list that predates anything registered "
            "since — a real package newer than the index may be reported as "
            "nonexistent."
        )
        if not database.get("stale"):
            note.append("Run `valvur update --if-stale` and scan again.")
            return note
    if found_nothing:
        note += [
            "This scan found nothing, and that is NOT evidence that there is nothing.",
            "Absence of findings requires current data to mean anything; presence "
            "does not.",
        ]
    else:
        note += [
            "The findings above are real, but the list is incomplete — advisories "
            "published since are missing.",
        ]
    note += [
        "Run `valvur update --if-stale` and scan again before relying on this result.",
    ]
    return note


def _age_text(block: dict) -> str:
    age = block.get("age_days")
    return f"{age:.0f} days old" if isinstance(age, (int, float)) else "out of date"


def list_findings(args: dict) -> str:
    data = _load(args.get("workspace"))
    findings = data["findings"]

    status = args.get("status")
    if status:
        findings = [f for f in findings if f.get("status") == status]
    if not args.get("include_suppressed"):
        findings = [f for f in findings if not f.get("suppressed")]

    findings.sort(key=lambda f: f.get("rank") or 10**9)

    limit = min(int(args.get("limit") or DEFAULT_LIMIT), MAX_LIMIT)
    shown, omitted = findings[:limit], max(0, len(findings) - limit)

    if not findings:
        lines = [
            "No findings match. The scan itself may still have been incomplete — "
            "check `scan_status`."
        ]
        lines += _staleness_note(args.get("workspace"), found_nothing=True)
        return "\n".join(lines)

    lines = [f"{len(findings)} finding(s); showing {len(shown)}, worst first.", ""]
    lines += [_one_line(f) for f in shown]
    if omitted:
        # Silent truncation reads as "that is everything" (F9.10).
        lines += [
            "",
            f"{omitted} more not shown. Raise `limit` (max {MAX_LIMIT}) or filter "
            "by `status`.",
        ]
    lines += _staleness_note(args.get("workspace"), found_nothing=False)
    return "\n".join(lines)


def explain_finding(args: dict) -> str:
    fingerprint = args.get("fingerprint")
    if not fingerprint:
        raise ValueError("fingerprint is required; list_findings reports it for each finding")

    data = _load(args.get("workspace"))
    finding = next(
        (f for f in data["findings"] if f["fingerprint"] == fingerprint), None
    )
    if finding is None:
        raise ValueError(f"No finding with fingerprint {fingerprint}")

    lines = [
        f"{finding['title']}",
        f"  rule:        {finding['rule']}",
        f"  location:    {finding['path']}"
        + (f":{finding['line']}" if finding.get("line") else ""),
        f"  severity:    {finding.get('severity', 'unknown')}",
        f"  status:      {finding.get('status', '?')}",
        f"  reported by: {', '.join(finding.get('sources') or []) or 'unknown'}",
    ]

    exploit = finding.get("exploit") or {}
    if exploit.get("cve"):
        lines += [
            "",
            "Exploitation:",
            f"  CVE:        {exploit['cve']}",
            f"  in CISA KEV: {exploit.get('kev')}"
            + ("  — used in ransomware campaigns"
               if exploit.get("ransomware") else ""),
            f"  EPSS:       {exploit.get('epss')}",
        ]

    dependency = finding.get("dependency") or {}
    if dependency.get("package"):
        lines += ["", "Dependency:",
                  f"  package: {dependency['package']} {dependency.get('version', '')}",
                  f"  scope:   {dependency.get('scope', 'unknown')}"]
        if dependency.get("path") and len(dependency["path"]) > 1:
            lines.append(f"  reached via: {' -> '.join(dependency['path'])}")
        if dependency.get("fixed_version"):
            lines.append(f"  fixed in: {dependency['fixed_version']}")

    if finding.get("suppressed"):
        lines += ["", f"SUPPRESSED: {finding['suppressed']}",
                  "This is an accepted risk recorded in .security-scan.toml."]

    if finding.get("evidence"):
        # Already neutralised at the model boundary (F3.13, F9.9). Quoted, never
        # presented as prose the agent might read as addressed to it.
        lines += ["", "Evidence:", finding["evidence"]]

    lines += [
        "",
        "valvur proposes; it does not change your code. Applying this is your "
        "decision, and a finding disappearing is not proof it was fixed.",
    ]
    return "\n".join(lines)


def scan_status(args: dict) -> str:
    workspace = Path(args.get("workspace") or ".").resolve()

    job = jobs.current(workspace)
    if job is not None and job.state == "running":
        # Wait a bounded time before answering, so a poll covers seconds of scan
        # rather than milliseconds. The agent pays one turn per call either way;
        # returning instantly made it pay fourteen (task 10.2.5).
        job.wait()
    if job is not None and job.state == "running":
        # An image pull in progress is the one stage that is not a Scanner
        # completing, and the one that made a first run look hung (10.2 claim 4):
        # it gets its own line, and disappears once "image pulled" follows it.
        pulling = [p for p in job.progress if p.startswith("pulling ")]
        settled = any(p.startswith("image pulled") for p in job.progress)
        completed = [p for p in job.progress if not p.startswith("pulling ")]
        lines = [f"RUNNING — {job.profile} scan, {job.elapsed:.0f}s elapsed."]
        if pulling and not settled:
            lines.append(f"Now: {pulling[-1]}.")
        lines.append(f"Completed so far: {', '.join(completed) or 'starting'}")
        lines.append(f"This call waited {jobs.STATUS_WAIT_SECONDS:.0f}s for it. Call again; "
                     "do not report a result yet.")
        return "\n".join(lines)
    if job is not None and job.state == "failed":
        return f"FAILED after {job.elapsed:.0f}s — {job.error}\nNo result to report."

    path = _results(args.get("workspace")) / "run.json"
    if not path.is_file():
        return f"No scan has run in this workspace ({path.parent})."
    data = json.loads(path.read_text(encoding="utf-8"))

    # `findings` is a breakdown, not a total (task 19.C.1). An agent reading one
    # number could not tell four accepted risks from four live problems, and this is
    # the surface ADR-0015 makes primary — it reaches an agent's context with no file
    # in between, so a caveat it does not carry is a caveat nobody sees.
    counts = data.get("findings")
    if not isinstance(counts, dict):          # a run.json written by an older valvur
        counts = {"active": counts, "suppressed": 0, "not_covered": 0}
    lines = [
        f"status:   {data.get('status')}",
        f"complete: {data.get('complete')}",
        f"findings: {counts.get('active', 0)} active"
        + (f", {counts['suppressed']} suppressed" if counts.get("suppressed") else "")
        + (f", {counts['not_covered']} not covered" if counts.get("not_covered") else ""),
    ]
    # `inconclusive` beside `complete: True` and a list of healthy Scanners reads as
    # a contradiction unless the reason is given. It is not a contradiction: every
    # Scanner ran, and the data they ran against was too old for "nothing" to mean
    # anything.
    if data.get("status") == "inconclusive":
        # Three different causes produce this verdict and an agent must be told
        # which. `run.json` says so in one field since 22.D.4; before that this
        # code guessed from `database.stale` and `name_index.stale`, and a run
        # with both stale and an uninspected ecosystem named only the first.
        reason = data.get("status_reason") or (
            "nothing live was found, and the reason is not recorded — a run.json "
            "from before 22.D.4; rescan"
        )
        lines.append(f"          ^ {reason}")
    lines += ["", "Scanners:"]
    for scanner in data.get("scanners", []):
        mark = "ok" if scanner["ok"] else f"FAILED — {scanner['reason'][:80]}"
        lines.append(f"  {scanner['tool']}: {mark}")
    # What did NOT run, and what nothing here reads even when it does. Two different
    # claims, both absent from this surface until task 19.C.1.
    not_run = data.get("scanners_not_run") or []
    if not_run:
        lines += ["", f"not run on the `{data.get('profile')}` profile: " + ", ".join(not_run)]
    skipped = data.get("scanners_skipped") or {}
    for tool, why in skipped.items():
        lines.append(f"  {tool}: skipped — {why}")
    ignores = (data.get("coverage") or {}).get("dependency-reality", {}).get("ignores") or []
    if ignores:
        lines += ["", "coverage: " + "; ".join(ignores)]

    network = data.get("network", {})
    lines += ["", f"left this machine: {network.get('what_left_the_machine', 'unknown')}"]
    if job is not None and job.state == "done":
        lines = [f"DONE in {job.elapsed:.0f}s.", "", *lines]
    if not data.get("complete"):
        lines += ["", "This scan was INCOMPLETE. Do not report it as clean."]
    lines += _staleness_note(
        args.get("workspace"), found_nothing=not counts.get("active")
    )
    return "\n".join(lines)


