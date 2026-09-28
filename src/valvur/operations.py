"""What valvur does, independent of how it is asked.

Both the MCP tools and the CLI call these functions, so the two surfaces cannot
drift (F9.3). Parity is structural rather than tested by comparing formatted output,
which would be brittle and would keep passing while the semantics diverged.

Each returns plain text: an agent reads it, and so does a person.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import profiles as _profiles
from .findings import exploit_badge as _exploit_badge
from .mcp import jobs
from .mcp.jobs import State
from .results import RESULTS_DIR

DEFAULT_LIMIT = 20
MAX_LIMIT = 100

#: Set by Claude Code for a project's stdio server: the project root.
PROJECT_DIR_ENV = "CLAUDE_PROJECT_DIR"


from .refusal import Refusal  # noqa: E402 — re-exported: callers import it from here


def resolve_workspace(raw: str | None) -> Path:
    """The Workspace a call names, or a Refusal. Never creates anything (R1.2):
    a relative path in the second gate became `relative/path/.security-scan/`
    inside the project, and a confident report on an empty folder."""
    import os

    project = os.environ.get(PROJECT_DIR_ENV) or None
    roots = _client_roots()
    if not raw:
        # The client's project (R6.4): Claude Code's variable, or the first root it
        # names over `roots/list`; a person at a terminal means where they stand.
        path = Path(project) if project else roots[0] if roots else Path.cwd()
    else:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            if project is None:
                raise Refusal(
                    f"The workspace must be an absolute path; got {raw!r}, and there is "
                    "no project directory to resolve it against.", kind="relative-path")
            path = Path(project) / path
    path = path.resolve()
    if roots and not any(path == root or root in path.parents for root in roots):
        # A scan writes into the folder it scans (R6.4, N2.2).
        raise Refusal(f"{path} is outside the client's roots ("
                      f"{', '.join(str(root) for root in roots)}); a scan writes into the "
                      "folder it scans, so name one inside them.", kind="outside-roots")
    if not path.exists():
        raise Refusal(f"There is no directory at {path}; nothing was scanned or created.",
                      kind="no-directory")
    if not path.is_dir():
        raise Refusal(f"{path} is a file, not a directory; name the project's folder.",
                      kind="not-a-directory")
    return path


def _client_roots() -> list[Path] | None:
    """The roots of the MCP client this call comes from; None outside a call, or
    when the client declared none."""
    from .mcp import protocol

    call = protocol.current_call()
    return call.client.roots() if call is not None and call.client is not None else None


def _checked_profile(value) -> str:
    """The Profile a call names, or a Refusal in one sentence (R1.5)."""
    try:
        return _profiles.resolve(value or _profiles.DEFAULT)
    except ValueError:
        raise Refusal(f"`profile` must be offline or full; got {value!r}.") from None


def _checked_budget(value) -> float | None:
    """`budget_s` as seconds, None when not given, or a Refusal (R1.5). Zero means
    no budget, as it always has; a negative or non-numeric value used to start a
    job that failed a moment later in Python's words."""
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = float(value)      # "300" from a model is a number; "ten" is not
        except ValueError:
            pass
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Refusal(f"`budget_s` must be a number of seconds, 0 for none; got {value!r}.")
    if value < 0:
        raise Refusal(f"`budget_s` must be 0 or more seconds; got {value!r}.")
    return float(value)


def _checked_limit(value) -> int:
    """`limit` as a whole number of at least 1, the default when absent, or a
    Refusal (R1.5)."""
    if value is None:
        return DEFAULT_LIMIT
    number = value
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value)
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise Refusal(f"`limit` must be a whole number of 1 or more; got {value!r}.")
    return number


def _checked(args: dict) -> dict:
    """The call's arguments with its Workspace resolved and checked (R1.2)."""
    return {**args, "workspace": str(resolve_workspace(args.get("workspace")))}

def _results(workspace: str | None) -> Path:
    return Path(workspace or ".").resolve() / RESULTS_DIR


def _load(workspace: str | None) -> dict:
    path = _results(workspace) / "findings.json"
    if not path.is_file():
        raise Refusal(f"No scan results at {path}. Run the `scan` tool first.",
                      kind="no-results")
    return json.loads(path.read_text(encoding="utf-8"))


def _one_line(finding: dict) -> str:
    word = _exploit_badge(finding.get("exploit"))
    badge = f" [{word}]" if word else ""
    suppressed = " [suppressed]" if finding.get("suppressed") else ""
    where = f"{finding['path']}:{finding['line']}" if finding.get("line") else finding["path"]
    return (
        f"{finding.get('rank', 0)}. [{finding.get('status', '?')}] {where} — "
        f"{finding['title']} ({finding['rule']}){badge}{suppressed}\n"
        f"   fingerprint: {finding['fingerprint']}"
    )


# ----------------------------------------------------------------- the tools

#: The scan budget over MCP when the client names none (23.3.7): F2.6's five
#: minutes. The CLI has none unless `--budget` is given — a person at a terminal
#: can press Ctrl-C; an agent session with a runaway Scanner waited ten minutes.
MCP_BUDGET_S = 300.0


def _scan_with_budget(budget_s: float | None):
    """The work a background job performs, with its budget bound in. Returns the
    summary it will report. A budget of 0 means none."""
    budget = float(budget_s) if budget_s else None

    def run_scan(workspace: Path, profile: str, progress) -> str:
        from . import engine_host
        from .api import scan

        # The Scan Container (ADR-0022): the only engine since R3.9.
        runner: Any = engine_host.for_scan()
        job = jobs.current(workspace)
        if job is not None:
            job.canceller = runner.kill      # `scan_cancel` stops this fleet, not another's
        run = scan(workspace, runner=runner, profile=profile, on_progress=progress,
                   budget_s=budget)
        return _summarise(workspace, run)

    run_scan.budget_s = budget  # type: ignore[attr-defined]
    return run_scan


def _run_scan(workspace: Path, profile: str, progress) -> str:
    return _scan_with_budget(MCP_BUDGET_S)(workspace, profile, progress)


def _summarise(workspace: Path, run) -> str:
    lines = [f"{run.status}: {len(run.findings)} finding(s). {run.status_reason}."]
    if run.failures:
        lines += ["", "INCOMPLETE — these scanners did not run:"]
        lines += [f"  - {f.tool}: {f.reason}" for f in run.failures]
        lines.append("Findings are partial; do not treat this as a clean result.")
    if run.fixed:
        lines.append(f"Fixed since the last scan: {len(run.fixed)}")
    if run.not_rechecked:
        lines.append(f"Not re-checked since the last scan: {len(run.not_rechecked)} — their "
                     "Scanner did not run this time; neither fixed nor persisting")
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
    workspace = resolve_workspace(args.get("workspace"))
    profile = _checked_profile(args.get("profile"))
    budget_s = _checked_budget(args.get("budget_s"))

    existing = jobs.current(workspace)
    if existing and existing.state is State.RUNNING:
        return (
            f"A {existing.profile} scan is already running here "
            f"({existing.elapsed:.0f}s so far). Poll `scan_status`."
        )
    if existing and existing.state is State.CANCELLING:
        return (
            f"The previous {existing.profile} scan here is still stopping "
            f"({existing.elapsed:.0f}s since it started). Poll `scan_status` until it "
            "reads CANCELLED, then call `scan` again."
        )

    jobs.start(workspace, profile,
               _scan_with_budget(MCP_BUDGET_S if budget_s is None else budget_s))
    return (
        f"Started a {profile} scan of {workspace}.\n"
        "Scans take seconds to minutes depending on the project, so this returns "
        "immediately.\n\n"
        "Poll `scan_status` until it reports done, then use `list_findings`."
    )


def scan_reply(args: dict) -> tuple[str, dict]:
    """`scan` over MCP (R6.3, ADR-0024): start the scan, or attach to the one
    already running here, and return its result in schema 2, sending each progress
    message as a notification on the way.

    R6.1 measured that Claude Code keeps a 150-second call's result, and start-and-
    poll cost the second gate's agent sixteen turns. A client that lets go of the
    call, by cancelling it or by closing stdin, stops the wait and not the scan: the
    next `scan` here attaches and returns the same generation, and `scan_cancel` is
    what stops one."""
    from . import reply

    workspace = resolve_workspace(args.get("workspace"))
    profile = _checked_profile(args.get("profile"))
    budget_s = _checked_budget(args.get("budget_s"))
    job = jobs.start(workspace, profile,
                     _scan_with_budget(MCP_BUDGET_S if budget_s is None else budget_s))
    _attach(job, None)
    fields = reply.fields(workspace, job)
    return reply.text(fields), fields


def update_reply(args: dict) -> tuple[str, dict]:
    """`update` over MCP (ADR-0025, R6.6; F10.8): what `valvur update` does, each
    step sent as progress, and the answer the list of what was fetched. An explicit
    request, so `fetch = never` does not refuse it: an air-gapped site runs it
    against its mirrors."""
    from . import engine_host, updating
    from .mcp import protocol

    call = protocol.current_call()
    said: list[str] = []

    def say(line: str) -> None:
        said.append(line)
        if call is not None:
            call.progress(line)

    updated = updating.run(say, engine_host.for_scan(),
                           if_stale=bool(args.get("if_stale")))
    fetched = ", ".join(updated.fetched) or "nothing"
    verdict = (f"Fetched: {fetched}." if updated.ok else
               f"The update did not finish; fetched: {fetched}. The reason is above.")
    return "\n".join([*said, "", verdict]), {"ok": updated.ok,
                                              "fetched": list(updated.fetched),
                                              "said": said}


def _attach(job, seconds: float | None) -> None:
    """Wait for `job` to settle, for `seconds` at most (None: as long as it takes),
    sending each progress message as a notification to the call being answered,
    and stopping once the client lets go of the call (R6.3)."""
    from .mcp import protocol

    call = protocol.current_call()
    deadline = None if seconds is None else time.monotonic() + seconds
    sent = 0
    while True:
        step = 0.25 if deadline is None else min(0.25, max(0.0, deadline - time.monotonic()))
        if job.settled.wait(timeout=step):
            break
        sent = _forward(job, call, sent)
        if call is not None and call.detached.is_set():
            break
        if deadline is not None and time.monotonic() >= deadline:
            break
    _forward(job, call, sent)


def _forward(job, call, sent: int) -> int:
    """Each progress message the job has said since `sent`, as a notification."""
    said = list(job.progress)
    if call is not None:
        for message in said[sent:]:
            call.progress(message)
    return len(said)


def _provenance(workspace: str | None) -> dict:
    path = _results(workspace) / "run.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _staleness_note(workspace: str | None, *, found_nothing: bool) -> list[str]:
    """What an agent must be told when the data was too old to be evidence (the
    words are `reply`'s, one copy for every surface)."""
    from .reply import staleness_note

    return staleness_note(Path(workspace or ".").resolve(), _provenance(workspace),
                          found_nothing=found_nothing)


def _text_of(reply):
    """The text half of a reply, as its own function: what the CLI prints and
    what every text-only caller gets, derived from the one computation the MCP
    surface answers in both forms (28.2.2). `.reply` names that form, so the
    parity test can see the two are one (F9.3)."""
    def text(args: dict) -> str:
        return reply(args)[0]

    text.__name__ = reply.__name__.removesuffix("_reply")
    text.__qualname__ = text.__name__
    text.__doc__ = reply.__doc__
    text.reply = reply  # type: ignore[attr-defined]
    return text


def findings_reply(args: dict) -> tuple[str, dict]:
    """`findings` (R6.5, D12): the last scan's Findings, worst first, filtered by
    fingerprint, group, rule and path prefix, by status and suppression; with a
    fingerprint, that Finding in full. It says when it clamped the limit, and what
    it did not show. The text, and the same answer as a dict for
    `structuredContent`, from one computation (28.2.2)."""
    args = _checked(args)
    asked = _checked_limit(args.get("limit"))
    limit = min(asked, MAX_LIMIT)
    status = args.get("status")
    if status and status not in ("new", "persisting", "regressed"):
        # The arguments first: what the call asked, before what the folder holds.
        raise Refusal(f"`status` must be new, persisting or regressed; got {status!r}.")
    filters = {key: args[key] for key in ("fingerprint", "group", "rule", "path", "status")
               if args.get(key)}
    data = _load(args.get("workspace"))
    findings = [f for f in data["findings"] if _matches(f, filters)]
    if filters.get("fingerprint") and not findings:
        raise Refusal(f"No finding with fingerprint {filters['fingerprint']} in the last "
                      "scan; `findings` gives each finding's.", kind="unknown-fingerprint")
    if not args.get("include_suppressed") and not filters.get("fingerprint"):
        findings = [f for f in findings if not f.get("suppressed")]
    findings.sort(key=lambda f: f.get("rank") or 10**9)

    shown, omitted = findings[:limit], max(0, len(findings) - limit)
    caveats = _staleness_note(args.get("workspace"), found_nothing=not findings)
    detail = _detail(findings[0]) if filters.get("fingerprint") else None
    structured = {
        "total": len(findings), "shown": len(shown), "omitted": omitted, "limit": limit,
        "clamped": asked > MAX_LIMIT, "filters": filters,
        "findings": [_structured_finding(f) for f in shown],
        "detail": detail, "caveats": caveats,
    }
    if detail is not None:
        return "\n".join([_explained(findings[0]), *caveats]), structured
    if not findings:
        lines = ["No findings match. The scan itself may still have been incomplete — "
                 "check `scan_status`."]
        return "\n".join(lines + caveats), structured

    lines = [f"{len(findings)} finding(s); showing {len(shown)}, worst first."
             + (f" `limit` {asked} was clamped to {MAX_LIMIT}." if asked > MAX_LIMIT else ""),
             ""]
    lines += [_one_line(f) for f in shown]
    if omitted:
        # Silent truncation reads as "that is everything" (F9.10).
        lines += [
            "",
            f"{omitted} more not shown. Raise `limit` (max {MAX_LIMIT}) or filter "
            "by `group`, `rule`, `path` or `status`.",
        ]
    lines += caveats
    return "\n".join(lines), structured


def _matches(finding: dict, filters: dict) -> bool:
    """A Finding against the call's filters: exact fingerprint, group, rule and
    status; `path` a prefix on whole segments, as an exclude is."""
    prefix = str(filters.get("path") or "").rstrip("/")
    return (all(finding.get(key) == filters[key]
                for key in ("fingerprint", "group", "rule", "status") if key in filters)
            and (not prefix or finding["path"] == prefix
                 or finding["path"].startswith(prefix + "/")))


def list_findings_reply(args: dict) -> tuple[str, dict]:
    """`list_findings`, since R6.5 `findings` with no fingerprint: kept one release
    so a client that allowed it by name still works."""
    return findings_reply(args)


list_findings = _text_of(list_findings_reply)
findings = _text_of(findings_reply)


def _structured_finding(finding: dict) -> dict:
    """One Finding for the structured reply: what the one-line text shows, plus
    severity, exploitation and the evidence. Title and evidence are neutralised
    on the way out (F9.9) — idempotent on a `findings.json` this valvur wrote,
    where the model boundary already did it, and a guard on one an older valvur
    did. The reply is bounded by `limit` and by `defang.MAX_EVIDENCE` per entry."""
    from . import defang

    exploit = finding.get("exploit") or {}
    # Fenced always, not only when it reads as an instruction (29.3.3): the
    # machine block tells the agent what the markers mean, so a quoted line
    # without them is a line the block did not describe. `neutralise` bounds
    # a fenced text to MAX_EVIDENCE and leaves an already-fenced one alone.
    evidence = defang.neutralise(str(finding.get("evidence") or ""), always_fence=True)
    return {
        "rank": finding.get("rank", 0),
        "status": finding.get("status", "?"),
        "severity": finding.get("severity", "unknown"),
        "path": finding["path"],
        "line": finding.get("line") or None,
        "title": defang.neutralise(str(finding.get("title") or "")),
        "rule": finding["rule"],
        "fingerprint": finding["fingerprint"],
        "suppressed": bool(finding.get("suppressed")),
        "exploit": {"kev": exploit.get("kev"), "ransomware": bool(exploit.get("ransomware")),
                    "epss": exploit.get("epss")},
        "evidence": evidence,
    }


def explain_finding(args: dict) -> str:
    """`explain_finding`, since R6.5 `findings` with a fingerprint: kept one release."""
    if not args.get("fingerprint"):
        raise Refusal("`fingerprint` is required; `findings` gives each finding's.",
                      kind="missing-argument")
    return findings_reply(args)[0]


def _detail(finding: dict) -> dict:
    """What `findings` adds for one fingerprint: every source, the exploitation,
    the dependency path, the suppression."""
    return {"sources": list(finding.get("sources") or []),
            "exploit": dict(finding.get("exploit") or {}),
            "dependency": dict(finding.get("dependency") or {}),
            "suppressed": finding.get("suppressed"),
            "group": finding.get("group")}


def _explained(finding: dict) -> str:
    """One Finding in full, as text."""
    lines = [
        f"{finding['title']}",
        f"  rule:        {finding['rule']}",
        f"  location:    {finding['path']}"
        + (f":{finding['line']}" if finding.get("line") else ""),
        f"  severity:    {finding.get('severity', 'unknown')}",
        f"  status:      {finding.get('status', '?')}",
        f"  reported by: {', '.join(finding.get('sources') or []) or 'unknown'}",
    ]
    if finding.get("group"):
        lines.append(f"  group:       {finding['group']}")

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
        # Neutralised at the model boundary (F3.13, F9.9), and fenced here always
        # (29.3.3): quoted, never presented as prose the agent might read as
        # addressed to it — the markers `SUMMARY.md` says quoted text carries.
        from . import defang

        lines += ["", "Evidence:", defang.neutralise(finding["evidence"], always_fence=True)]

    lines += [
        "",
        "valvur proposes; it does not change your code. Applying this is your "
        "decision, and a finding disappearing is not proof it was fixed.",
    ]
    return "\n".join(lines)


def cancel_scan(args: dict) -> str:
    """Stop a running scan (23.3.3): the same outcome Ctrl-C gives the CLI (F1.11)
    — containers stopped, nothing written, not a failure."""
    workspace = resolve_workspace(args.get("workspace"))
    job, stopped = jobs.cancel(workspace)
    if job is None:
        return f"No scan is running in {workspace}."
    containers = (
        f"stopped {stopped} container(s)" if stopped
        else "no container had started; the scan stops at its next step"
    )
    return (
        f"Cancelling the {job.profile} scan of {workspace} after {job.elapsed:.0f}s — "
        f"{containers}.\n"
        "No results are written for a cancelled scan; the previous results, if any, "
        "stand. `scan_status` will read CANCELLED once the fleet has stopped; call "
        "`scan` to start again."
    )


def doctor(args: dict) -> str:
    """Every precondition a scan has, checked and named before one runs (23.3.1).
    Read-only; opens no socket unless `network` is asked for."""
    from . import doctor as _doctor

    workspace = resolve_workspace(args.get("workspace"))
    checks = _doctor.run(workspace, network=bool(args.get("network")))
    return _doctor.render(checks, workspace)


def scan_status_reply(args: dict) -> tuple[str, dict]:
    """Schema 2 (R6.2, ADR-0024): the fields, and the text rendered from them.

    A running scan is attached to (R6.3): the call waits for its result, sending
    its progress, up to `jobs.STATUS_WAIT_SECONDS`, and never starts one. Returning
    instantly made an agent pay fourteen turns for one scan (task 10.2.5)."""
    from . import reply

    args = _checked(args)
    workspace = Path(args["workspace"])
    job = jobs.current(workspace)
    if job is not None and job.state in jobs.ACTIVE:
        _attach(job, jobs.STATUS_WAIT_SECONDS)
    fields = reply.fields(workspace, job)
    return reply.text(fields), fields


scan_status = _text_of(scan_status_reply)
