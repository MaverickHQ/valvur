"""The reply every scan surface gives: schema 2 (ADR-0024, D7; F9.8 to F9.10).

Fields first, and the text rendered from them alone, so the two cannot disagree:
Claude Code hands the model only `structuredContent` when a reply has both forms
(29.2.4), and the status reply had grown field by field until its fields and its
text said different things (C4, C7). The Markdown summary travels as `report`, so
what `SUMMARY.md` says reaches the model too.

Six states: `none` (no scan here), `running`, `cancelling`, `cancelled`, `failed`
and `done`. Every state has `next`; every state with no result to give has
`error.kind`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Protocol

from . import events, verdict
from .events import Event, Kind
from .results import RESULTS_DIR, findings_of

SCHEMA = 2
#: The groups a reply names, best-ranked first; `findings.json` has all.
GROUPS_SHOWN = 10
#: What the File Set left out, named in a reply; `run.json` has every entry.
NOT_READ_SHOWN = 20
#: The summary's characters a reply carries (R6.2). A reply carries it twice, as
#: `report` and in the text, and Claude Code's limit is 25,000 tokens: 30,000
#: characters each leaves the fields room at three characters a token. The
#: largest measured, repository 2's, was 6,000.
REPORT_CHARS = 30_000
#: How many lines of a failure reason a reply shows. The bound is on LINES, never
#: on the sentence (23.3.4): the Kiro run read *"…no package-name index for PyPI,
#: so"* at an 80-character cut, which was the one sentence it needed whole.
REASON_LINES = 6

#: The sentences after a job's state, one string each so text and field agree.
CANCELLING_NEXT = "Call again; no result will follow."
CANCELLED_NEXT = ("No result: a cancelled scan writes nothing, and the previous results, if "
                  "any, stand. Call `scan` to start again.")
DOCTOR_NEXT = ("Run `doctor` (the tool; `valvur doctor` on a shell) before scanning again: "
               "it names what this machine is missing and the fix.")
NO_RESULT = "No result to report."


#: How long a status call waits for a running scan, when the surface does not say:
#: the MCP jobs' `STATUS_WAIT_SECONDS`, which the server passes in.
WAITED_S = 330.0


def running_next(waited_s: float = WAITED_S) -> str:
    return (f"Call `scan_status` again; it waits up to {waited_s:g} s and "
            "returns the moment the scan finishes; do not report a result yet.")


class JobView(Protocol):
    """What the reply reads of a surface's scan job (D51): passed in, so this module
    imports nothing from the surface that holds one."""

    profile: str
    started: float
    error: str
    doctor_may_help: bool
    next_moves: tuple[str, ...]
    failure: dict | None
    progress: list[Event]
    progress_at: list[float]

    @property
    def state(self) -> Any: ...

    @property
    def elapsed(self) -> float: ...


# ------------------------------------------------------------------ the fields

def fields(workspace: Path, job: JobView | None = None, *,
           waited_s: float | None = None) -> dict:
    """Schema 2 for the scan of `workspace`: the job's state if there is one that
    has not finished well, otherwise what the Results Folder holds. `waited_s` is
    how long the surface waits for a running scan before answering."""
    waited = WAITED_S if waited_s is None else waited_s
    base: dict = {"schema": SCHEMA, "workspace": str(workspace), "profile": None,
                  "elapsed_s": None, "generation": None, "verdict": None, "reason": "",
                  "complete": None, "next": [], "error": None}
    if job is not None:
        base.update(profile=job.profile, elapsed_s=round(job.elapsed, 1))
    state = str(job.state) if job is not None else None
    if job is not None and state == "running":
        return {**base, "state": "running", "progress": _progress(job, waited),
                "next": [running_next(waited)]}
    if job is not None and state == "cancelling":
        return {**base, "state": "cancelling", "next": [CANCELLING_NEXT],
                "error": {"kind": "cancelled", "message": (
                    f"the {job.profile} scan, {job.elapsed:.0f}s in; its containers are "
                    "being stopped")}}
    if job is not None and state == "cancelled":
        return {**base, "state": "cancelled", "next": [CANCELLED_NEXT],
                "error": {"kind": "cancelled", "message": job.error}}
    if job is not None and state == "failed":
        advice = list(job.next_moves)
        if job.doctor_may_help and not advice:
            # Only when a precondition could be the cause (29.0.3): the budget's
            # refusal carries its own levers, and `doctor` would say *ready*.
            advice.append(DOCTOR_NEXT)
        advice.append(NO_RESULT)
        kind = ("budget" if job.failure else "precondition" if job.doctor_may_help
                else "busy" if job.next_moves else "failed")
        error: dict = {"kind": kind, "message": job.error}
        if job.failure:
            error["budget"] = dict(job.failure)
        return {**base, "state": "failed", "next": advice, "error": error,
                "doctor_may_help": job.doctor_may_help}

    results = workspace / RESULTS_DIR
    path = results / "run.json"
    if not path.is_file():
        return {**base, "state": "none", "next": ["Call `scan` to scan it."], "error": {
            "kind": "no-scan", "message": f"No scan has run in this workspace ({results})."}}
    return {**base, **_done(workspace, json.loads(path.read_text(encoding="utf-8"))),
            "state": "done"}


def _progress(job: JobView, waited_s: float) -> dict:
    """A running scan, as fields: what is being fetched, what is running and for
    how long, what finished, and what the workspace line said (29.0.4). Each event
    is placed by its kind (D53), and only its words are carried."""
    now: str | None = None
    completed: list[str] = []
    started: dict[str, float] = {}
    finished: list[str] = []
    done: set[str] = set()
    fleet: int | None = None
    workspace_lines: list[str] = []
    stamps = list(job.progress_at) + [job.elapsed + job.started] * len(job.progress)
    for event, at in zip(job.progress, stamps, strict=False):
        if event.kind is Kind.FETCH_STARTED:
            now = str(event)
            continue
        now = None
        if event.kind is Kind.FLEET:
            fleet = int(event.fields["count"])
        elif event.kind is Kind.WORKSPACE:
            workspace_lines.append("Workspace: " + events.workspace_body(event))
        elif event.kind is Kind.SCANNER_STARTED:
            started[str(event.fields["name"])] = at
        elif event.kind is Kind.SCANNER_ENDED and event.fields["name"] in started:
            finished.append(str(event))
            done.add(str(event.fields["name"]))
        else:
            completed.append(str(event))
    running = {tool: round(time.monotonic() - at, 1) for tool, at in started.items()
               if tool not in done}
    return {"now": now, "running": running, "finished": finished, "fleet": fleet,
            "completed": completed, "workspace": workspace_lines,
            "waited_s": waited_s, "messages": [str(event) for event in job.progress]}


def _done(workspace: Path, data: dict) -> dict:
    """What a finished scan left: the verdict and why, the scope, the counts, the
    top groups, what did not run, and the summary itself."""
    counts = data.get("findings")
    if not isinstance(counts, dict):          # a run.json written by an older valvur
        counts = {"active": counts, "suppressed": 0, "not_covered": 0}
    results = workspace / RESULTS_DIR
    scanners = [{"tool": s.get("tool"), "ok": bool(s.get("ok")),
                 "reason": s.get("reason") or "", "duration_s": s.get("duration_s") or 0}
                for s in data.get("scanners", [])]
    timed = [(s["duration_s"], s["tool"]) for s in scanners
             if isinstance(s["duration_s"], int | float) and s["duration_s"] > 0]
    skipped = dict(data.get("scanners_skipped") or {})
    not_run = [{"tool": s["tool"], "kind": "failed", "reason": s["reason"]}
               for s in scanners if not s["ok"]]
    not_run += [{"tool": tool, "kind": "skipped", "reason": why} for tool, why in skipped.items()]
    not_run += [{"tool": tool, "kind": "not-in-profile", "reason": ""}
                for tool in data.get("scanners_not_run") or []]
    report = results / "SUMMARY.md"
    try:
        document = json.loads((results / "findings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        document = None
    # Results that are not valvur's have no groups to show (R27.4, found by fuzzing).
    groups = document.get("groups") or [] if findings_of(document) is not None else []
    groups = [g for g in groups if isinstance(g, dict)] if isinstance(groups, list) else []
    reason = data.get("status_reason") or ""
    if data.get("status") == "inconclusive" and not reason:
        reason = ("nothing live was found, and the reason is not recorded — a run.json "
                  "from before 22.D.4; rescan")
    coverage = (data.get("coverage") or {}).get("dependency-reality", {}).get("ignores") or []
    not_read = [e for e in data.get("not_read") or [] if isinstance(e, dict)]
    return {
        "generation": data.get("generation"), "profile": data.get("profile"),
        "verdict": data.get("status"), "reason": reason,
        "complete": bool(data.get("complete")),
        "scope": data.get("scope"),
        "counts": {**{k: int(counts.get(k) or 0)
                      for k in ("active", "suppressed", "not_covered", "total")},
                   "fixed": int(data.get("fixed") or 0),
                   "not_rechecked": int(data.get("not_rechecked") or 0)},
        "resolution": _resolution(data.get("resolution")),
        "groups": groups[:GROUPS_SHOWN],
        "not_run": not_run,
        "not_read": [{"path": e.get("path"), "reason": e.get("reason")}
                     for e in not_read[:NOT_READ_SHOWN]],
        "not_read_total": len(not_read),
        "coverage": list(coverage),
        "hygiene": data.get("hygiene"),
        "scanners": scanners,
        "slowest": _slowest(timed),
        "next": next_moves(workspace),
        "caveats": staleness_note(workspace, data, found_nothing=not counts.get("active")),
        "network": dict(data.get("network") or {}),
        "build": dict(data.get("build") or {}),
        "database": dict(data.get("database") or {}),
        "name_index": dict(data.get("name_index") or {}),
        # Every dataset's age and its basis (R11.6), as `run.json` holds them.
        "data": dict(data.get("data") or {}),
        # 30.1.3 (C6): an agent refused a `git status` told the user to add the folder
        # to `.gitignore`; it holds its own. Checked, not assumed.
        "results": {"path": str(results), "ignores_itself": _ignores_itself(results)},
        "report": _bounded(report.read_text(encoding="utf-8")) if report.is_file() else None,
    }


#: Rows of each list the reply carries; the totals count the rest (D59).
SINCE_SHOWN = 20


def _slowest(timed: list[tuple[float, str]]) -> dict | None:
    """The Scanner that took longest, a tie going to the one that ran first, as
    `SUMMARY.md` names it: one scan gives one answer on every surface. The engine
    rounds each time to a tenth of a second, so quick Scanners often tie."""
    if not timed:
        return None
    seconds, tool = max(timed, key=lambda entry: entry[0])
    return {"tool": tool, "seconds": round(seconds, 1)}


def _resolution(block: object) -> dict | None:
    """On a rescan, every earlier Finding's state and the new ones, bounded (R21.4)."""
    if not isinstance(block, dict):
        return None
    earlier, new = list(block.get("earlier") or []), list(block.get("new") or [])
    return {"earlier": earlier[:SINCE_SHOWN], "earlier_total": len(earlier),
            "new": new[:SINCE_SHOWN], "new_total": len(new)}


def _ignores_itself(results: Path) -> bool:
    try:
        return "*" in (results / ".gitignore").read_text(encoding="utf-8").split()
    except OSError:
        return False


def _bounded(summary: str) -> str:
    """The summary, whole when it fits, else cut at a line and said so."""
    if len(summary) <= REPORT_CHARS:
        return summary
    head = summary[:REPORT_CHARS].rsplit("\n", 1)[0]
    return head + "\n\n_The rest is in `.security-scan/SUMMARY.md`._\n"


# ------------------------------------------------------------------ the text

def text(f: dict) -> str:
    """The reply as text, from the fields and nothing else."""
    state = f["state"]
    if state == "none":
        return " ".join([f["error"]["message"], *f["next"]])
    if state == "running":
        return "\n".join(_running_text(f))
    if state == "cancelling":
        return f"CANCELLING — {f['error']['message']}. {' '.join(f['next'])}"
    if state == "cancelled":
        return f"CANCELLED after {f['elapsed_s']:.0f}s — {f['error']['message']}\n" + \
            "\n".join(f["next"])
    if state == "failed":
        return "\n".join([f"FAILED after {f['elapsed_s']:.0f}s — {f['error']['message']}",
                          *f["next"]])
    return "\n".join(_done_text(f))


def _running_text(f: dict) -> list[str]:
    p = f["progress"]
    lines = [f"RUNNING — {f['profile']} scan, {f['elapsed_s']:.0f}s elapsed.", *p["workspace"]]
    if p["now"] is not None:
        lines.append(f"Now: {p['now']}.")
    if p["running"]:
        # What an agent could not tell before: a running scan from a hung one.
        names = ", ".join(f"{tool} {seconds:.0f}s" for tool, seconds in p["running"].items())
        total = p["fleet"] if p["fleet"] is not None else len(p["running"]) + len(p["finished"])
        lines.append(f"Now: {names} running — {len(p['finished'])} of {total} finished: "
                     f"{', '.join(p['finished']) or 'none yet'}")
    lines.append(f"Completed so far: {', '.join(p['completed']) or 'starting'}")
    lines.append(f"This call waited {p['waited_s']:.0f}s for it. Call again; "
                 "do not report a result yet.")
    return lines


def _done_text(f: dict) -> list[str]:
    counts = f["counts"]
    lines = [
        f"status:   {f['verdict']}",
        f"complete: {f['complete']}",
        f"findings: {counts['active']} active"
        + (f", {counts['suppressed']} suppressed" if counts["suppressed"] else "")
        + (f", {counts['not_covered']} not covered" if counts["not_covered"] else ""),
    ]
    if f["elapsed_s"] is not None:
        stamp = f" Generation {f['generation']}." if f["generation"] else ""
        lines = [f"DONE in {f['elapsed_s']:.0f}s.{stamp}", "", *lines]
    lines += _resolution_text(f.get("resolution"))
    not_read = f["not_read"]
    if not_read:
        more = f["not_read_total"] - min(len(not_read), 8)
        lines.append("not read by any Scanner: " + ", ".join(
            f"{e['path']} ({e['reason']})" for e in not_read[:8])
            + (f" and {more} more" if more else ""))
    if counts["not_rechecked"]:
        lines.append(f"not re-checked: {counts['not_rechecked']} previous finding(s) whose "
                     "Scanner did not run this time — neither fixed nor persisting")
    if f["verdict"] == "inconclusive":
        lines.append(f"          ^ {f['reason']}")
    if f["next"]:
        lines += ["", "Next:", *(f"  {move}" for move in f["next"])]
    lines += ["", "Scanners:"]
    for scanner in f["scanners"]:
        mark = "ok" if scanner["ok"] else "FAILED — " + whole_reason(scanner["reason"])
        seconds = scanner["duration_s"]
        if isinstance(seconds, int | float) and seconds > 0:
            mark += f" ({seconds:.1f}s)"
        lines.append(f"  {scanner['tool']}: {mark}")
    if f["slowest"]:
        lines.append(f"  slowest: {f['slowest']['tool']} {f['slowest']['seconds']:.1f}s — "
                     "the fleet runs concurrently, so that is about what the scan cost")
    not_in_profile = [e["tool"] for e in f["not_run"] if e["kind"] == "not-in-profile"]
    if not_in_profile:
        lines += ["", f"not run on the `{f['profile']}` profile: " + ", ".join(not_in_profile)]
    lines += [f"  {e['tool']}: skipped — {e['reason']}" for e in f["not_run"]
              if e["kind"] == "skipped"]
    if f["coverage"]:
        lines += ["", "coverage: " + "; ".join(f["coverage"])]
    build = f["build"]
    if build.get("match") is False:
        lines += ["", "WARNING: the shim and the image were built from different trees "
                  f"(shim {str(build.get('shim'))[:12]}, image {str(build.get('image'))[:12]}). "
                  "Same version, different code — the image may lack a Check or a rule "
                  "this shim expects. `docker pull` the image this version publishes, or "
                  "`pip install -U valvur`."]
    lines += ["", "left this machine: "
              f"{f['network'].get('what_left_the_machine', 'unknown')}"]
    if f["results"]["ignores_itself"]:
        lines.append(f"results: {f['results']['path']}; the folder ignores itself; "
                     "there is nothing to add to .gitignore")
    if not f["complete"]:
        lines += ["", "This scan was INCOMPLETE. Do not report it as clean."]
    lines += f["caveats"]
    if f["report"]:
        lines += ["", "--- SUMMARY.md ---", f["report"].rstrip("\n")]
    return lines


# ------------------------------------------------------------------ helpers

def _resolution_text(block: dict | None) -> list[str]:
    """The rescan table, right after the verdict: each earlier Finding by rule and
    path with its state now, then the new ones (R21.4)."""
    if block is None:
        return []
    lines = ["", "since the last scan:"]
    lines += [f"  {e['now']}: {e['rule']} at {e['path']}" for e in block["earlier"]]
    if not block["earlier_total"]:
        lines.append("  the last scan had no active findings")
    elif block["earlier_total"] > len(block["earlier"]):
        lines.append(f"  …and {block['earlier_total'] - len(block['earlier'])} more")
    lines.append(f"new since the last scan: {block['new_total']}")
    lines += [f"  {e['rule']} at {e['path']}" + (" (regressed)" if e.get("regressed") else "")
              for e in block["new"]]
    if block["new_total"] > len(block["new"]):
        lines.append(f"  …and {block['new_total'] - len(block['new'])} more")
    return lines


def whole_reason(reason: str) -> str:
    """A failure reason as the Scanner gave it, every sentence intact, continuation
    lines indented under the tool's name, and only the count of lines bounded."""
    shown = [line for line in reason.strip().splitlines()] or [""]
    kept, rest = shown[:REASON_LINES], shown[REASON_LINES:]
    out = kept[0]
    for line in kept[1:]:
        out += "\n         " + line
    if rest:
        out += f"\n         … {len(rest)} more line(s) in run.json"
    return out


def next_moves(workspace: Path) -> list[str]:
    """What an agent does with a finished scan: report from the summary it holds,
    naming each finding by rule and location; evidence only when asked (R6's exit).

    Task 23.3.4 pointed at `explain_finding` and REMEDIATION.md because an agent had
    called neither; measured at R6's exit, an agent handed the whole summary in
    `report` took each pointer as a turn to spend, and three of eight reports ran
    past six. The top Finding's fingerprint stays, as data. Nothing when nothing is
    active; nothing invented for results an older valvur wrote."""
    try:
        findings = findings_of(json.loads((workspace / RESULTS_DIR / "findings.json")
                                          .read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return []
    if findings is None:
        return []
    active = [f for f in findings if verdict.active(f)]
    if not active:
        return []
    top = min(active, key=lambda f: f.get("rank") or 10**9)
    # Every field read as the gate reads it: the folder is the project's, and a
    # finding that lost a key is named by what it kept (R27.4, found by fuzzing).
    where = f"{top.get('path')}:{top['line']}" if top.get("line") else top.get("path")
    moves = ["Report from `report`, the summary: it is the whole result, ranked, with what "
             "did not run.",
             "Name each finding by its rule and its location, as the summary does: the user "
             "needs both to ask about one or to accept it.",
             f"Evidence only when asked: `findings` with a fingerprint; #{top.get('rank', '?')} "
             f"is {top.get('fingerprint')}, {where} {top.get('title', '')}"]
    action = first_action(workspace / RESULTS_DIR / "REMEDIATION.md")
    if action:
        moves.append(f"The first proposed fix is REMEDIATION.md's {action}")
    return moves


def first_action(path: Path) -> str:
    """`action 1 of N: <heading>` from REMEDIATION.md's own text, so the agent is
    pointed at exactly the line it will read there; empty if the file has none."""
    import re

    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    total = re.search(r"\*\*([\d,]+) action\(s\)\*\*", body)
    first = re.search(r"^## 1\. (.+)$", body, re.M)
    if not first:
        return ""
    heading = first.group(1).replace("**", "").strip()
    count = f" of {total.group(1)}" if total else ""
    return f"action 1{count}: {heading}"


def staleness_note(workspace: Path, provenance: dict, *, found_nothing: bool) -> list[str]:
    """What an agent must be told when the data was too old to be evidence. An
    agent that reads "no findings" stops looking; unlike a human it will not glance
    at `SUMMARY.md` for a caveat nobody told it to expect."""
    database = provenance.get("database") or {}
    index = provenance.get("name_index") or {}
    if not database.get("stale") and not index.get("stale"):
        return []
    note = [""]
    if database.get("stale"):
        note.append(f"WARNING: the vulnerability database is {_age_text(database)}.")
    if index.get("stale"):
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
    note += ["Run `valvur update --if-stale` and scan again before relying on this result."]
    return note


def _age_text(block: dict) -> str:
    age = block.get("age_days")
    return f"{age:.0f} days old" if isinstance(age, (int, float)) else "out of date"
