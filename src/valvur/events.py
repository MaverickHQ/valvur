"""What a scan says while it runs, as typed events (D53): a kind and fields.

The engine reports structured events; until R23.7 `api` turned them into prose and
the reply parsed the prose back by its first words, and the budget's state was
read off the prefixes of reasons (the review of 2026-10-03, §3.4). Now each event
keeps its kind and its fields to the surface, and `render` is the one place their
words are written: what the CLI prints, what an MCP progress notification and the
`scan_status` reply carry. The words are the ones every surface showed before.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


class Kind(enum.StrEnum):
    #: Data a first run fetches, or a stale copy refreshed (ADR-0025): its start
    #: and its end. What `scan_status` shows as `Now:` while it lasts.
    FETCH_STARTED = "fetch-started"
    FETCH_ENDED = "fetch-ended"
    #: The pre-flight count, and the one lever for a large tree (29.1.2).
    WORKSPACE = "workspace"
    #: How many Scanners run, and how many at once (29.0.4).
    FLEET = "fleet"
    SCANNER_STARTED = "scanner-started"
    SCANNER_ENDED = "scanner-ended"
    #: A Scanner answered from its last result (R14.3, D32).
    REUSED = "reused"
    #: The budget spent, and what it stopped and kept from starting (R3.5).
    BUDGET = "budget"
    #: What git history was read for secrets, or why none was (R3.7).
    HISTORY = "history"
    #: Anything else said once: containers an ended scan left, removed; the File
    #: Set's warning; a fetch's own detail.
    NOTE = "note"


@dataclass(frozen=True, eq=False)
class Event:
    kind: Kind
    fields: Mapping[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return render(self)


def note(text: str) -> Event:
    return Event(Kind.NOTE, {"text": text})


def fetch_started(what: str, *, age_days: float | None, size_mb: int | None = None,
                  name: str = "") -> Event:
    """`what` is one of image, database, index, malicious, kev, epss, osv; `name`
    the image's reference or OSV's ecosystem; no age is a first fetch."""
    return Event(Kind.FETCH_STARTED, {"what": what, "name": name, "age_days": age_days,
                                      "size_mb": size_mb})


def fetch_ended(what: str, *, ok: bool = True, seconds: float = 0.0, detail: str = "",
                name: str = "", said: str = "") -> Event:
    """`said` is the update operation's own sentence, for KEV and EPSS, whose
    refresh `valvur update` runs and words too (F9.3)."""
    return Event(Kind.FETCH_ENDED, {"what": what, "name": name, "ok": ok,
                                    "seconds": seconds, "detail": detail, "said": said})


def workspace(files: int, largest: Iterable[tuple[str, int]]) -> Event:
    return Event(Kind.WORKSPACE, {"files": files, "largest": [tuple(x) for x in largest]})


def large_tree(top: str, count: int) -> Event:
    return Event(Kind.WORKSPACE, {"top": top, "count": count})


def fleet(count: int, at_once: int) -> Event:
    return Event(Kind.FLEET, {"count": count, "at_once": at_once})


def scanner_started(name: str) -> Event:
    return Event(Kind.SCANNER_STARTED, {"name": name})


def scanner_ended(name: str, *, ok: bool, seconds: float) -> Event:
    return Event(Kind.SCANNER_ENDED, {"name": name, "ok": ok, "seconds": seconds})


def reused(name: str, generation: str) -> Event:
    return Event(Kind.REUSED, {"name": name, "generation": generation})


def budget(spent: float, stopping: list[str], waiting: list[str]) -> Event:
    return Event(Kind.BUDGET, {"spent": spent, "stopping": list(stopping),
                               "waiting": list(waiting)})


def history_read(commits: int, size_bytes: int, bounded: str | None) -> Event:
    return Event(Kind.HISTORY, {"commits": commits, "bytes": size_bytes, "bounded": bounded})


def history_not_read(why: str) -> Event:
    return Event(Kind.HISTORY, {"why": why})


# ---------------------------------------------------------------------- the words

#: Each fetched dataset's name in a sentence, and in a short one.
_NOUN = {"database": "vulnerability database", "index": "package-name index",
         "malicious": "malicious list"}
_SHORT = {"database": "database", "index": "index", "malicious": "malicious list",
          "image": "image"}


def _mb(size: int | None) -> str:
    return f" ({size}MB)" if size else ""


def _fetch_started(f: Mapping[str, Any]) -> str:
    what, age, size, name = f["what"], f.get("age_days"), f.get("size_mb"), f.get("name")
    first = age is None
    if what == "image":
        return f"pulling {name}{_mb(size)} — the first run only; the runtime keeps it"
    if what == "kev":
        return "refreshing KEV" + (f" ({age:.0f} days old)" if not first else "")
    if what == "epss":
        return ("fetching EPSS scores (about 3MB) — the first run only" if first else
                f"refreshing EPSS ({age:.0f} days old)")
    if what == "osv":
        return (f"fetching the OSV database for {name} — the first run for it only" if first
                else f"refreshing the OSV database for {name} ({age:.0f} days old)")
    noun = _NOUN[what]
    mb = "" if what == "malicious" else _mb(size)
    return (f"fetching the {noun}{mb} — the first run only" if first else
            f"refreshing the {noun} ({age:.0f} days old){mb}")


def _fetch_ended(f: Mapping[str, Any]) -> str:
    what, ok, seconds = f["what"], f.get("ok", True), f.get("seconds", 0.0)
    if f.get("said"):
        return str(f["said"])
    if what == "image":
        return f"image pulled ({seconds:.0f}s)"
    if what == "osv":
        return (f"OSV database fetched for {f['name']} ({seconds:.0f}s)" if ok else
                f"OSV database not fetched for {f['name']}: {f.get('detail', '')}")
    short = _SHORT[what]
    if ok:
        return f"{short} fetched ({seconds:.0f}s)"
    return f"{short} not fetched" + (f": {f['detail']}" if f.get("detail") else "")


def workspace_body(event: Event) -> str:
    """A workspace event's words without their `workspace: ` lead, for the line
    `scan_status` gives them."""
    f = event.fields
    if "top" in f:
        top = f["top"]
        return (f"{top} holds {f['count']:,} of them — if it is not source, "
                f'`[scan] exclude = ["{top}"]` in `.security-scan.toml` drops it before the '
                "Scanners start")
    largest = ", ".join(f"{d} {n:,}" for d, n in f["largest"]) or "none"
    return f"{f['files']:,} files to scan; largest: {largest}"


def render(event: Event) -> str:
    """An event's words, as every surface shows them."""
    f = event.fields
    kind = event.kind
    if kind is Kind.FETCH_STARTED:
        return _fetch_started(f)
    if kind is Kind.FETCH_ENDED:
        return _fetch_ended(f)
    if kind is Kind.WORKSPACE:
        return f"workspace: {workspace_body(event)}"
    if kind is Kind.FLEET:
        return f"fleet: {f['count']} Scanners, {f['at_once']} at a time"
    if kind is Kind.SCANNER_STARTED:
        return f"{f['name']}: started"
    if kind is Kind.SCANNER_ENDED:
        return f"{f['name']}: {'ok' if f['ok'] else 'failed'} ({float(f['seconds']):.1f}s)"
    if kind is Kind.REUSED:
        return (f"{f['name']}: reused (its inputs and data are unchanged since run "
                f"{str(f['generation'])[:8]})")
    if kind is Kind.BUDGET:
        return (f"budget spent after {f['spent']:.0f}s: stopping "
                f"{', '.join(f['stopping']) or 'nothing'}"
                f"; not starting {', '.join(f['waiting']) or 'nothing'}")
    if kind is Kind.HISTORY:
        if "why" in f:
            return f"history: not read ({f['why']})"
        bound = f", stopped at {f['bounded']}" if f.get("bounded") else ""
        return (f"history: {f['commits']} commits read for secrets "
                f"({f['bytes'] / 2**20:.1f} MB{bound})")
    return str(f.get("text", ""))
