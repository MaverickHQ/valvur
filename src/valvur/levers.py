"""What a user can turn when a scan does not finish (29.0.3).

One sentence, in one place: the refusal a budget raises, `SUMMARY.md`'s cut
block and the README name the same three levers, and a test holds all three
to this module. A leaf on purpose — `api` and `summary` both import it.

Measured at the first gate: the 300 s default budget cut every Scanner on a
107,544-file working tree, and nothing on any surface named `[scan] exclude`,
`budget_s` or `VALVUR_JOBS`; the participant found them by reading the source.
"""

from __future__ import annotations

#: The three things that make a scan finish, in the order they usually help.
LEVERS = (
    "To finish: exclude what is not source (`[scan] exclude` in `.security-scan.toml`), "
    "give it longer (`budget_s` on the `scan` call; `--budget` on the CLI), or run "
    "fewer Scanners at once (`VALVUR_JOBS`, `--jobs`)."
)


def budget_exhausted_message(scanners, budget_s: float) -> str:
    """The refusal when the budget cut every Scanner: what ran and for how long,
    what never started, and the levers — never *every scanner failed*, which is
    what killing them looks like from inside, and never *run doctor*, which says
    *ready* on a machine that is."""
    cut = [s for s in scanners if s.reason.startswith("cut by the ")]
    unstarted = [s for s in scanners if s.reason.startswith("not started: ")]
    ran = ", ".join(f"{s.tool} {s.duration_s:.0f}s" for s in cut) or "nothing"
    parts = [f"the {budget_s:g}s budget ran out before any Scanner finished: "
             f"{len(cut)} cut ({ran})"]
    if unstarted:
        parts.append(f"{len(unstarted)} not started ({', '.join(s.tool for s in unstarted)})")
    return "; ".join(parts) + "; none finished. " + LEVERS
