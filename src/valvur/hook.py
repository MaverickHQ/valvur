"""The `check_package` hook: an install asks first (R18.3, D44; F3.16).

Claude Code runs `valvur-hook` before every `Bash` call an agent makes, with the call as
JSON on stdin (code.claude.com/docs/en/hooks.md, read 2026-10-02). When the command
installs a package that `valvur check` would flag, the hook answers `ask`, naming each
package's verdict, and the human decides. Otherwise it says nothing, and the usual
permission flow applies.

What it never does, by D44: answer `deny`, run or change the command, or open a socket.
The answers come from this machine's index, as `check_package`'s do. When it cannot
check, because there is no index, it asks rather than say nothing, so the check is never
silently off. The CLI keeps its nine commands: this is a script of its own, beside
`valvur-mcp`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from . import installs
from . import packages as _packages


def answer(event: dict) -> dict | None:
    """Claude Code's decision for one `PreToolUse` event, or None to say nothing."""
    if event.get("tool_name") != "Bash":
        return None
    command = str((event.get("tool_input") or {}).get("command") or "")
    cwd = Path(str(event.get("cwd") or "."))
    asked = installs.packages(command, cwd)
    if not asked:
        return None
    answers = _packages.check(asked[:_packages.MOST], workspace=cwd if cwd.is_dir() else None)
    flagged = [a for a in answers if a.flagged]
    unchecked = [a for a in answers if a.verdict == "unknown" and "valvur update" in a.reason]
    if not flagged and not unchecked:
        return None
    lines = ["valvur checked this install before it runs (offline, from this machine's "
             "index):"]
    lines += [f"- {a.ecosystem} `{a.name}`: {a.verdict}. {a.reason}" for a in flagged]
    if unchecked:
        lines.append("- valvur could not check "
                     + ", ".join(f"`{a.name}`" for a in unchecked)
                     + f": {unchecked[0].reason}")
    if len(asked) > _packages.MOST:
        lines.append(f"- only the first {_packages.MOST} of {len(asked)} packages were "
                     "checked")
    lines.append("Install only if these are the packages you meant; a flagged name may be "
                 "a typo, an invented package, or a malicious one.")
    return _ask("\n".join(lines))


def _ask(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "ask",
                                   "permissionDecisionReason": reason}}


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None,
         stdout: TextIO | None = None) -> int:
    """Read one event, print the decision when there is one, exit 0. Never exit 2:
    that would block the call, which is the human's to decide (D44)."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        event = json.load(stdin)
    except ValueError:
        return 0
    decision = answer(event) if isinstance(event, dict) else None
    if decision is not None:
        stdout.write(json.dumps(decision) + "\n")
    return 0
