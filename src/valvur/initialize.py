"""`valvur init`: prints, never writes (D10, R6.8).

For each MCP client found on this machine or in this project, the file it reads and
the block to paste, from the one table the README renders from; and a starter
`.security-scan.toml`, its excludes suggested from the pre-flight count and left
commented, because an exclusion hides a directory from every Scanner and is the
human's to decide (CLAUDE.md §4). Whether `init` may write is the owner's decision
(tasks.md §8), so nothing on disk changes.
"""

from __future__ import annotations

import platform
from pathlib import Path

#: A directory holding more than this share of the files is suggested as an exclude.
SUGGEST_SHARE = 0.5


def render(workspace: Path) -> str:
    from .mcp import clients as _clients

    lines = ["valvur init prints and writes nothing: paste what you choose.", ""]
    present = _clients.found(workspace, Path.home(), platform.system())
    if not present:
        lines += ["No MCP client configuration was found in this project or in your home "
                  "directory; the two valvur is built for:", ""]
        present = [_clients.client("claude-code"), _clients.client("kiro")]
    for entry in present:
        lines += [f"{entry.name} reads {' or '.join(entry.files)}:", "",
                  f"```{_clients.fence(entry)}", _clients.snippet(entry).rstrip("\n"), "```",
                  "", f"Then: {entry.after}.", ""]
    lines += [f"A starter `.security-scan.toml` for {workspace.name}, committed with it:",
              "", "```toml", starter(workspace).rstrip("\n"), "```"]
    return "\n".join(lines) + "\n"


def starter(workspace: Path) -> str:
    """The project file, every choice stated and every default left as it is."""
    from . import fileset
    from .refusal import Refusal

    try:
        files = fileset.build(workspace).files
    except Refusal:
        files = fileset.walk(workspace)          # past the ceiling: this is when it matters
    largest = fileset.largest(files)
    counts = " · ".join(f"{name if name == '.' else name + '/'} {n:,}" for name, n in largest)
    suggest = [name for name, n in largest
               if name != "." and files and n / len(files) > SUGGEST_SHARE]
    lines = [
        "# This project's scan policy (valvur), committed with the project.",
        "",
        "[scan]",
        "# The git view is read (ADR-0021); `scope = \"tree\"` walks the folder instead.",
        "# Git history is read for secrets; `history = false` turns that off.",
        f"# The largest directories here, by files: {counts or 'none'}.",
        "# Exclude only what is not source (generated data, vendored trees, planted",
        "# fixtures), and only when the project's owner agrees: an exclusion hides a",
        "# directory from every Scanner.",
    ]
    if suggest:
        lines.append("# exclude = [" + ", ".join(f'"{name}"' for name in suggest) + "]")
    lines += [
        "exclude = []",
        "",
        "# An accepted risk, once a human has reviewed it; `valvur suppress` prints one.",
        "# [[suppress]]",
        "# fingerprint = \"...\"",
        "# rule = \"...\"",
        "# path = \"...\"",
        "# expires = 2027-01-01",
        "# reason = \"why this risk is accepted\"",
    ]
    return "\n".join(lines) + "\n"
