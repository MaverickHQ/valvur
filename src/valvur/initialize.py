"""`valvur init`: prints; with `--write`, writes what it prints (D10, R6.8).

For each MCP client found on this machine or in this project, the file it reads and
the block to paste, from the one table the README renders from; and a starter
`.security-scan.toml`, its excludes suggested from the pre-flight count and left
commented, because an exclusion hides a directory from every Scanner and is the
human's to decide (CLAUDE.md §4).

`--write` was the owner's to allow, and was allowed on 2026-09-28 (CLAUDE.md §10). It
writes the starter when there is none, and the valvur server into each client's file
in the project, beside what is there. It never overwrites: a file already naming
valvur is left, a file it cannot read is left and said, and a client whose file
lives outside the project is said, not written.
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


def write(workspace: Path, keys: list[str] | None = None) -> tuple[list[str], bool]:
    """What `init --write` did, a line each, and whether all of it could be done:
    the project file, then each client named, or each found here (Claude Code when
    none is)."""
    from .mcp import clients as _clients

    lines: list[str] = []
    policy = workspace / ".security-scan.toml"
    if policy.exists():
        lines.append("left .security-scan.toml as it is")
    else:
        policy.write_text(starter(workspace), encoding="utf-8")
        lines.append("wrote .security-scan.toml")
    chosen = ([_clients.client(key) for key in keys] if keys else
              _clients.found(workspace, Path.home(), platform.system())
              or [_clients.client("claude-code")])
    ok = True
    for entry in chosen:
        line, done = _write_client(workspace, entry)
        lines.append(line)
        ok = ok and done
    return lines, ok


def _write_client(workspace: Path, entry) -> tuple[str, bool]:
    """The valvur server into `entry`'s file in the project, merged; never over a
    file that names it already or that cannot be read."""
    import json

    from .mcp import clients as _clients

    local = next((f for f in entry.files if not f.startswith("~") and " " not in f), None)
    if local is None:
        return (f"{entry.name} reads {' or '.join(entry.files)}, outside the project: not "
                "written; add the block `valvur init` prints", False)
    if not entry.shape.startswith("json-"):
        return (f"left {local} as it is: {entry.shape.upper()}, which init does not edit; add "
                "the block `valvur init` prints", False)
    block = json.loads(_clients.snippet(entry))
    key = next(iter(block))
    path = workspace / local
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_clients.snippet(entry), encoding="utf-8")
        return f"wrote {local}", True
    try:
        present = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"left {local} as it is: not valid JSON ({exc}); add the block by hand", False
    if not isinstance(present, dict) or not isinstance(present.get(key, {}), dict):
        return f"left {local} as it is: its `{key}` is not an object", False
    if _clients.SERVER in present.get(key, {}):
        return f"left {local} as it is: it already names valvur", True
    present.setdefault(key, {})[_clients.SERVER] = block[key][_clients.SERVER]
    path.write_text(json.dumps(present, indent=2) + "\n", encoding="utf-8")
    return f"added valvur to {local}", True

