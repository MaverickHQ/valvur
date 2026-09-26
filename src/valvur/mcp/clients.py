"""Every agent's IDE, by MCP (29.2.1): one table, and the snippet each client reads.

The README used to give one JSON block and name no file; the first gate's
participant had to find `.mcp.json` from `doctor`'s output. The table here is
what the README's section is rendered from and what `doctor` reads (29.2.2), so
the two cannot disagree — a test holds the README to it. Each entry says
whether the handshake was *measured* here or is the shape the client documents,
dated; the server speaks every protocol version the spec has published
(`protocol.SUPPORTED_VERSIONS`), and a transcript per version is committed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

#: What every client is told to run: the published shim, no install step.
COMMAND = "uvx"
ARGS = ("--from", "valvur", "valvur-mcp")
SERVER = "valvur"


@dataclass(frozen=True)
class Client:
    key: str
    name: str
    #: Where the client reads the snippet from — the project-level file first.
    files: tuple[str, ...]
    #: `json-mcpServers`, `json-servers`, `json-context_servers`, `toml`, `yaml`.
    shape: str
    #: What happens after the file is written, in the client's own terms.
    after: str
    #: How the handshake was verified — measured here, or the documented shape.
    verified: str


CLIENTS: tuple[Client, ...] = (
    Client("claude-code", "Claude Code",
           (".mcp.json", "~/.claude.json"), "json-mcpServers",
           "approve the project server once in an interactive `claude`; a headless or "
           "SDK session passes `--mcp-config .mcp.json --strict-mcp-config`",
           "measured 2026-09-26 at the first gate: connected from this block in under "
           "eight seconds; `claude mcp list` health-checks a project server only once "
           "it is approved"),
    Client("kiro", "Kiro",
           (".kiro/settings/mcp.json", "~/.kiro/settings/mcp.json"), "json-mcpServers",
           "`kiroAgent.configureMCP` must be `Enabled`; the server starts with the agent",
           "measured 2026-09-12 (task 22.F.2), and `doctor` reads Kiro's files"),
    Client("codex", "Codex",
           ("~/.codex/config.toml",), "toml",
           "or `codex mcp add valvur -- uvx --from valvur valvur-mcp`; the server "
           "starts with the next session",
           "documented shape, 2026-09-26; not run here"),
    Client("cursor", "Cursor",
           (".cursor/mcp.json", "~/.cursor/mcp.json"), "json-mcpServers",
           "enable the server under Settings → MCP; Cursor starts it on demand",
           "documented shape, 2026-09-26; not run here"),
    Client("vscode", "VS Code (Copilot agent mode)",
           (".vscode/mcp.json",), "json-servers",
           "the key is `servers`, not `mcpServers`; start it from the file's inline "
           "*Start* action or trust the workspace",
           "documented shape, 2026-09-26; not run here"),
    Client("windsurf", "Windsurf",
           ("~/.codeium/windsurf/mcp_config.json",), "json-mcpServers",
           "refresh the MCP panel; Windsurf starts it on demand",
           "documented shape, 2026-09-26; not run here"),
    Client("cline", "Cline",
           ("cline_mcp_settings.json (under the extension's global storage)",),
           "json-mcpServers",
           "edit through the extension's MCP Servers panel, which opens this file",
           "documented shape, 2026-09-26; not run here"),
    Client("roo", "Roo Code",
           (".roo/mcp.json",), "json-mcpServers",
           "the extension reloads the file on save",
           "documented shape, 2026-09-26; not run here"),
    Client("continue", "Continue",
           (".continue/config.yaml", "~/.continue/config.yaml"), "yaml",
           "YAML, under `mcpServers:`; reload the config from the extension",
           "documented shape, 2026-09-26; not run here"),
    Client("gemini-cli", "Gemini CLI",
           (".gemini/settings.json", "~/.gemini/settings.json"), "json-mcpServers",
           "`/mcp` in the CLI lists it; the server starts with the session",
           "documented shape, 2026-09-26; not run here"),
    Client("zed", "Zed",
           ("~/.config/zed/settings.json",), "json-context_servers",
           "the key is `context_servers`; the assistant panel lists it",
           "documented shape, 2026-09-26; not run here"),
)


#: Where the files are on disk, per client, with `~` the home directory,
#: `{code-storage}` VS Code's global storage (an extension's settings live there)
#: and everything else relative to the workspace (29.2.2). Descriptive names in
#: `files` above are for people; these are for `doctor`.
LOOKUPS: dict[str, tuple[str, ...]] = {
    "claude-code": (".mcp.json", "~/.claude.json"),
    "kiro": (".kiro/settings/mcp.json", "~/.kiro/settings/mcp.json"),
    "codex": ("~/.codex/config.toml",),
    "cursor": (".cursor/mcp.json", "~/.cursor/mcp.json"),
    "vscode": (".vscode/mcp.json",),
    "windsurf": ("~/.codeium/windsurf/mcp_config.json",),
    "cline": ("{code-storage}/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",),
    "roo": (".roo/mcp.json",),
    "continue": (".continue/config.yaml", "~/.continue/config.yaml"),
    "gemini-cli": (".gemini/settings.json", "~/.gemini/settings.json"),
    "zed": ("~/.config/zed/settings.json",),
}


def code_storage(home, system: str):
    """VS Code's global storage directory on this platform."""
    if system == "Darwin":
        return home / "Library" / "Application Support" / "Code" / "User" / "globalStorage"
    if system == "Windows":
        return home / "AppData" / "Roaming" / "Code" / "User" / "globalStorage"
    return home / ".config" / "Code" / "User" / "globalStorage"


def lookups(entry: Client, workspace, home, system: str):
    """(label, path) pairs for `doctor`: the label as a person would write it."""
    out = []
    for pattern in LOOKUPS[entry.key]:
        if pattern.startswith("~/"):
            out.append((pattern, home / pattern[2:]))
        elif pattern.startswith("{code-storage}/"):
            tail = pattern[len("{code-storage}/"):]
            out.append((f"VS Code global storage: {tail}", code_storage(home, system) / tail))
        else:
            out.append((pattern, workspace / pattern))
    return out


def client(key: str) -> Client:
    for entry in CLIENTS:
        if entry.key == key:
            return entry
    raise KeyError(f"no such client: {key}; one of {', '.join(c.key for c in CLIENTS)}")


def snippet(entry: Client) -> str:
    """The text a user pastes into that client's file, exactly."""
    stdio = {"command": COMMAND, "args": list(ARGS)}
    if entry.shape == "json-mcpServers":
        body: dict = {"mcpServers": {SERVER: stdio}}
        if entry.key == "kiro":
            body["mcpServers"][SERVER].update({"disabled": False, "autoApprove": []})
        return json.dumps(body, indent=2) + "\n"
    if entry.shape == "json-servers":
        return json.dumps({"servers": {SERVER: {"type": "stdio", **stdio}}}, indent=2) + "\n"
    if entry.shape == "json-context_servers":
        return json.dumps({"context_servers": {SERVER: {"source": "custom", **stdio}}},
                          indent=2) + "\n"
    if entry.shape == "toml":
        args = ", ".join(f'"{a}"' for a in ARGS)
        return f'[mcp_servers.{SERVER}]\ncommand = "{COMMAND}"\nargs = [{args}]\n'
    if entry.shape == "yaml":
        args = "".join(f"      - {a}\n" for a in ARGS)
        return f"mcpServers:\n  - name: {SERVER}\n    command: {COMMAND}\n    args:\n{args}"
    raise ValueError(f"unknown shape {entry.shape!r}")


def fence(entry: Client) -> str:
    return {"toml": "toml", "yaml": "yaml"}.get(entry.shape, "json")


README_START = ("<!-- clients:start — rendered from valvur.mcp.clients; a test holds this "
                "block to it -->")
README_END = "<!-- clients:end -->"


def readme_section() -> str:
    """The README's client-by-client block, rendered from the table."""
    lines = [README_START, ""]
    for entry in CLIENTS:
        files = " or ".join(f"`{f}`" for f in entry.files)
        lines += [f"**{entry.name}** — {files}. {entry.after.capitalize()}. "
                  f"*{entry.verified.capitalize()}.*", "",
                  f"```{fence(entry)}", snippet(entry).rstrip("\n"), "```", ""]
    lines.append(README_END)
    return "\n".join(lines) + "\n"
