"""Agent instruction and configuration files — the AI-native attack surface.

Nothing else in the fleet looks at these files. They are the channel by which a
repository talks to whatever agent opens it.

Two kinds of surface, and the second is the sharper one (task 23.5.1). *Instruction*
files are read for what they say: an override directive, a permission bypass, hidden
Unicode. *Hooks* are read for what they do: a committed hook that runs a shell command
on a file event makes every agent that opens the repository execute it, unprompted —
an autonomous-execution surface, exactly §4's concern. Kiro keeps them in
`.kiro/hooks/`, Claude Code in `.claude/settings.json`, aider as `lint-cmd`/`test-cmd`;
one rule, `hook-runs-command`, at high, with the command as fenced evidence.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..defang import describe_invisible, is_invisible, neutralise
from .base import Check

# F3.6: the agent instruction and configuration files this Check reads.
ARTIFACT_NAMES = {
    "CLAUDE.md", "AGENTS.md", "AGENT.md", ".cursorrules", ".windsurfrules",
    ".mcp.json", "SKILL.md", "copilot-instructions.md", "GEMINI.md",
    # 23.5.1 — Cline (single-file form), Roo Code's modes, aider.
    ".clinerules", ".roomodes", ".aider.conf.yml",
}
# Every file under these is an agent surface. `.clinerules` is also a directory form.
ARTIFACT_DIRS = {
    ".claude", ".cursor", ".codex", ".gemini",
    ".clinerules", ".roo", ".continue", ".windsurf",
}
# Kiro (23.5.1): three of its folders are what the agent acts on unprompted —
# steering files, hooks, MCP settings. `specs/` is the project's own documents, read
# on request like any other file; this repository's own tasks.md contains the phrase
# "ignore previous instructions" in the sentence specifying this rule, so reading
# `specs/` would fail our own gate with our own words.
KIRO_DIRS = {"steering", "hooks", "settings"}
#: MCP settings files read for `autoApprove` (F3.9) and mutable refs (F3.8), by the
#: key each client uses: `autoApprove` (Kiro, and the same shape under `.mcp.json`),
#: `alwaysAllow` (Roo Code).
MCP_FILES = {".mcp.json", ".kiro/settings/mcp.json", ".roo/mcp.json"}
AUTO_APPROVE_KEYS = ("autoApprove", "alwaysAllow")

# Phrases whose only purpose is to override a prior instruction. Deliberately narrow:
# a false positive here accuses someone of planting an attack.
INJECTION = re.compile(
    r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+"
    r"(instructions?|prompts?|rules?|directions?)",
    re.IGNORECASE,
)
# F3.9: blanket auto-approval (below, `autoApprove`) and permission-bypass directives.
BYPASS = re.compile(
    r"(--dangerously-skip-permissions|bypassPermissions|--yolo|"
    r"disable\s+(all\s+)?(safety|guardrails|security))",
    re.IGNORECASE,
)
MUTABLE_REF = re.compile(r"git\+[^\s\"']+@(main|master|HEAD|develop)\b")
# aider: `yes-always` answers every confirmation on the user's behalf (F3.9);
# `lint-cmd` and `test-cmd` run after each edit aider makes. YAML read by line, not
# by a parser — the shim has no dependencies, and these keys are flat.
AIDER_YES_ALWAYS = re.compile(r"^\s*yes-always\s*:\s*true\b", re.IGNORECASE | re.MULTILINE)
AIDER_COMMAND_KEYS = ("lint-cmd", "test-cmd")


class AiArtifactCheck(Check):
    name = "ai-artifact"

    def run(self, workspace: Path) -> list[dict]:
        findings: list[dict] = []
        for path in _artifact_files(workspace):
            rel = path.relative_to(workspace).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            findings += _hidden_unicode(text, rel)
            findings += _directives(text, rel)
            parts = path.relative_to(workspace).parts
            if path.name == ".mcp.json" or _tail(parts, 3) in MCP_FILES:
                findings += _mcp_config(text, rel)
            if _under(parts, ".kiro", "hooks"):
                findings += _kiro_hooks(text, rel)
            if ".claude" in parts[:-1] and path.name in ("settings.json", "settings.local.json"):
                findings += _claude_hooks(text, rel)
            if path.name == ".aider.conf.yml":
                findings += _aider_config(text, rel)
        return findings


def _artifact_files(workspace: Path) -> list[Path]:
    found = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        parts = path.relative_to(workspace).parts
        if (path.name in ARTIFACT_NAMES or set(parts[:-1]) & ARTIFACT_DIRS
                or any(_under(parts, ".kiro", d) for d in KIRO_DIRS)):
            found.append(path)
    return found


def _tail(parts: tuple[str, ...], n: int) -> str:
    return "/".join(parts[-n:])


def _under(parts: tuple[str, ...], *chain: str) -> bool:
    """Whether the path has `chain` as consecutive directory components — so
    `apps/web/.kiro/hooks/x.json` is a Kiro hook and `.kiro/specs/x.md` is not."""
    dirs = parts[:-1]
    return any(dirs[i:i + len(chain)] == chain for i in range(len(dirs) - len(chain) + 1))


def _hidden_unicode(text: str, rel: str) -> list[dict]:
    lines = [
        (n, line) for n, line in enumerate(text.splitlines(), 1)
        if any(is_invisible(c) for c in line)
    ]
    if not lines:
        return []
    first_line, content = lines[0]
    return [{
        "rule": "valvur.ai-artifact.hidden-unicode",
        "severity": "high",
        "path": rel,
        "line": first_line,
        "title": (
            f"Hidden Unicode in an agent instruction file "
            f"({len(lines)} line(s); {describe_invisible(text)})"
        ),
        # Escaped, not reproduced: an invisible character copied into our own output
        # would carry the attack forward (F3.13).
        "evidence": neutralise(content, always_fence=True),
        "identity": ("ai_artifact", "hidden-unicode", rel),
    }]


def _directives(text: str, rel: str) -> list[dict]:
    findings = []
    for n, line in enumerate(text.splitlines(), 1):
        for pattern, rule, title in (
            (INJECTION, "prompt-injection", "Instruction-override directive in an agent file"),
            (BYPASS, "permission-bypass", "Permission-bypass directive in an agent file"),
        ):
            if pattern.search(line):
                findings.append({
                    "rule": f"valvur.ai-artifact.{rule}",
                    "severity": "high",
                    "path": rel,
                    "line": n,
                    "title": title,
                    "evidence": neutralise(line, always_fence=True),
                    "identity": ("ai_artifact", rule, rel, str(n)),
                })
    return findings


def _mcp_config(text: str, rel: str) -> list[dict]:
    findings = []
    mutable = MUTABLE_REF.search(text)
    if mutable:
        findings.append({
            "rule": "valvur.ai-artifact.mcp-mutable-ref",
            "severity": "medium",
            "path": rel,
            "line": 0,
            "title": "MCP server pinned to a mutable git ref",
            "evidence": neutralise(mutable.group(0), always_fence=True),
            "identity": ("ai_artifact", "mcp-mutable-ref", rel),
        })
    try:
        config = json.loads(text)
    except json.JSONDecodeError:
        return findings
    servers = config.get("mcpServers") if isinstance(config, dict) else None
    for server, spec in (servers or {}).items():
        if not isinstance(spec, dict):
            continue
        approved: list = next((spec[k] for k in AUTO_APPROVE_KEYS if spec.get(k)), [])
        if approved:
            findings.append({
                "rule": "valvur.ai-artifact.blanket-auto-approve",
                "severity": "high",
                "path": rel,
                "line": 0,
                "title": f"MCP server '{server}' auto-approves {len(approved)} tool(s)",
                "evidence": neutralise(", ".join(map(str, approved)), always_fence=True),
                "identity": ("ai_artifact", "blanket-auto-approve", rel, server),
            })
    return findings


def _hook(rel: str, event: str, name: str, command: str) -> dict:
    """One committed hook that runs a shell command on an event (23.5.1)."""
    return {
        "rule": "valvur.ai-artifact.hook-runs-command",
        "severity": "high",
        "path": rel,
        "line": 0,
        "title": (
            f"Agent hook runs a shell command on {event}: '{name}' in {rel.rsplit('/', 1)[-1]}"
        ),
        # The command is workspace content and is exactly the kind of text an agent
        # might act on if it met it as prose (F3.13).
        "evidence": neutralise(command, always_fence=True),
        "identity": ("ai_artifact", "hook-runs-command", rel, name),
    }


def _kiro_hooks(text: str, rel: str) -> list[dict]:
    """Both shapes Kiro has shipped. A hooks file (`version: v1`, a `hooks` list,
    each with a `trigger` and an `action` of type `command` or `agent`), and the
    older one-hook-per-file `.kiro.hook` (`when`/`then`, `then.type` of `runCommand`
    or `askAgent`). An agent-type hook is a prompt; `_directives` already reads it."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings = []
    hooks = data.get("hooks")
    if isinstance(hooks, list):
        for index, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                continue
            action = hook.get("action") or {}
            if not (isinstance(action, dict) and action.get("type") == "command"):
                continue
            if action.get("command"):
                findings.append(_hook(rel, str(hook.get("trigger") or "an event"),
                                      str(hook.get("name") or index), str(action["command"])))
    then = data.get("then")
    if isinstance(then, dict) and then.get("type") == "runCommand" and then.get("command"):
        when = data.get("when") or {}
        event = str(when.get("type") or "an event") if isinstance(when, dict) else "an event"
        findings.append(_hook(rel, event, str(data.get("name") or "hook"), str(then["command"])))
    return findings


def _claude_hooks(text: str, rel: str) -> list[dict]:
    """`.claude/settings.json`: `hooks.<Event>[i].hooks[j]` with `type: command`.
    The other handler types — `prompt`, `agent`, `http`, `mcp_tool` — do not run a
    shell; a prompt handler's text is read by `_directives` like any other."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    events = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(events, dict):
        return []
    findings = []
    for event, groups in events.items():
        if not isinstance(groups, list):
            continue
        for i, group in enumerate(groups):
            handlers = group.get("hooks") if isinstance(group, dict) else None
            for j, handler in enumerate(handlers or []):
                if (isinstance(handler, dict) and handler.get("type") == "command"
                        and handler.get("command")):
                    findings.append(_hook(rel, str(event), f"{event}/{i}/{j}",
                                          str(handler["command"])))
    return findings


def _aider_config(text: str, rel: str) -> list[dict]:
    findings = []
    if AIDER_YES_ALWAYS.search(text):
        line = next(n for n, row in enumerate(text.splitlines(), 1) if "yes-always" in row)
        findings.append({
            "rule": "valvur.ai-artifact.permission-bypass",
            "severity": "high",
            "path": rel,
            "line": line,
            "title": "Permission-bypass directive in an agent file",
            "evidence": neutralise("yes-always: true", always_fence=True),
            "identity": ("ai_artifact", "permission-bypass", rel, str(line)),
        })
    lines = text.splitlines()
    for key in AIDER_COMMAND_KEYS:
        for n, row in enumerate(lines):
            head = re.match(rf"^\s*{re.escape(key)}\s*:\s*(.*)$", row)
            if not head:
                continue
            value = head.group(1).strip()
            if not value:
                # A list: the indented `- ` items that follow.
                items = []
                for following in lines[n + 1:]:
                    entry = re.match(r"^\s+-\s*(.+)$", following)
                    if not entry:
                        break
                    items.append(entry.group(1).strip())
                value = "; ".join(items)
            if value:
                findings.append(_hook(rel, "every edit", key, value))
            break
    return findings
