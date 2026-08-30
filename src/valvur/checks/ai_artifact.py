"""Agent instruction and configuration files — the AI-native attack surface.

Nothing else in the fleet looks at these files. They are the channel by which a
repository talks to whatever agent opens it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..defang import describe_invisible, is_invisible, neutralise

ARTIFACT_NAMES = {
    "CLAUDE.md", "AGENTS.md", "AGENT.md", ".cursorrules", ".windsurfrules",
    ".mcp.json", "SKILL.md", "copilot-instructions.md", "GEMINI.md",
}
ARTIFACT_DIRS = {".claude", ".cursor", ".codex", ".gemini"}

# Phrases whose only purpose is to override a prior instruction. Deliberately narrow:
# a false positive here accuses someone of planting an attack.
INJECTION = re.compile(
    r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+"
    r"(instructions?|prompts?|rules?|directions?)",
    re.IGNORECASE,
)
BYPASS = re.compile(
    r"(--dangerously-skip-permissions|bypassPermissions|--yolo|"
    r"disable\s+(all\s+)?(safety|guardrails|security))",
    re.IGNORECASE,
)
MUTABLE_REF = re.compile(r"git\+[^\s\"']+@(main|master|HEAD|develop)\b")


class AiArtifactCheck:
    name = "ai-artifact"

    def run(self, workspace: Path) -> list[dict]:
        findings: list[dict] = []
        for path in _artifact_files(workspace):
            rel = str(path.relative_to(workspace))
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            findings += _hidden_unicode(text, rel)
            findings += _directives(text, rel)
            if path.name == ".mcp.json":
                findings += _mcp_config(text, rel)
        return findings


def _artifact_files(workspace: Path) -> list[Path]:
    found = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        parts = set(path.relative_to(workspace).parts)
        if path.name in ARTIFACT_NAMES or parts & ARTIFACT_DIRS:
            found.append(path)
    return found


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
        "path": rel,
        "line": first_line,
        "title": (
            f"Hidden Unicode in an agent instruction file "
            f"({len(lines)} line(s); {describe_invisible(text)})"
        ),
        # Escaped, not reproduced: an invisible character copied into our own output
        # would carry the attack forward (F3.13).
        "evidence": neutralise(content),
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
                    "path": rel,
                    "line": n,
                    "title": title,
                    "evidence": neutralise(line),
                    "identity": ("ai_artifact", rule, rel, str(n)),
                })
    return findings


def _mcp_config(text: str, rel: str) -> list[dict]:
    findings = []
    if MUTABLE_REF.search(text):
        findings.append({
            "rule": "valvur.ai-artifact.mcp-mutable-ref",
            "path": rel,
            "line": 0,
            "title": "MCP server pinned to a mutable git ref",
            "evidence": neutralise(MUTABLE_REF.search(text).group(0)),
            "identity": ("ai_artifact", "mcp-mutable-ref", rel),
        })
    try:
        config = json.loads(text)
    except json.JSONDecodeError:
        return findings
    for server, spec in (config.get("mcpServers") or {}).items():
        approved = spec.get("autoApprove") or []
        if approved:
            findings.append({
                "rule": "valvur.ai-artifact.blanket-auto-approve",
                "path": rel,
                "line": 0,
                "title": f"MCP server '{server}' auto-approves {len(approved)} tool(s)",
                "evidence": neutralise(", ".join(map(str, approved))),
                "identity": ("ai_artifact", "blanket-auto-approve", rel, server),
            })
    return findings
