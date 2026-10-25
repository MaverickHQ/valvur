"""The files an agent obeys — the names the AI Artifact Check reads (23.5.1).

A leaf on purpose: `exclusions` needs them too (a `.gitignore` opt-in must keep
reading a hidden `.mcp.json`, 29.0.1), and importing the Check from there would
close a cycle the ratchet refuses. Nothing here imports anything.
"""

from __future__ import annotations

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
    # 1.6.0: the folder agents share. Codex reads skills from `.agents/skills/` alone,
    # VS Code beside `.claude/skills/` (their documentation, read 2026-10-25).
    ".agents",
}
# Kiro (23.5.1): three of its folders are what the agent acts on unprompted —
# steering files, hooks, MCP settings. `specs/` is the project's own documents, read
# on request like any other file; this repository's own tasks.md contains the phrase
# "ignore previous instructions" in the sentence specifying this rule, so reading
# `specs/` would fail our own gate with our own words.
KIRO_DIRS = {"steering", "hooks", "settings"}
# GitHub Copilot (1.6.0, its documentation read 2026-10-25): under `.github/`, the
# instructions files VS Code attaches by their `applyTo` glob, and its skills. The
# rest of `.github/` is the project's CI, which zizmor reads, not prose an agent obeys.
GITHUB_DIRS = {"instructions", "skills"}


def under(parts: tuple[str, ...], *chain: str) -> bool:
    """Whether the path has `chain` as consecutive directory components — so
    `apps/web/.kiro/hooks/x.json` is a Kiro hook and `.kiro/specs/x.md` is not."""
    dirs = parts[:-1]
    return any(dirs[i:i + len(chain)] == chain for i in range(len(dirs) - len(chain) + 1))
