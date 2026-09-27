"""Agent scoring (task R2.4): one `claude -p` sentence per acceptance repository.

Opt-in, because it needs a Claude login and costs money: D19 caps the build at $25,
and the running total is kept in the build cache. A run records turns, cost, seconds,
whether the answer names every expected finding, and the containers left.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SENTENCE = "Scan this project with valvur and tell me what it found."
CAP_USD = 25.0
LEDGER = Path(os.environ.get("HOME", "~")) / ".cache" / "valvur-build" / "agent-cost.json"
TOOLS = ",".join(f"mcp__valvur__{t}" for t in (
    "scan", "scan_status", "scan_cancel", "list_findings", "explain_finding", "doctor")) \
    + ",Read"


@dataclass
class AgentScore:
    turns: int
    cost_usd: float
    seconds: float
    named_all: bool
    unnamed: list[str] = field(default_factory=list)
    containers_left: int = 0


def _ticked(tasks_text: str) -> set[str]:
    return set(re.findall(r"^- \[[xX]\] \*\*(R\d+\.\d+)\*\*", tasks_text, re.M))


def score(result: dict, expected: dict, tasks_text: str) -> AgentScore:
    """How the agent did: turns, cost, time, and each live expected finding named in
    its answer by path (or by rule where the expectation has no path)."""
    answer = str(result.get("result", ""))
    done = _ticked(tasks_text)
    unnamed = []
    for must in expected.get("must", []):
        if must.get("until") and must["until"] not in done:
            continue
        name = must.get("path") or must["rule"]
        if name not in answer:
            unnamed.append(name)
    return AgentScore(int(result.get("num_turns", 0)),
                      round(float(result.get("total_cost_usd", 0.0)), 2),
                      round(int(result.get("duration_ms", 0)) / 1000, 1),
                      not unnamed, unnamed)


def spent() -> float:
    try:
        return float(json.loads(LEDGER.read_text()).get("usd", 0.0))
    except (OSError, ValueError):
        return 0.0


def _record(usd: float) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(json.dumps({"usd": round(spent() + usd, 2)}))


def run(root: Path, tasks_text: str) -> AgentScore | None:
    """One `claude -p` sentence against `root`, through this checkout's shim. None when
    the cap is reached, which is reported, not an error."""
    import tomllib

    if spent() >= CAP_USD:
        return None
    config = {"mcpServers": {"valvur": {
        "command": "uv", "args": ["run", "--project", str(REPO), "valvur-mcp"],
        "env": {key: os.environ[key] for key in ("VALVUR_IMAGE", "VALVUR_CACHE")
                if key in os.environ}}}}
    (root / ".mcp.json").write_text(json.dumps(config, indent=2))
    completed = subprocess.run(  # noqa: S603 — the Claude CLI, fixed arguments
        ["claude", "-p", SENTENCE, "--mcp-config", ".mcp.json", "--strict-mcp-config",
         "--max-turns", "40", "--output-format", "json", "--allowedTools", TOOLS],
        cwd=root, capture_output=True, text=True, check=False, timeout=1800)
    try:
        result = json.loads(completed.stdout)
    except ValueError:
        result = {"result": completed.stdout[-2000:], "num_turns": 0}
    _record(float(result.get("total_cost_usd", 0.0)))
    expected = tomllib.loads((root / "expected.toml").read_text())
    return score(result, expected, tasks_text)
