"""R15.2's smoke run of the Claude Code plugin (D36), repeatable at a release.

    uv run python scripts/acceptance/plugin_smoke.py [--from-tree]

`claude -p --plugin-dir plugins/valvur`, with no shell and a budget, in an empty
directory. The stream's first event lists what loaded; the run passes when the
plugin, its skill and its connected server are there, with every tool the server
should list. As shipped, the server is the release the plugin pins, from PyPI;
`--from-tree` runs a copy of the plugin whose server is this checkout. Each run's
cost goes to D36's ledger, and none starts once the cap is spent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLUGIN = REPO / "plugins" / "valvur"
SERVER = "plugin:valvur:valvur"
TOOL_PREFIX = "mcp__plugin_valvur_valvur__"
SKILL = "valvur:valvur"
PER_RUN_USD = 1.0


@dataclass(frozen=True)
class Smoke:
    loaded: bool
    version: str
    skill: bool
    connected: bool
    tools: list[str]
    missing: list[str] = field(default_factory=list)
    cost_usd: float = 0.0

    @property
    def ok(self) -> bool:
        return self.loaded and self.skill and self.connected and not self.missing


def judge(stream: str, *, expected: set[str]) -> Smoke:
    """The run, from its stream-json: the init event says what loaded."""
    events = [json.loads(line) for line in stream.splitlines() if line.strip()]
    init = next((e for e in events if e.get("type") == "system"
                 and e.get("subtype") == "init"), {})
    result = next((e for e in events if e.get("type") == "result"), {})
    plugin = next((p for p in init.get("plugins") or [] if p.get("name") == "valvur"), None)
    server = next((s for s in init.get("mcp_servers") or [] if s.get("name") == SERVER), {})
    tools = sorted(t.removeprefix(TOOL_PREFIX) for t in init.get("tools") or []
                   if t.startswith(TOOL_PREFIX))
    return Smoke(loaded=plugin is not None, version=str((plugin or {}).get("version", "")),
                 skill=SKILL in (init.get("skills") or []),
                 connected=server.get("status") == "connected", tools=tools,
                 missing=sorted(expected - set(tools)),
                 cost_usd=round(float(result.get("total_cost_usd") or 0.0), 2))


def command(plugin: Path, *, budget: float) -> list[str]:
    return ["claude", "-p", "Reply with the one word: ready.", "--plugin-dir", str(plugin),
            "--output-format", "stream-json", "--verbose", "--max-turns", "1",
            "--disallowedTools", "Bash", "--max-budget-usd", f"{budget:g}"]


def from_tree(plugin: Path, copy: Path) -> Path:
    """A copy of `plugin` whose server is this checkout's, not the pinned release."""
    shutil.copytree(plugin, copy)
    (copy / ".mcp.json").write_text(json.dumps({"mcpServers": {"valvur": {
        "command": "uv", "args": ["run", "--project", str(REPO), "valvur-mcp"]}}},
        indent=2) + "\n")
    return copy


def run(*, tree: bool) -> Smoke | None:
    """One smoke run; None when D36's cap is spent."""
    sys.path.insert(0, str(Path(__file__).parent))
    import agent  # type: ignore[import-not-found]

    from valvur.mcp.tools import registry

    left = agent.SCENARIO_CAP_USD - agent.spent(agent.SCENARIO_LEDGER)
    if left <= 0:
        return None
    with tempfile.TemporaryDirectory() as scratch:
        plugin = from_tree(PLUGIN, Path(scratch) / "plugin") if tree else PLUGIN
        empty = Path(scratch) / "empty"
        empty.mkdir()
        completed = subprocess.run(command(plugin, budget=min(PER_RUN_USD, left)),  # noqa: S603
                                   cwd=empty, capture_output=True, text=True,
                                   check=False, timeout=600)
    judged = judge(completed.stdout, expected={tool.name for tool in registry()})
    agent._record(judged.cost_usd, agent.SCENARIO_LEDGER)
    return judged


def main(argv: list[str] | None = None) -> int:
    tree = "--from-tree" in (sys.argv[1:] if argv is None else argv)
    judged = run(tree=tree)
    if judged is None:
        print("D36's cap is spent: the smoke run was not started")
        return 1
    print(f"{'from this tree' if tree else 'as shipped'}: plugin "
          f"{'loaded' if judged.loaded else 'NOT loaded'} ({judged.version}), skill "
          f"{'listed' if judged.skill else 'NOT listed'}, server "
          f"{'connected' if judged.connected else 'NOT connected'}; tools: "
          f"{', '.join(judged.tools) or 'none'}"
          + (f"; missing: {', '.join(judged.missing)}" if judged.missing else "")
          + f"; ${judged.cost_usd}")
    return 0 if judged.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
