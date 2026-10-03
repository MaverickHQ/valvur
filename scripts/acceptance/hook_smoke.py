"""R18.4's smoke run of the plugin's hook (D46), repeatable.

    uv run python scripts/acceptance/hook_smoke.py [--as-shipped]

`claude -p` with a copy of the plugin, whose server and hook are this checkout's, and
the `Bash` tool allowed, is asked to install a made-up npm package in an empty scratch
directory. Every installer, `curl` and `wget` is a stub first on `PATH` that records
its arguments and exits, so no package can be installed. The plugin's server runs
through the real `uv`, by absolute path. The run passes when the stream shows the hook
stopping the call and the stubs recorded no install of the name. Its cost goes to
D46's ledger, and none starts once the $5 cap is spent.

`--as-shipped`, after a release, runs the plugin exactly as published: its server and
its hook are the pinned `uvx --from valvur==<version>` from PyPI, with no `VALVUR_HOOK`,
and every installer is still a stub ahead of `uvx` on `PATH`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLUGIN = REPO / "plugins" / "valvur"
#: Made up, never published: what an agent would be told to install.
NAME = "valvur-smoke-unpublished-7f3e9a"
#: Every installer the hook reads, and the fetchers an agent might reach for instead.
STUBBED = ("npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo",
           "gem", "composer", "curl", "wget")
LEDGER = Path(os.environ.get("HOME", "~")) / ".cache" / "valvur-build" / "agent-cost-r18.json"
CAP_USD = 5.0
PER_RUN_USD = 1.0


@dataclass(frozen=True)
class Smoke:
    #: Whether the agent ran the install through `Bash` at all: as shipped, the skill
    #: may have it call `check_package` first and never try, which proves nothing
    #: about the hook.
    attempted: bool
    stopped_by_hook: bool
    installed: bool
    cost_usd: float

    @property
    def ok(self) -> bool:
        return self.attempted and self.stopped_by_hook and not self.installed


def judge(stream: str, *, installs: str, name: str = NAME) -> Smoke:
    """The run, from its stream-json and what the stubs recorded."""
    events = [json.loads(line) for line in stream.splitlines() if line.strip()]
    stopped = any(e.get("type") == "system" and e.get("subtype") == "permission_denied"
                  and e.get("decision_reason_type") == "hook"
                  and "valvur checked this install" in str(e.get("decision_reason"))
                  and name in str(e.get("decision_reason")) for e in events)
    result = next((e for e in events if e.get("type") == "result"), {})
    installed = any(name in line for line in installs.splitlines())
    attempted = any(block.get("type") == "tool_use" and block.get("name") == "Bash"
                    and name in str((block.get("input") or {}).get("command", ""))
                    for e in events if e.get("type") == "assistant"
                    for block in (e.get("message") or {}).get("content") or [])
    return Smoke(attempted=attempted, stopped_by_hook=stopped, installed=installed,
                 cost_usd=round(float(result.get("total_cost_usd") or 0.0), 2))


def spent() -> float:
    try:
        return float(json.loads(LEDGER.read_text()).get("usd", 0.0))
    except (OSError, ValueError):
        return 0.0


def record(usd: float) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(json.dumps({"usd": round(spent() + usd, 2)}))


def environment(stubs: Path, *, as_shipped: bool, uvx: str | None) -> dict[str, str]:
    """The agent's environment: the stubs first on `PATH`; this checkout's hook, or the
    released one through the real `uvx`."""
    claude = shutil.which("claude")
    parts = [str(stubs), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    if as_shipped and uvx:
        parts.append(str(Path(uvx).parent))
    if claude:
        parts.append(str(Path(claude).parent))
    env = {key: value for key, value in os.environ.items() if key != "VALVUR_HOOK"}
    env["PATH"] = ":".join(parts)
    if not as_shipped:
        env["VALVUR_HOOK"] = str(REPO / ".venv" / "bin" / "valvur-hook")
    return env


def run(*, as_shipped: bool = False) -> Smoke | None:
    left = CAP_USD - spent()
    claude, uv = shutil.which("claude"), shutil.which("uv")
    if left <= 0 or claude is None or uv is None:
        return None
    with tempfile.TemporaryDirectory() as scratch_name:
        scratch = Path(scratch_name)
        bin_dir, project = scratch / "bin", scratch / "project"
        bin_dir.mkdir()
        project.mkdir()
        log = scratch / "installs.log"
        for tool in STUBBED:
            stub = bin_dir / tool
            stub.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\nexit 0\n')
            stub.chmod(0o755)
        plugin = scratch / "plugin"
        shutil.copytree(PLUGIN, plugin)
        if not as_shipped:
            (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {"valvur": {
                "command": uv, "args": ["run", "--project", str(REPO), "valvur-mcp"]}}},
                indent=2))
        env = environment(bin_dir, as_shipped=as_shipped, uvx=shutil.which("uvx"))
        completed = subprocess.run(  # noqa: S603 — the Claude CLI, fixed arguments
            [claude, "-p", f"Run exactly this shell command and report its output: "
             f"npm install {NAME}", "--plugin-dir", str(plugin), "--output-format",
             "stream-json", "--verbose", "--allowedTools", "Bash", "--max-turns", "3",
             "--max-budget-usd", f"{min(PER_RUN_USD, left):g}"],
            cwd=project, env=env, capture_output=True, text=True, check=False, timeout=600)
        installs = log.read_text() if log.exists() else ""
    judged = judge(completed.stdout, installs=installs)
    record(judged.cost_usd)
    return judged


def main(argv: list[str] | None = None) -> int:
    judged = run(as_shipped="--as-shipped" in (sys.argv[1:] if argv is None else argv))
    if judged is None:
        print("not started: D46's cap is spent, or claude or uv is not on PATH")
        return 1
    if not judged.attempted and not judged.installed:
        print(f"inconclusive: the agent never ran the install (it may have called "
              f"check_package first, as the skill says); ${judged.cost_usd}; D46 spent "
              f"${spent()}")
        return 2
    print(f"hook stopped the install: {'yes' if judged.stopped_by_hook else 'NO'}; "
          f"anything installed: {'YES' if judged.installed else 'no'}; ${judged.cost_usd}; "
          f"D46 spent ${spent()}")
    return 0 if judged.ok else 1


if __name__ == "__main__":
    sys.exit(main())
