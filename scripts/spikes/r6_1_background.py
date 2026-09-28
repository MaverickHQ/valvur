"""R6.1: does Claude Code keep a long stdio tool call's result? (F9.1, ADR-0024)

A stdio MCP server with one tool, `slow_answer`, that runs for `seconds`, sends a
progress notification every ten when the call carries a progress token, and returns
a number the model could not guess. `claude -p` is asked for the number; the stream
says whether the call was moved to the background and whether the number reached
the model. Usage:

    uv run python scripts/spikes/r6_1_background.py serve          # the server
    uv run python scripts/spikes/r6_1_background.py measure 150    # the measurement
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ANSWER = "73194"


def _send(message: dict, lock: threading.Lock) -> None:
    with lock:
        sys.stdout.write(json.dumps(message) + "\n")
        sys.stdout.flush()


def serve() -> None:
    lock = threading.Lock()
    for line in sys.stdin:
        request = json.loads(line)
        method, rid = request.get("method"), request.get("id")
        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": request["params"].get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "slow", "version": "0"}}}, lock)
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "slow_answer",
                "description": "Returns the answer after the given number of seconds.",
                "inputSchema": {"type": "object", "properties": {
                    "seconds": {"type": "integer"}}, "required": ["seconds"]}}]}}, lock)
        elif method == "tools/call":
            threading.Thread(target=_answer, args=(request, lock), daemon=True).start()
        elif rid is not None:
            _send({"jsonrpc": "2.0", "id": rid, "result": {}}, lock)


def _answer(request: dict, lock: threading.Lock) -> None:
    params = request["params"]
    seconds = int(params.get("arguments", {}).get("seconds", 150))
    token = (params.get("_meta") or {}).get("progressToken")
    started = time.monotonic()
    while (elapsed := time.monotonic() - started) < seconds:
        time.sleep(min(10, seconds - elapsed))
        if token is not None:
            _send({"jsonrpc": "2.0", "method": "notifications/progress", "params": {
                "progressToken": token, "progress": int(time.monotonic() - started),
                "total": seconds, "message": "still working"}}, lock)
    _send({"jsonrpc": "2.0", "id": request["id"], "result": {"content": [
        {"type": "text", "text": f"The answer is {ANSWER}."}], "isError": False}}, lock)


def measure(seconds: int) -> dict:
    config = {"mcpServers": {"slow": {"command": sys.executable,
                                      "args": [str(Path(__file__).resolve()), "serve"]}}}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mcp.json"
        path.write_text(json.dumps(config))
        started = time.monotonic()
        done = subprocess.run(  # noqa: S603 — the Claude CLI, fixed arguments
            ["claude", "-p", f"Call the slow_answer tool with seconds={seconds} and tell me "
             "the number it returns. Do nothing else.", "--mcp-config", str(path),
             "--strict-mcp-config", "--allowedTools", "mcp__slow__slow_answer",
             "--max-turns", "10", "--output-format", "stream-json", "--verbose"],
            cwd=tmp, capture_output=True, text=True, check=False, timeout=1800)
        wall = round(time.monotonic() - started, 1)
    events = [json.loads(line) for line in done.stdout.splitlines() if line.startswith("{")]
    final = next((e for e in reversed(events) if e.get("type") == "result"), {})
    text = json.dumps(events)
    return {"seconds": seconds, "wall_s": wall, "answer_reached_model": ANSWER in
            str(final.get("result", "")), "result": str(final.get("result", ""))[:300],
            "turns": final.get("num_turns"), "cost_usd": final.get("total_cost_usd"),
            "mentions_background": "background" in text.lower(),
            "tool_results": [str(c.get("content"))[:200] for e in events
                             if e.get("type") == "user"
                             for c in (e.get("message", {}).get("content") or [])
                             if isinstance(c, dict) and c.get("type") == "tool_result"],
            "stderr": done.stderr[-500:]}


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        print(json.dumps(measure(int(sys.argv[2])), indent=1))
