"""The MCP server: initialize, tools/list, tools/call.

That is the entire protocol for a tools-only server, which is what valvur is. It
exposes no resources and no prompts, and it never asks the client to sample —
every one of those would be a way for a scanned repository to reach further than
reporting on itself.
"""

from __future__ import annotations

import contextlib
import signal
import sys
from collections.abc import Callable
from typing import Any

from . import jobs, protocol
from .protocol import PROTOCOL_VERSION, SUPPORTED_VERSIONS, RpcError

SERVER_NAME = "valvur"

#: How long the exit waits for each cancelled job to settle (task 27.1.1). Long
#: enough for a `docker kill` of a full fleet and the scan's own unwinding —
#: measured at about a second (26.0.2: CANCELLED at 1.19s) — and short enough that
#: a job which will never settle does not hold a client's restart. Read at call
#: time so a test can shorten it.
SHUTDOWN_SECONDS = 10.0


class _Terminated(SystemExit):
    """SIGTERM, raised into the serve loop so the exit path runs.

    The default disposition ends the process without unwinding, so the `finally`
    below never runs and the fleet is orphaned — which is how a client that kills
    its server rather than closing stdin left containers behind (27.1.1).
    """


def shutdown(out=None) -> None:
    """Stop every scan this process started, on the way out.

    A scan job is a daemon thread and dies with the process; the containers it
    launched are the runtime's children and do not (`runner.py`, 23.3.3). So the
    same path a `scan_cancel` takes is taken for each active job — the mark, the
    runner's kill, the wait — and `kill_running` sweeps up anything no job owns:
    a fleet whose job has already been replaced, or a container started between
    the cancel and the kill. Nothing here raises: a server that cannot clean up
    must still exit.
    """
    from .. import runner

    stream = out or sys.stderr
    for workspace in jobs.active():
        job, stopped = jobs.cancel(workspace)
        if job is None:
            continue
        print(f"valvur-mcp: stopping the {job.profile} scan of {workspace} "
              f"({stopped} container(s))", file=stream, flush=True)
        if not job.wait(SHUTDOWN_SECONDS):
            print(f"valvur-mcp: the scan of {workspace} had not stopped after "
                  f"{SHUTDOWN_SECONDS:.0f}s; leaving it", file=stream, flush=True)
    try:
        swept = runner.kill_running()
    except Exception as exc:   # broad: a server that cannot clean up must still exit
        print(f"valvur-mcp: could not stop remaining containers: {exc}",
              file=stream, flush=True)
        return
    if swept:
        print(f"valvur-mcp: stopped {swept} container(s) with no job", file=stream, flush=True)


class Tool:
    """One exposed tool. Every tool valvur exposes is read-only (F9.2, ADR-0009)."""

    def __init__(self, name: str, description: str, schema: dict,
                 handler: Callable[[dict], str]):
        self.name = name
        self.description = description
        self.schema = schema
        self.handler = handler

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
            # Advertised so a client can show the user that nothing here mutates
            # their code. ADR-0009 is a safety property, not a preference.
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
        }


def version() -> str:
    from ..compat import shim_version

    return shim_version()


def build(tools: list[Tool]) -> dict[str, Callable[[dict], Any]]:
    by_name = {tool.name: tool for tool in tools}

    def initialize(params: dict) -> dict:
        # Negotiate: honour the client's version when we know it, otherwise state
        # ours and let the client decide whether it can proceed.
        wanted = params.get("protocolVersion")
        agreed = wanted if wanted in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return {
            "protocolVersion": agreed,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": version()},
        }

    def list_tools(_: dict) -> dict:
        return {"tools": [tool.describe() for tool in tools]}

    def call_tool(params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str):
            raise RpcError(protocol.INVALID_PARAMS, "tool name must be a string")
        tool = by_name.get(name)
        if tool is None:
            raise RpcError(
                protocol.INVALID_PARAMS,
                f"unknown tool: {name}. Available: {', '.join(sorted(by_name)) or 'none'}",
            )
        try:
            text = tool.handler(params.get("arguments") or {})
        except RpcError:
            raise
        except Exception as exc:   # broad: a server that cannot clean up must still exit
            # A tool failing is a result, not a protocol error: the agent should see
            # what went wrong rather than a transport-level fault.
            return {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            }
        return {"content": [{"type": "text", "text": text}], "isError": False}

    return {
        "initialize": initialize,
        "notifications/initialized": lambda _: None,
        "ping": lambda _: {},
        "tools/list": list_tools,
        "tools/call": call_tool,
    }


#: What `valvur-mcp --help` prints. Not argparse: this entry point takes no options
#: at all beyond these two, and a parser would invite adding some — every flag here is
#: a way for a client's configuration to change what the server does behind the
#: agent's back.
USAGE = """valvur-mcp — the MCP server, over stdio.

Not run by hand. An agent starts it and speaks JSON-RPC on stdin/stdout; there is no
listener and no port, because the process boundary is the trust boundary (ADR-0015).

Add it to your agent instead:

    {
      "mcpServers": {
        "valvur": { "command": "valvur-mcp" }
      }
    }

Tools: doctor, scan, scan_status, scan_cancel, list_findings, explain_finding — all
read-only with respect to your source. There is no scan-and-fix tool and there will
not be one (ADR-0009): you choose which fixes to apply. `doctor` checks this machine
can scan before one is started; `scan_cancel` stops one, as Ctrl-C would.

  --help      this text
  --version   the version, which must match the container image

Everything else — profiles, workspace paths — is an argument to the tools, not to
this command. `valvur --help` documents the CLI."""


def main(argv: list[str] | None = None) -> int:
    # stderr, never stdout: stdout is the JSON-RPC channel, and a line of prose
    # there corrupts the stream for every client.
    from ..runner import unsupported_platform_warning
    from ..version import __version__
    from .tools import registry

    # Silence on stdout is correct for stdio and terrible for a first-run diagnosis:
    # someone checking the binary works had no way to ask, and got a process that sat
    # there apparently doing nothing (task 19.C.3). These two answers go to STDOUT
    # deliberately — a person ran the command, so the JSON-RPC channel is not in use.
    args = sys.argv[1:] if argv is None else argv
    if args:
        if args[0] in ("-h", "--help", "help"):
            print(USAGE)
            return 0
        if args[0] in ("-V", "--version", "version"):
            print(f"valvur-mcp {__version__}")
            return 0
        # Refused rather than ignored. An unrecognised flag that starts the server
        # anyway is how a typo in an agent config becomes a silent misconfiguration.
        print(f"valvur-mcp: unrecognised argument {args[0]!r}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    if warning := unsupported_platform_warning():
        print(warning, file=sys.stderr, flush=True)

    def terminated(signum, frame):      # the handler's signature; neither is used
        raise _Terminated

    with contextlib.suppress(ValueError):     # not the main thread: a test, or an embedder
        signal.signal(signal.SIGTERM, terminated)

    try:
        protocol.serve(build(registry()))
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass                      # the client went away; that is a normal end
    except _Terminated:
        pass                      # SIGTERM; the same end, and the same cleanup
    finally:
        # Every way out of `serve` — stdin closed, Ctrl-C, a broken pipe, SIGTERM
        # — leaves through here, because a scan the client can no longer read is
        # a scan nobody wants running (27.1.1, F1.11).
        shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
