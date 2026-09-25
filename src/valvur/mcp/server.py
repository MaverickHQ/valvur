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
    """One exposed tool, and what it does to the machine it runs on.

    No tool touches the **source tree** — that is F9.2 and ADR-0009, structural
    and unchanged. `readOnlyHint` is a narrower claim in MCP's own words, "does
    not modify its environment", and until 27.1.2 all six tools declared it true:
    `scan` writes the Results Folder, pulls an image and starts containers, and
    `scan_cancel` kills them. A client may use these annotations to decide what
    to run without asking, so a hint that is wrong is worse than none — a prompt
    before a scan is the correct behaviour, not a regression.
    """

    def __init__(self, name: str, description: str, schema: dict,
                 handler: Callable[[dict], str | tuple[str, dict]], *,
                 read_only: bool = True, destructive: bool = False,
                 output_schema: dict | None = None):
        self.name = name
        self.description = description
        self.schema = schema
        #: Answers the text every client renders — and, for a tool that declares
        #: `output_schema`, the same answer as a dict beside it, which the reply
        #: carries as `structuredContent` (MCP 2025-06-18; 28.2.2). One call
        #: produces both, so the two forms cannot disagree.
        self.handler = handler
        self.output_schema = output_schema
        #: The default is the safe one: a tool says nothing and is advertised as
        #: read-only, so a tool that ACTS has to declare it.
        self.read_only = read_only
        #: Nothing valvur exposes is destructive, and a test over the registry
        #: says so: a scan only adds, and a cancel writes nothing at all (F1.11).
        #: The field exists so the claim is stated rather than assumed.
        self.destructive = destructive

    def describe(self) -> dict:
        described = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
            "annotations": {"readOnlyHint": self.read_only,
                            "destructiveHint": self.destructive},
        }
        if self.output_schema is not None:
            described["outputSchema"] = self.output_schema
        return described


def version() -> str:
    from ..compat import shim_version

    return shim_version()


def _default_instructions() -> str:
    # Lazy: `tools` imports `Tool` from here at module level. Both sit in the one
    # soft component the cycle ratchet names for the MCP package.
    from .tools import instructions

    return instructions()


def build(tools: list[Tool], *, instructions: str | None = None,
          ) -> dict[str, Callable[[dict], Any]]:
    """The handlers for one server. `instructions` is what `initialize` hands the
    client; None means the machine block's rules, "" means none."""
    by_name = {tool.name: tool for tool in tools}

    def initialize(params: dict) -> dict:
        # Negotiate: honour the client's version when we know it, otherwise state
        # ours and let the client decide whether it can proceed.
        wanted = params.get("protocolVersion")
        agreed = wanted if wanted in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        reply: dict[str, Any] = {
            "protocolVersion": agreed,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": version()},
        }
        # The rules an agent is given before its first call (28.2.2): the same
        # five `SUMMARY.md` opens with, so an agent that never opens the folder
        # has them too. A client may show or ignore them; a server that never
        # states them leaves it to whoever wrote the client's CLAUDE.md.
        rules = instructions if instructions is not None else _default_instructions()
        if rules:
            reply["instructions"] = rules
        return reply

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
            answer = tool.handler(params.get("arguments") or {})
        except RpcError:
            raise
        except Exception as exc:   # broad: a server that cannot clean up must still exit
            # A tool failing is a result, not a protocol error: the agent should see
            # what went wrong rather than a transport-level fault.
            return {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            }
        text, structured = (answer, None) if isinstance(answer, str) else answer
        reply: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": False}
        if structured is not None:
            reply["structuredContent"] = structured
        return reply

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
