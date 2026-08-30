"""MCP over stdio: newline-delimited JSON-RPC 2.0, implemented directly.

No dependencies (ADR-0015). The official SDK brings an HTTP server, an OAuth stack
and a crypto library to support transports Kiro and Claude Code do not use, and
installing a web server into a security tool enlarges what must be audited whether
or not a port is ever bound.

**stdout carries JSON-RPC and nothing else.** A stray print, a warning, or a
traceback corrupts the stream and the client sees a protocol error rather than the
problem that actually occurred. Everything diagnostic goes to stderr.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TextIO

# Pinned deliberately (task 9.0.3): we own compatibility now, so the version we
# declare is a decision rather than whatever a package happened to ship.
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class RpcError(Exception):
    """A JSON-RPC error the client should see, as opposed to a crash it should not."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


@dataclass
class Request:
    method: str
    params: dict
    id: Any = None

    @property
    def is_notification(self) -> bool:
        """Notifications carry no id and must receive no response."""
        return self.id is None


def parse(line: str) -> Request:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RpcError(PARSE_ERROR, f"invalid JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        raise RpcError(INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    method = payload.get("method")
    if not isinstance(method, str):
        raise RpcError(INVALID_REQUEST, "missing method")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        raise RpcError(INVALID_PARAMS, "params must be an object")
    return Request(method=method, params=params, id=payload.get("id"))


def result(request_id: Any, value: Any) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": value})


def error(request_id: Any, code: int, message: str, data: Any = None) -> str:
    body: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        body["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "error": body})


def serve(
    handlers: dict[str, Callable[[dict], Any]],
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Read requests until stdin closes, dispatching each to a handler."""
    source = stdin or sys.stdin
    sink = stdout or sys.stdout

    for line in source:
        line = line.strip()
        if not line:
            continue
        response = _handle(line, handlers)
        if response is not None:
            sink.write(response + "\n")
            sink.flush()


def _handle(line: str, handlers: dict[str, Callable[[dict], Any]]) -> str | None:
    request_id = None
    try:
        request = parse(line)
        request_id = request.id
        handler = handlers.get(request.method)
        if handler is None:
            if request.is_notification:
                return None      # unknown notifications are ignored, per spec
            raise RpcError(METHOD_NOT_FOUND, f"unknown method: {request.method}")
        value = handler(request.params)
        if request.is_notification:
            return None
        return result(request_id, value)
    except RpcError as exc:
        return error(request_id, exc.code, exc.message, exc.data)
    except Exception as exc:
        # Never let a traceback reach stdout: it would corrupt the stream and the
        # client would report a protocol error instead of the real failure.
        print(f"valvur mcp: unhandled error: {exc!r}", file=sys.stderr)
        return error(request_id, INTERNAL_ERROR, f"internal error: {exc}")
