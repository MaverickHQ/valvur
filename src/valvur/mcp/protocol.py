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
import threading
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


class Client:
    """What this session knows of its client (R6.4): the capabilities it declared
    at `initialize`, the requests this server has put to it and awaits, and its
    roots once asked, until it says they changed."""

    def __init__(self, emit: Callable[[str], None]):
        self._emit = emit
        self.capabilities: dict = {}
        self._pending: dict[str, Any] = {}
        self._next = 0
        self._lock = threading.Lock()
        self._roots: list[Any] | None = None

    def ask(self, method: str, params: dict | None = None, seconds: float = 10.0) -> Any:
        """Put a request to the client and wait for its result; None on an error or
        no answer. The id is the server's own, so it never meets a client's."""
        import queue

        with self._lock:
            self._next += 1
            request_id = f"valvur-{self._next}"
            answer: queue.Queue = queue.Queue()
            self._pending[request_id] = answer
        self._emit(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method,
                               **({"params": params} if params else {})}))
        try:
            message = answer.get(timeout=seconds)
        except queue.Empty:
            return None
        finally:
            with self._lock:
                self._pending.pop(request_id, None)
        return message.get("result")

    def answered(self, message: dict) -> bool:
        """Deliver the client's answer to a request of ours; False if it is not one."""
        with self._lock:
            waiting = self._pending.get(str(message.get("id")))
        if waiting is None:
            return False
        waiting.put(message)
        return True

    def roots(self) -> list[Any] | None:
        """The client's roots as paths, asked once; None when it declared none."""
        from pathlib import Path
        from urllib.parse import unquote, urlparse

        if "roots" not in self.capabilities:
            return None
        if self._roots is None:
            result = self.ask("roots/list") or {}
            found = []
            for root in result.get("roots") or []:
                uri = urlparse(str(root.get("uri", "")))
                if uri.scheme == "file":
                    found.append(Path(unquote(uri.path)).resolve())
            self._roots = found
        return list(self._roots)

    def roots_changed(self) -> None:
        self._roots = None


class Call:
    """One `tools/call` in flight (R6.3): its id, the client's progress token, and
    whether the client has let go of it. A handler that runs long reads this to
    send progress, and stops waiting once the client is gone."""

    def __init__(self, request_id: Any, token: Any, emit: Callable[[str], None],
                 client: Client | None = None):
        self.id = request_id
        self.token = token
        self._emit = emit
        self.client = client
        self._sent = 0
        #: Set by the client's `notifications/cancelled` or by stdin closing: a
        #: handler that waits stops waiting.
        self.detached = threading.Event()
        #: The client cancelled the request: nothing is written for it, per MCP.
        #: Stdin closing is not that: a call already answered is still answered.
        self.cancelled = False
        #: The tools the server answering it serves, set by that server, so `doctor`
        #: can say them without importing the registry that imports it (R12.3).
        self.served: tuple[str, ...] = ()

    def progress(self, message: str) -> None:
        """One `notifications/progress`, when the client asked for them."""
        if self.token is None or self.cancelled:
            return
        self._sent += 1
        self._emit(json.dumps({"jsonrpc": "2.0", "method": "notifications/progress",
                               "params": {"progressToken": self.token,
                                          "progress": self._sent, "message": message}}))


_local = threading.local()


def current_call() -> Call | None:
    """The call this thread is answering, if it is answering one."""
    return getattr(_local, "call", None)


#: How long the end of input waits for calls in flight to let go (R6.3).
JOIN_SECONDS = 10.0


def serve(
    handlers: dict[str, Callable[[dict], Any]],
    *,
    stdin: Any = None,
    stdout: TextIO | None = None,
) -> None:
    """Read requests until stdin closes, dispatching each to a handler.

    A `tools/call` runs on its own thread (R6.3): `scan` blocks until the result,
    and the client must still be able to send `scan_cancel`, `ping` or a
    cancellation meanwhile. Writes are serialised. When stdin closes every call
    in flight is let go, and the server's exit stops the scans it started."""
    source = stdin or sys.stdin
    sink = stdout or sys.stdout
    lock = threading.Lock()
    calls: dict[Any, tuple[Call, threading.Thread]] = {}

    def emit(text: str) -> None:
        with lock:
            sink.write(text + "\n")
            sink.flush()

    client = Client(emit)

    def answer(line: str, call: Call) -> None:
        _local.call = call
        try:
            response = _handle(line, handlers)
        finally:
            _local.call = None
        if response is not None and not call.cancelled:
            emit(response)

    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            message = None
        if isinstance(message, dict) and "method" not in message and client.answered(message):
            continue                          # the client answering a request of ours
        if isinstance(message, dict) and message.get("method") == "initialize":
            client.capabilities = dict((message.get("params") or {}).get("capabilities")
                                        or {})
        if isinstance(message, dict) and message.get("method") == \
                "notifications/roots/list_changed":
            client.roots_changed()
            continue
        if isinstance(message, dict) and message.get("method") == "notifications/cancelled":
            held = calls.get((message.get("params") or {}).get("requestId"))
            if held is not None:
                held[0].cancelled = True
                held[0].detached.set()
            continue
        if isinstance(message, dict) and message.get("method") == "tools/call" \
                and message.get("id") is not None:
            meta = (message.get("params") or {}).get("_meta") or {}
            call = Call(message["id"], meta.get("progressToken"), emit, client)
            for done in [key for key, (_, t) in calls.items() if not t.is_alive()]:
                del calls[done]              # a long session keeps only what runs
            thread = threading.Thread(target=answer, args=(line, call), daemon=True,
                                      name=f"valvur-call-{message['id']}")
            calls[message["id"]] = (call, thread)
            thread.start()
            continue
        response = _handle(line, handlers)
        if response is not None:
            emit(response)
    for call, _thread in calls.values():
        call.detached.set()
    for _, thread in calls.values():
        thread.join(timeout=JOIN_SECONDS)


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
