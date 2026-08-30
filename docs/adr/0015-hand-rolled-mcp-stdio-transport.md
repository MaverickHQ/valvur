# The MCP server is hand-rolled over stdio, with no dependencies

valvur implements MCP's stdio transport directly — newline-delimited JSON-RPC 2.0 on
stdin and stdout — rather than depending on the official Python SDK. The host shim
keeps **zero runtime dependencies** (F10.6), and MCP is on the **primary** install
path: `pip install valvur` gives a working server, with no extra to opt into.

## Considered Options

**The official MCP SDK.** Rejected on what it brings rather than what it does. It
pulls **22 transitive packages**, among them `starlette`, `uvicorn`, `sse-starlette`,
`python-multipart`, `pyjwt` and `cryptography` — an HTTP server, an OAuth stack and a
crypto library, all present to support HTTP and SSE transports. Kiro and Claude Code
both speak **stdio**, where none of them are used.

**The SDK as an opt-in extra (`valvur[mcp]`).** Considered and rejected for the
opposite reason: MCP is the *primary* interface, not a secondary one. The product is
agent-native — the whole point is a developer adding valvur to their agent and calling
it from there. Putting the main path behind an extra is friction in the wrong place.

## Consequences

The security argument is the deciding one, and it is specific rather than
philosophical. Installing a web server and an OAuth library into a security tool
enlarges the surface that must be audited and patched *whether or not a port is ever
bound*. It also means shipping the kind of dependency footprint our own **Dependency
Reality Check** exists to warn people about — a scanner whose install surface exceeds
what it scans is a credibility problem before it is a technical one.

**stdio has no listener and no network surface.** The process boundary is the trust
boundary: the agent spawns valvur, talks over a pipe, and there is nothing to
authenticate, nothing to bind and nothing to reach from outside.

The surface we implement is small and stable — `initialize`, `tools/list`,
`tools/call` — which is the whole protocol for a tools-only server.

**The risk we accept:** we own protocol compatibility. If MCP's handshake changes we
fix it, rather than upgrading a package. Mitigated by pinning the protocol version we
declare, by testing against a real client as Phase 9's exit criterion, and by keeping
the SDK as a documented fallback if we meet something we cannot match.
