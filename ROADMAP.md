# Roadmap

What valvur is doing now, what it is considering, and what it will not do. The plan it is
built from, with every decision and measurement, is
[`.kiro/specs/valvur/tasks.md`](.kiro/specs/valvur/tasks.md); this page is the reader's
view of it, as of 2026-10-27. To argue for something, open a thread in
[Discussions → Ideas](https://github.com/MaverickHQ/valvur/discussions/categories/ideas).

## Now

- **valvur's own updates, made to heal themselves: the second half,** approved, and waiting on
  three repository settings the maintainer makes: a lock that re-locks itself, and security
  patches that release themselves.

## Next

- **Two of the rules a second engine found valvur missing:** certificate validation turned
  off, and a JavaScript cookie sent without `secure`.

## Shipped recently

`1.6.0` (2026-10-27): `valvur mcp`, so the official MCP Registry lists valvur; the skill
where Codex reads it; Cursor in one click; and the first half of valvur's own updates
healing themselves: one writer for the image's Checkov lock, a watchdog over the scheduled
workflows, a nightly that judges the latest release, and a gate on the image as it ships,
whose release notes now say what it does not fix. Six Scanners moved to their newest
release, Gitleaks is built with a supported Go, and pip is gone from the image. `1.5.4`
(2026-10-24): a security release for the image. Its Checkov environment moves past ten
advisories in aiohttp, certifi and GitPython, and its base to Alpine 3.24, past six months
of OpenSSL, musl, xz and zlib fixes. `1.5.3` (2026-10-11): a Score track of its own for
model output reaching code, a shell, a query or the DOM. valvur's four rules for it catch
30 of its 34 generated flows with no false alarm, and none of the five published advisories
it holds, whose flows each cross a function. `1.5.2` (2026-10-10): Checkov 3.3.22, Trivy
0.75.0 and Syft 1.54.0, and one slowest Scanner per scan. `1.5.1`: the README rewritten,
and whole on PyPI. `1.5.0`: a project's own ignore comments and files no longer hide
findings silently, and every rule's precision is published in
[`docs/RULES.md`](docs/RULES.md). Everything else is in the [CHANGELOG](CHANGELOG.md).

## Being considered

Each needs something first, and none has a date.

| idea | what it needs first |
|---|---|
| Two more rules a second engine found that valvur misses: a short key and an old TLS version | evidence that they matter, then cases on a Score track and D29's measured bar ([the comparison](docs/acceptance/r29.md#what-valvur-misses-r294)) |
| Java and Go code rules | a benchmark for each language under a compatible licence |
| Container images scanned offline | a measurement on a real image: size and time |
| Scans limited to given paths | the reuse by declared inputs planned for 2.0 |
| A documentation site, and translations | the site first, then a volunteer per language |
| An IDE extension | demand: the MCP server already reaches the agents in IDEs |
| Native Windows | demand, and a Windows container path; WSL2 works today |
| An AI bill of materials beside the SBOM | the format's guidance for source repositories |
| Working with OWASP's GenAI Security Project | parked by the maintainer; a second maintainer first |

## Not planned

These are refused on principle, as [the README](README.md#what-it-does-not-do) says:
reachability analysis, autonomous fixing, penetration testing, code-quality analysis, a
hosted service, and telemetry of any kind.
