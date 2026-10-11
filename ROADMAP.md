# Roadmap

What valvur is doing now, what it is considering, and what it will not do. The plan it is
built from, with every decision and measurement, is
[`.kiro/specs/valvur/tasks.md`](.kiro/specs/valvur/tasks.md); this page is the reader's
view of it, as of 2026-10-11. To argue for something, open a thread in
[Discussions → Ideas](https://github.com/MaverickHQ/valvur/discussions/categories/ideas).

## Now

- **Model output reaching a sink, measured.** valvur's four rules for model output that
  reaches code, a shell, a query or the DOM get a Score track of their own, with real
  vulnerable and fixed code where its licence allows, so their precision is measured
  rather than claimed.

## Next

- **Two of the rules a second engine found valvur missing:** certificate validation turned
  off, and a JavaScript cookie sent without `secure`.

## Shipped recently

`1.5.2` (2026-10-10): Checkov 3.3.22, Trivy 0.75.0 and Syft 1.54.0, and one slowest Scanner
per scan. `1.5.1`: the README rewritten, and whole on PyPI. `1.5.0`: a project's own ignore
comments and files no longer hide findings silently, and every rule's precision is published
in [`docs/RULES.md`](docs/RULES.md). Everything else is in the [CHANGELOG](CHANGELOG.md).

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
