# Roadmap

What valvur is doing now, what it is considering, and what it will not do. The plan it is
built from, with every decision and measurement, is
[`.kiro/specs/valvur/tasks.md`](.kiro/specs/valvur/tasks.md); this page is the reader's
view of it, as of 2026-10-09. To argue for something, open a thread in
[Discussions → Ideas](https://github.com/MaverickHQ/valvur/discussions/categories/ideas).

## Now

- **A professional front door**: this README, the guides beside it, and the GitHub page.

## Shipped recently

`1.5.0` (2026-10-09): a project's own ignore comments and files no longer hide findings
silently; five false reports fixed; every rule's precision published in
[`docs/RULES.md`](docs/RULES.md); KEV current over a weekend. Everything else is in the
[CHANGELOG](CHANGELOG.md).

## Being considered

Each needs something first, and none has a date.

| idea | what it needs first |
|---|---|
| Four rules a second engine found that valvur misses: certificate validation turned off, a JavaScript cookie without `secure`, a short key, an old TLS version | cases on a Score track, then D29's measured bar ([the comparison](docs/acceptance/r29.md#what-valvur-misses-r294)) |
| A Score track for model output reaching code, a shell, a query or the DOM | real or generated cases, vulnerable and fixed, under a licence that allows them |
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
