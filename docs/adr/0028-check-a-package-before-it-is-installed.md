# ADR-0028 — Check a package before it is installed, and know its registry

**Status:** accepted 2026-09-29 by the owner, with the review of that day; written by
task R9.2 from `tasks.md` D27 and D28. Requirements F3.15, F3.16 and F9.11.

## Context

Slopsquatting does its damage at install: `npm install` runs a package's scripts before
any scan reads the manifest. The dependency-reality Check ran only inside a scan, after
the fact.

It also read every name against the public registries alone. A regulated company's
internal packages, which this product's buyers have, were reported as hallucinated at
high. Gemfile and Composer private sources were already understood; npm scopes and
Python indexes were not.

## Decision

1. **Private registries** (F3.15), read from the File Set:
   - npm: `.npmrc` and `.yarnrc.yml`, scoped and whole registries;
   - Python: `--index-url` and `--extra-index-url` in requirements files, `pip.conf`,
     `[[tool.uv.index]]` with `[tool.uv.sources]`, `[[tool.poetry.source]]`, and a
     `Pipfile`'s `[[source]]`.

   How a name absent from the public index is reported depends on the configuration:
   - its scope or source is a private registry: not looked up publicly, listed as a
     coverage note;
   - a supplemental source is configured (`--extra-index-url`, or a supplemental uv or
     Poetry source): `valvur.dependency.confusion`, **high**, because the resolver may
     take a public package registered under that name;
   - the public registry is replaced entirely: `valvur.dependency.not-public`, **low**,
     advising the name be reserved;
   - no configuration: `nonexistent`, high, as now. The message names the index's build
     date and says an internal package should declare its registry in the project.
2. **`check_package`** (F3.16, F9.11), in three forms:
   - the API, `valvur.packages.check`;
   - the CLI, `valvur check <ecosystem> <name>[@version] …`, which exits 0 when every
     package exists and is not flagged, 1 when any is flagged, and 2 on error;
   - the MCP tool `check_package`: up to 50 packages, `readOnlyHint` true,
     `openWorldHint` false.

   Each answer is `exists`, `nonexistent`, `near-miss` with the name it is near,
   `malicious` with its `MAL-` ID, `confusion` or `not-public`, or `unknown` where no
   index exists (JVM, Go). Each carries the index's build date. It runs on the host,
   with **no network, ever**, in under a second.
3. **The handshake's instructions and `SUMMARY.md`'s agent block** say: before adding a
   dependency, call `check_package`, and never add one it flags without the human.

## Rejected

- **Asking the registry on `full`.** The registry, and anyone watching it, learns which
  hallucinated name an agent wanted: the attacker's shopping list.
- **A hook that blocks `npm install`.** `CLAUDE.md` §4 forbids watchers and on-save
  hooks, and this would be neither. Whether a pre-install hook may exist is the owner's
  decision, not this ADR's.
