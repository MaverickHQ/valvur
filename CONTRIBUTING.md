# Contributing to valvur

Thank you for looking. This document is longer than most because valvur has a few
constraints that are load-bearing, and it is kinder to state them up front than to
reject a pull request that took you a weekend.

## Before you build something large, open an issue

Not bureaucracy — some things will be refused however well they are built, and you
deserve to know which before you start. See **What will be turned down** below.

## Getting set up

```bash
uv venv --python 3.12
uv sync --extra dev --locked  # install the committed uv.lock, and fail if it is stale
uv run valvur update          # fetches the vulnerability database, once
./scripts/verify.sh           # lint, types, traceability, unit tests, package build
```

`scripts/verify.sh` is the one command worth running before every push: it is the
same file `ci.yml` and `release.yml` call, so it cannot drift from what CI checks.
Pass names to run a subset — `./scripts/verify.sh lint types`.

The end-to-end tests need Docker or Podman and the image. It is not included above
because it needs a container; CI runs it, and so should you before anything touching
the runner, adapters or Checks:

```bash
docker buildx build --load \
  --build-arg VALVUR_VERSION="$(uv run python -c 'import valvur; print(valvur.__version__)')" \
  -t valvur:dev .
VALVUR_IMAGE=valvur:dev uv run pytest -q -m e2e
```

If a version test fails after you change `pyproject.toml`, reinstall — the editable
install's metadata goes stale, and that is a real bug we shipped for six days.

**Rules and Checks ship *inside* the image** (ADR-0013), so editing
`src/valvur/checks/` or `rules/` changes nothing about a real scan until you rebuild.
Unit tests exercise your new code; `valvur scan` runs the image's copy. This has
caught us twice — a new Opengrep rule (12a.6) and a new coverage report (19.D.3) —
both times as a change that passed every test and did nothing in practice:

```bash
docker buildx build --load --build-arg VALVUR_VERSION="$(uv run python -c 'import valvur; print(valvur.__version__)')" -t valvur:dev .
VALVUR_IMAGE=valvur:dev uv run valvur scan .
```

## How the work is organised

- **Spec-driven.** [`.kiro/specs/valvur/`](.kiro/specs/valvur/) holds requirements →
  design → tasks. Requirement IDs (`F1.1`, `N2.1`, `P5`) are cited by the design, the
  tasks and the tests. **Never renumber them.**
- **Decisions live in [`docs/adr/`](docs/adr/)**, numbered, each recording the
  alternatives that were rejected and why. If your change reverses one, argue with
  the ADR rather than around it — several exist because the obvious approach was
  tried and was wrong.
- **Vocabulary is fixed.** [`CONTEXT.md`](CONTEXT.md) is the glossary and its
  `_Avoid_` lists are deliberate. A **Scanner** is third-party; a **Check** is ours.
  Using the wrong word erodes a constraint that the right word protects.

## Tests

Test-first. That is the house style, and for this codebase it has earned its keep —
most of the defects found in the last month were found by a test written before the
fix, not by review.

**Every assertion must be able to fail.** This matters more here than the usual
amount, because valvur's failure mode is silence. A test that a scan "found no
network activity" passes trivially against a repository with nothing to scan. So:

- Pair a guarantee with a check that the guarantee can break. If you assert the
  offline profile opens no socket, assert the networked one does.
- Prove the fixture reaches the code under test. Enrichment short-circuits when
  there are no CVEs; a stub without one tests nothing at all.
- Mutation-test anything load-bearing. Break it deliberately, watch the right test
  fail, put it back. If nothing fails, the test is decoration.

Run `pytest -q -m "not e2e"` constantly and the full suite before pushing.

## Style

`ruff` and `mypy` gate the build; run both. Beyond that, match the surrounding code.

Comments explain **why**, especially why an obvious alternative was not taken. A
comment saying what the line does is noise; one saying "found by CI on Linux, not
locally" saves the next person a day.

## What will be turned down

These are in [`CLAUDE.md §3`](CLAUDE.md) as the product's non-negotiables. They are
not preferences:

- **Anything that sends code, or data derived from it, anywhere.** Non-exfiltration
  is provable and tested. A feature that improves results by transmitting something
  is the product being traded away.
- **Anything requiring an account, API key or token to function.**
- **Anything that writes to the scanned source tree.** The mount is read-only, and
  structurally so.
- **Autonomous remediation** — a `scan_and_fix` tool, a file watcher, an on-save
  hook. A test asserts no such tool exists in the registry, so this fails the build
  rather than review. The reasoning is in
  [ADR-0009](docs/adr/0009-human-in-the-loop-remediation.md): an agent told to drive
  findings to zero has a cheaper path via deletion than via correct fixes.
- **A claim we cannot support** — reachability analysis, proprietary detection, or
  coverage we do not have.
- **GPL-licensed tools added to the distributed image.**

Improvements to detection, presentation, ranking, performance, packaging and
documentation are all welcome, and the checks nobody else ships — slopsquatting,
agent-config auditing, hidden Unicode, LLM-output-to-sink taint — are where the most
interesting work is.

## Pull requests

- One change per pull request.
- Say what breaks if you are wrong. That sentence is usually the review.
- Update the ADR, spec or `CHANGELOG.md` if the change touches a decision, a
  requirement or user-visible behaviour.
- The self-scan gate must pass: valvur scans itself on every build, and an
  unsuppressed finding fails it. A suppression needs a reason and an expiry.

## Releasing

Maintainers: [docs/RELEASING.md](docs/RELEASING.md). The release is a consequence of
a tag — bump `pyproject.toml`, tag, push, and the workflow verifies, signs, attests
and publishes. It refuses a tag that disagrees with the tree.

## Reporting a security issue

Please do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. By contributing, you agree your contribution is licensed under it.
