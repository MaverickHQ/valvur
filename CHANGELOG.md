# Changelog

All notable changes to valvur are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the 0.x caveat that
a minor bump may break things until 1.0.

## [Unreleased]

### Changed — BREAKING

- **Two profiles, `offline` and `full`, replacing `quick`/`standard`/`deep`**
  ([ADR-0016](docs/adr/0016-two-profiles-split-on-the-network-boundary.md)). The old
  set was split along *speed* while being described as a network boundary, and `deep`
  was byte-identical to `standard` — it promised more and delivered exactly
  `standard`.

  **The retired names still resolve, so existing configuration keeps working:**

  | old | new | |
  |---|---|---|
  | `quick` | `offline` | now also runs Checkov and Syft, which need no network |
  | `standard` | `full` | |
  | `deep` | `full` | it was never different |

  `offline` is now the **default**. The target market cannot send code or dependency
  manifests anywhere, and the dependency-reality check does transmit package names,
  so reaching the network is something you opt into rather than acquire by typing
  `valvur scan`.

- **`offline` now finds what `full` finds.** Trivy excludes development dependencies
  by default; valvur did not pass `--include-dev-deps`. Measured on a real project,
  `offline` reported 0 CVEs where `full` found 24 — the same 24, in the same
  lockfile, one flag apart. Build and test tooling runs on developer machines and in
  CI, which is precisely the supply-chain surface this tool exists to cover.

### Added

- **Checkov runs only where there is infrastructure to analyse.** It costs about ten
  seconds of fixed startup whatever it finds, so a repository with no Dockerfile,
  terraform, Kubernetes manifests, CI workflows or templates went from ~18s to ~7s.
  Detection is biased towards scanning when unsure, and the skip is reported in
  `SUMMARY.md` and `run.json` — a scanner that did not run must never look like one
  that ran and found nothing.
- **`[scan] exclude` in `.security-scan.toml`** — repo-relative paths a project has
  chosen not to scan, for deliberately vulnerable test fixtures and the like. Never a
  default: the count of excluded findings and the paths responsible both appear in
  the output.
- **`scripts/verify-offline.py`** — checks both halves of the non-exfiltration claim,
  the containers and the host shim, and reports what it cannot prove as well as what
  it can.
- **`run.json` now records** the profile, the scanners it did not run and why, the
  scanners skipped for having nothing to analyse, and what any exclusion cost.

### Fixed

- **Dependency findings now say what to upgrade to.** `fixed_version` was declared
  and never populated, so the remediation proposal restated that a vulnerability
  existed without saying what to do about it. It now names the *minimal* upgrade —
  OSV publishes a fix per release line, so `brace-expansion 1.1.15` carries fixes
  1.1.16, 2.1.2 *and* 5.0.7, and taking the first would advise a major-version jump
  where a patch exists.
- **Remediation no longer proposes a downgrade.** Distinct major lines of one package
  were merged into a single action, telling a 5.0.7 install to "upgrade to 1.1.18";
  and within a group the version named was whichever finding was grouped first rather
  than the one that clears them all. Case variants (`Pillow` vs `pillow`) were also
  proposed as two separate upgrades, the second undoing the first.
- **The same CVE from two scanners is now one finding.** Trivy reports the lockfile
  *format* (`pnpm`) where OSV reports the ecosystem (`npm`), so identical
  vulnerabilities never merged.
- **A missing report is a failure, not a clean result.** "No package sources found"
  — which OSV-Scanner emits for a project with a `pyproject.toml` and no lockfile —
  was treated as a crash, marking the whole run incomplete.
- **Dotfile paths keep their leading dot.** `lstrip("./")` takes a character set
  rather than a prefix, so `/.github/workflows/ci.yml` was reported as
  `github/workflows/ci.yml` — a path that does not exist, with a fingerprint no
  suppression could match.
- **A container that fails to start now says so.** The workspace probe discarded
  stderr, so a failed image pull was reported as "the container cannot read the
  workspace", sending the reader to check mount permissions for an authentication
  problem.
- **The licence check no longer states as fact what it cannot read.** npm licence
  metadata lives inside installed packages, not the lockfile; reporting "618
  dependencies declare no licence" asserted something unreadable rather than absent.
  Workflow files, lockfiles and GitHub Actions are no longer counted as dependencies.
- **Vendored code is excluded**, and its count reported. On a real project, 30% of
  findings came from a dependency's own test fixtures.
- **Secrets in gitignored files are ranked honestly** rather than as leaks.
- valvur no longer scans its own results folder, which produced findings about
  findings that compounded on every run.

### Security

- The version is now derived from package metadata in one place. It previously lived
  in five, and had already drifted: the shim ran as `0.1.0.dev0` while writing
  `0.1.0rc1` into `results.sarif` — a provenance artifact claiming a version the
  running code was not.

## [0.1.0rc1] — 2026-08-31

First published release candidate. Offline-first scanning, MCP server and CLI, the
layered results contract, exploit-aware ranking via CISA KEV and FIRST EPSS,
suppressions with mandatory expiry, and the checks built for AI-generated code:
slopsquat detection, agent-config auditing, hidden Unicode and LLM-output-to-sink
taint.
