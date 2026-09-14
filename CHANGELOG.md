# Changelog

All notable changes to valvur are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the 0.x caveat that
a minor bump may break things until 1.0.

## [Unreleased]

### Added

- **`valvur doctor`, and a `doctor` MCP tool.** Every precondition a first run has
  failed on for real, checked before a scan and named with the fix: the interpreter
  can verify TLS (python.org's macOS build has no CA bundle until its certificate
  script runs — 0 trusted roots, and every host-side fetch fails); the container
  runtime is found *and running* (a stopped daemon looks like a missing image to
  `image inspect`); the image is present, its version matches the shim's (F1.9), and
  a container of it actually starts; the vulnerability database and the name index
  are present and current, with each ecosystem's count; the SELinux label on the
  tree on an enforcing host; which Claude Code or Kiro configuration names the
  server, and whether it is disabled. One line per check, exit 1 if any would fail a
  scan. `--network` (or `network: true`) adds one bounded TCP connect per host a
  first run and `full` need, honouring every mirror setting; without it doctor opens
  no socket. A `scan_status` that reports FAILED now points at it.

- **How long each Scanner took.** `duration_s` on every entry of `run.json`'s
  `scanners`, on each line of `scan_status` (and on its "Completed so far" progress
  while a scan runs), and one line in `SUMMARY.md`: *"slowest: checkov 40.9s"*. The
  fleet runs concurrently, so the slowest Scanner is roughly what a scan costs. The
  corpus report gains `scan_s` and per-Scanner timings.

- **The shim carries the tree hash it was built beside.** A build hook writes
  `valvur/_build.py` into the wheel — the same digest over the same inputs the
  image records in `/etc/valvur/inputs.sha256` — and a scan compares the two,
  reading the image's once per image id. Different trees behind the same version
  (the hole `0.1.0rc1` fell through, which F1.9's version label cannot see) is now
  a warning in `run.json` (`build: {shim, image, match}`), `SUMMARY.md`,
  `scan_status` and `doctor`'s image line — never a refusal.
- **One bake file; each architecture built natively.** `docker-bake.hcl` is the
  one place the image build lives — `dev` for a local or CI image, `release` for a
  manifest pushed by digest — and `CONTRIBUTING.md`, `ci.yml`, `corpus.yml` and
  `release.yml` all build through it. The release builds amd64 and arm64 on their
  own native runners side by side and merges them into one index with
  `imagetools create`; QEMU is gone from the release.
- **Checkov 3.2.517 → 3.3.17**, through the lock: `requirements-checkov.in` moved,
  `scripts/lock-checkov.sh` regenerated the lock with the asteval override intact
  (Dependabot's own regeneration had dropped it, restoring the vulnerable pin —
  the self-scan gate refused that PR). Same 13 findings on the fixture. 3.3.17
  pulls in python-ecdsa, whose Minerva timing advisory (CVE-2024-23342) has no fix
  and none coming; accepted in `.security-scan.toml` with the reason and a
  one-year expiry, since Checkov never signs anything in a scan. ruff 0.16.7.
- **The three Checks run in one container.** `python -m valvur.checks batch` runs
  licence-file, ai-artifact and dependency-reality in one container start instead
  of three — nine container starts a scan became seven — with three ScannerRuns,
  three coverage contracts and each Check's findings and failures its own, as
  before. The batch carries the Profile's network grant (dependency-reality's on
  `full`, none on `offline`) and runs that Check last. Measured on the fixture on
  a loaded Mac: about four seconds off every scan.
- **Checkov hash-locked, in its own virtual environment.** `requirements-checkov.txt`
  pins Checkov and every one of its 96 transitive packages by version and sha256,
  and the image installs from it with `--require-hashes` into `/opt/checkov`, which
  shares nothing with valvur's interpreter — the system site-packages went from 96
  packages and 191MB to valvur alone. Regenerate with `scripts/lock-checkov.sh`;
  Dependabot watches the lock. The image is the same 576MB. Found on the way: the
  Dockerfile's `… && find … || true` let a failed `pip install` produce an image
  without Checkov and report success; scoped, and a test refuses the shape. And
  found by the lock's first self-scan: Checkov pins `asteval==1.0.6`, which has
  two sandbox-escape advisories fixed in 1.0.9 — the lock overrides it to 1.0.10
  (`requirements-checkov.overrides`, with the reason), so the image ships a
  Checkov that upstream's own users do not get.
- **`MaverickHQ/valvur-action`.** A composite GitHub Action: install the shim (a
  PyPI pin, a git source, or the `valvur` on PATH), install cosign so the name
  index's signature is verified, restore the index from the Actions cache, `valvur
  update`, `valvur scan`, read `run.json` into outputs, upload `results.sarif` to
  code scanning, `valvur gate`. One `uses:` line for CI adoption; this repository's
  own self-scan job uses it on every commit, with the shim from the tree under test.
- **A scan budget.** Over MCP a scan has a 300-second budget unless the client
  passes `budget_s` (0 for none); on the CLI none unless `--budget SECONDS`. Past
  it no new Scanner starts, the running ones are stopped, and the result is
  written incomplete with each cut Scanner named — *"cut by the 300s budget after
  300s"* / *"not started: the 300s budget was spent before its turn"* — in
  `run.json` (`budget: {seconds, cut}`), `SUMMARY.md`, `scan_status` and the gate.
  A cut is not a cancel: the Scanners that finished are a result.
- **`scan_cancel`, and `--jobs`.** A `scan_cancel` MCP tool stops a running scan
  the way Ctrl-C does on the command line (F1.11): its containers are killed — one
  `kill` for all of them, 2.7s for eight, measured — nothing is written, the
  previous results stand, and `scan_status` reads CANCELLING then CANCELLED rather
  than FAILED. A cancel stops that workspace's fleet, not another's. `valvur scan
  --jobs N` bounds how many Scanners run at once, honoured by the fleet's executor;
  `VALVUR_JOBS` sets the same default for the MCP server, for a Docker Desktop whose
  memory cannot start eight containers together.
- **`valvur gate` and `valvur cache`.** `gate [path] [--fail-on SEVERITY|any]
  [--no-inconclusive]` reads the last scan's `run.json` and `findings.json` and
  exits 1 if the result should not ship: an incomplete run, a lapsed suppression
  (at every threshold), an active finding at or above the threshold (default
  `high`; suppressed findings and coverage notes are never counted), or — asked for
  — an `inconclusive` scan. Exit 2 when there are no results. Under GitHub Actions
  each reason is a `::error::` annotation. It replaces the Python heredoc that
  `ci.yml` and `release.yml` each carried a copy of; the self-scan gate is now
  `valvur gate . --fail-on any --no-inconclusive`. `cache` lists the database, the
  index (with each ecosystem's count) and the KEV copy with size and age;
  `--clear` removes them under the exclusive cache lock, never the directory or
  the lock file.
- **`scan_status` names the next two moves.** After a scan with active findings:
  `explain_finding <fingerprint>` for the top-ranked one, with its location and
  title, and `REMEDIATION.md`'s first action (`action 1 of N: …`). An agent's
  first scan (22.G.1) never called `explain_finding` because nothing pointed at it.

### Changed

- **The README says what OSV-Scanner adds, measured.** On twelve real repositories
  `full` added 121 Go standard-library advisories on the one Go project (keyed on
  `go.mod`'s `go` directive, which Trivy reports only from binaries), one disputed
  Python advisory, and nothing on the other ten. It stays on `full`, with that
  number beside it; `scripts/corpus.py compare` repeats the measurement from any
  two corpus reports, and the weekly corpus run uploads it.
- **A failure reason on `scan_status` is never cut mid-sentence.** It was cut at
  80 characters — *"…no package-name index for PyPI, so"* — which was the one
  sentence the agent needed whole. Now every line of the reason is shown, indented
  under the Scanner's name, and only the number of lines is bounded (six, then
  "… N more line(s) in run.json").
- **A first `scan` fetches what is absent, and says so.** Measured against `0.2.0`
  over MCP with an empty cache, the first `scan` finished `complete: False` — Trivy
  and the dependency-reality Check both failed, each naming `valvur update`, which
  an agent cannot run. Now a scan that finds the vulnerability database or the
  package-name index *absent* fetches it first — the way it already pulled an absent
  image — and reports it on `scan_status` (*"Now: fetching the vulnerability
  database (119MB) — the first run only"*) and on the terminal. Measured from an
  empty machine: **110s** to a complete result, one tool call. A *stale* database
  or index is still never refreshed by a scan; the warning stands and you decide.
  `valvur update` is unchanged and remains the way to refresh. A fetch that fails
  costs only the Scanner that needed it, and that Scanner's failure says what went
  wrong; a scan never starts the seven-minute registry walk `valvur update` falls
  back to. A refused index signature still stops the scan.

## [0.2.0] — 2026-09-13

The first release anyone can install: the repository and both GHCR packages are
public, the image is published for `linux/amd64` and `linux/arm64`, and the shim
pulls the published image rather than a local development tag. Everything below was
on `main` between the release candidate and this tag.

### Changed — BREAKING

- **A scan can now report `inconclusive`.** Previously `status` was `findings` or
  `clean`; there is now a third value, for a scan that found nothing against a
  vulnerability database too old for that to be evidence. Anything parsing `status`
  and treating "not `findings`" as "safe" needs updating. What was *found* is real
  however old the data — only absence needs current data to mean anything.

  Keep the database current cheaply; the check costs one file read when it is:

  ```bash
  valvur update --if-stale
  ```

- **`Ctrl-C` now stops a scan.** It previously left the scanner containers running to
  completion, because the container runtime's daemon owns their lifecycle. An
  interrupted scan writes no results and is not reported as a failure.

- **One scan per project at a time.** A second concurrent scan of the same directory
  is refused with a message rather than silently spoiling the first run's status diff.

- **The image is published for `linux/amd64` as well as `linux/arm64`.** `0.1.0rc1`
  was arm64 only — unusable on most CI, most Linux desktops and every Intel Mac.

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

- **The package-name index is published, and `valvur update` pulls it.** Every name
  on PyPI, npm, RubyGems, Packagist and crates.io, built once a day by a workflow in
  this repository and pushed to `ghcr.io/maverickhq/valvur-index` as a cosign-signed
  OCI artifact — 34MB, seconds, instead of every machine walking the registries for
  eight minutes. The signature is verified when `cosign` is installed and its state is
  recorded; a refused signature stops the update. The walk remains as the fallback and
  as `valvur update --build-index`. `VALVUR_INDEX_REPOSITORY` and
  `VALVUR_INDEX_INSECURE` mirror it the way the database is mirrored
  ([ADR-0018](docs/adr/0018-offline-package-name-index.md), amended).
- **Ruby, PHP and Rust dependencies are checked for existence, offline.** `Gemfile`
  and `*.gemspec` against RubyGems (case-sensitive, as the registry is),
  `composer.json` against Packagist, `Cargo.toml` — every dependency table, workspace
  members and `package =` renames included — against crates.io, whose list is
  streamed out of its database dump. On `full` each also gets first-publish age.
  Five ecosystems offline; JVM and Go stay `full`-only.
- **`valvur update` pulls the image, and a scan that has to pull it says so.**
  The image was fetched silently by the runtime on the first *scan* — measured
  through Kiro, where the first tool call looked hung for as long as the pull took.
  Now `update` pulls it first, streaming the runtime's progress; a scan that finds it
  missing pulls it and reports *"pulling ghcr.io/…:0.2.0 (240MB) — the first run
  only"* on `scan_status` and on the CLI, with the size read from the registry's
  manifest when it states one. A failed pull is a named failure with the runtime's
  words and the command that fetches it by hand.
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

- **`0.1.0rc1` could not find its own image.** The published shim had the image name
  hard-coded as `valvur:dev` — a local development tag nobody else has — and never
  pulled the published `ghcr.io/maverickhq/valvur:0.1.0rc1`. A fresh install's first
  scan failed with "image not found". Found on 2026-09-12 by running the rc through
  Kiro on a machine that happened to have a `valvur:dev`: it used that, months newer
  than the shim, and the version check passed because both said `0.1.0rc1`. The tag
  is now derived from the shim's version (task 12a.2), and the image records what it
  was built from so a mismatch is caught (22.C.1).

- **`scan_status` no longer returns instantly.** It waits up to fifteen seconds for
  the scan to settle before answering, because an agent polls exactly as fast as the
  tool lets it: Claude Code polled fourteen times, and Kiro ten — **two thirds of
  what a scan cost in model credits was polling**, measured against the rc.

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
