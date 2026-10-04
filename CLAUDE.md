# CLAUDE.md

> For any agent or human joining with no prior context. **Budget: under 200 lines** of rules,
> decisions and current focus; history goes to `CHANGELOG.md`, the ADRs and `docs/history/`
> ([the text this replaced](docs/history/CLAUDE-2026-09-27.md)). **Name:** `valvur` (Estonian: *guard*).

## 1. What this is, and where it stands

A **local-first, fully offline** security scanner focused on AI-generated code. It
orchestrates open-source Scanners, normalises and ranks their findings, and writes an
agent-readable Results Folder into the project. Primary surface: an **MCP server** for
Claude Code or Kiro (ADR-0015); second, the CLI. One OCI image on Docker or Podman,
launched by a small host shim. **The goal every change is judged against:** from an agent
session, one request scans the project and writes a report into it that is fast, complete or
honest about why not, and trustworthy. Locally. **On target is the Score** (R9, ADR-0026):
`scripts/eval.py`, eight tracks by the OWASP Benchmark's formula, ratcheted in `tests/eval/`.

**Status (2026-10-04).** **`1.4.0` is published**, with R23 to R25, R21 and R22: the Score
**73.9** on Linux, the cloud VM and the Mac (64.9 at `1.2.0`), and releases carry their provenance.
[The review](docs/history/REVIEW-2026-10-03.md) scoped 2.0. R19 moved CI to 26.04; R26 lightened the release. **Next:** R27 to R29.

## 2. What it is NOT

- **Not a scanning engine.** Detection is Trivy, Gitleaks, Opengrep, zizmor, Checkov,
  OSV-Scanner and Syft, plus valvur's own Checks. Credit them; never imply proprietary detection.
- **Not a reachability analyser, an autonomous fixer (§4), a pen-test tool, or a
  code-quality platform.** Never claim or drift into any of them.

## 3. The moat: non-negotiable

The product is defined by what it refuses to do. A feature that trades one of these away is
rejected, or escalated to the owner explicitly.

1. **It never phones home, provably.** `offline` Scanners have no network interface; no
   account, API key or telemetry. The shim's fetches of public data (image, database, Name
   Index, KEV, EPSS, OSV's databases) carry nothing of the Workspace, and are recorded.
   One module decides the network, `src/valvur/egress.py`; `scripts/verify-offline.py`
   checks it independently; on Linux `unshare -rn valvur scan` proves it. macOS cannot.
2. **The source cannot be modified by a Scanner**, structurally: since R3.9 it is copied
   into the Scan Container as a Snapshot on stdin and never mounted (ADR-0022).
3. **Vulnerability data comes from auditable primary sources** (CISA KEV, FIRST EPSS, OSV,
   the registries), mirrorable for air-gapped use.
4. **Results never leave the machine and are never committed.**

## 4. Human in the loop is a safety property

The developer chooses which fixes to apply and when to rescan: an agent told to drive
findings to zero has a cheaper path through deleting code or writing suppressions, and *the
finding disappeared* is not *the vulnerability is fixed*. No `scan_and_fix` tool (a test
asserts none exists), no source-modifying MCP tool, no watchers or on-save hooks; the one
hook, the plugin's `valvur-hook`, asks before a flagged install and nothing else (D44, the
owner 2026-10-02). `REMEDIATION.md` is a proposal whose items apply independently.

## 5. Who it is for

Regulated industries that cannot send code to a vendor; data-residency jurisdictions; teams
shipping AI-generated code; developers who want one command and no account.

## 6. Locked decisions

Rationale and rejected alternatives are in `docs/adr/`. Do not re-litigate without a strong
new argument.

| ADR | decision |
|---|---|
| 0001 | Thin host shim, sealed container; results written by the host as the user. Implementation amended by ADR-0022. |
| 0002 | One findings model, projected to artifacts that each have one consumer. |
| 0003 | Per-class Finding identity; `fp_version` is a compatibility surface. |
| 0004 | Opengrep, not Semgrep (rule licensing). |
| 0005 | No GPL tool added to the image. This is why `git` is not in it. |
| 0006 | No graph database (and 0014: no HTML report). |
| 0007 | Enrichment is internal: KEV bundled, EPSS on demand. VulnGraph is parked, never a dependency. |
| 0008 | No SaaS-coupled dependency. |
| 0009 | Human-in-the-loop remediation (§4). |
| 0010 | Non-exfiltration is a tested property, not a policy. |
| 0011 | Scan output never enters git, on any branch. |
| 0012 | The vulnerability database lives outside the image, in the host cache. |
| 0013 | valvur's own Checks run inside the container. |
| 0015 | MCP stdio hand-rolled, zero dependencies. |
| 0016 | Two Profiles split on the network boundary: `offline` (default) and `full`. |
| 0017 | SELinux relabelling of the source is opt-in. Moot since R3.9: the source is never mounted. |
| 0018 | An exact, offline index of package names, published daily and signed. |
| 0019 | One image with Checkov in it. Reopened by task 34.1, on the ADR's own stated condition. |
| 0020 | Release is stage, validate, promote; the brake sits before the irreversible step. |

**Agreed by the owner:** 0021 to 0025 on 2026-09-27; 0026 to 0031 on 2026-09-29, written by
R9.2 from `tasks.md` §5, which holds every other decision the build needs, with fallbacks.

| ADR | decision |
|---|---|
| 0021 | The File Set is the git view, plus ignored `.env*` and agent configuration; excludes are root-relative prefixes; history is scanned |
| 0022 | One Scan Container per Profile boundary, fed a Snapshot; protocol 2 |
| 0023 | The Scanner set, by rule; amended with R4.1's measurements |
| 0024 | `scan` returns the result, with progress, instead of start-and-poll |
| 0025 | A scan refreshes stale data as it fetches absent data; `fetch = "never"` for air-gapped use |
| 0026 | The Score: eight tracks, TPR minus FPR, a ratchet no track may fall 2 points under |
| 0027 | Every dataset's age is its data's; index, KEV and EPSS refreshed past 2 days; EPSS from FIRST's daily file; `MAL-` names published daily |
| 0028 | `check_package`, offline, before an install; private registries and dependency confusion |
| 0029 | Static-analysis rules from licence-audited sources, each shipped only on measured precision |
| 0030 | Trivy's and OSV-Scanner's results reused when their inputs and data are unchanged |
| 0031 | One skill in the open Agent Skills format, shipped as a Claude Code plugin, a Kiro power and by `init --write`; no separate agent |

## 7. The Results Folder

```
.security-scan/
  .gitignore      "*": the folder ignores itself from creation
  .lock           one Scan Run per Workspace at a time
  SUMMARY.md      entry point, bounded, leads with failures
  REMEDIATION.md  ranked proposal
  findings.json   normalised, schema-versioned, secrets redacted
  results.sarif   SARIF 2.1.0
  sbom.cdx.json   CycloneDX, when asked for (`--sbom`)
  run.json        provenance: versions, what ran, what was fetched, what left (nothing)
  state.json      the previous run's fingerprints and their Scanners
  raw/            per-tool output, secrets redacted
```

`.security-scan.toml` at the project root is committed: Suppressions with mandatory expiry
dates, and `[scan] exclude`.

- **Three Statuses**: `findings`, `clean`, `inconclusive`. Clean is never claimed when it
  cannot be supported: a stale database, an uninspected ecosystem or a Scanner that did not
  complete makes a nil result `inconclusive` (F7.19), and `status_reason` says why in one line.
- **The verdict is about the code.** Only active Findings count: not suppressed ones, and
  not coverage notes, which are valvur's own limits.
- **Fail loudly.** A Scanner that failed, timed out, was cut or skipped is named at the top.
  A partial run says *incomplete*.
- **A Finding is fixed only if the Scanner that reported it ran** (F5.6). Otherwise it is
  *not re-checked*.
- **One generation per folder**, `run.json` written last. **Evidence is neutralised**, in
  files and MCP replies (F3.13, F9.9). The project's own `.gitignore` is never touched.

## 8. Finding identity

| Class | Identity |
|---|---|
| Dependency CVE | `(ecosystem, package, version, vuln_id)` |
| Secret | `(rule, path, sha256(secret)[:16])` |
| IaC misconfig | `(rule, path, resource_address)` |
| Licence | `(package, license_id)` |
| Slopsquat, dependency reality | `(ecosystem, package_name)` |
| SAST, AI artifact | `(rule, path, sha256(normalised_match), occurrence)` |

Never line numbers. Paths are repo-relative, so fingerprints match across machines. A change
to the algorithm bumps `fp_version` and invalidates every Suppression everywhere.

## 9. How we work

- **Spec-driven.** `.kiro/specs/valvur/` holds requirements, design and tasks; `tasks.md` is
  authoritative. Requirement IDs are **never renumbered**; change one by amendment.
- **Layers** (D50): `core` < `infra` < `app` < `surfaces`, no cycle, held by `scripts/layers.toml`
  and `scripts/check_layers.py` in `verify.sh`. A deferred import says why: `# deferred:`.
- **Vocabulary:** [`CONTEXT.md`](CONTEXT.md), used exactly. **Measure before writing:** a
  task starts from evidence and closes with the after-measurement in a STATUS note.
- **Test-driven, in vertical slices** (the `tdd` skill; `tasks.md` §3): each task lists its
  behaviours in test order, one red-to-green slice and one commit each, for example
  `feat(r3.4): …`. Never refactor while red. Fake only the container runtime and the network.
- **Every phase ends with a phase commit**, `chore(r<n>): close phase R<n>, …`, and one PR
  (`tasks.md` §4). Commit messages must pass the Conventional Commits hook.
- **Unattended** (`tasks.md` §1 and §2): the build runs without the owner and, after a
  usage limit, resumes through the schedules R9.1 arms. Owner-only steps wait in its §8.
- **Landing.** `main` is protected (eight required checks, signed commits, linear history); a
  phase lands by fast-forward. Auto mode refuses that push and a tag push, so the executor
  never makes them: phases stack, and the owner approves the landing in manual approve mode.
- **Local tests:** `PYTHONDONTWRITEBYTECODE=1 uv run --extra dev pytest -q -p no:cacheprovider
  -m "not e2e and not timing"` unless the container or the clock is the point; scans use
  `VALVUR_CACHE=~/.cache/valvur-build VALVUR_IMAGE=valvur:dev`, never the owner's cache or images.
- **The acceptance set and the Score judge** (`scripts/acceptance.py`, `scripts/eval.py`): a
  phase's exit is measured on this Mac and on Linux. **After R9, a change to detection,
  ranking, data or the reply** runs `scripts/eval.py --compare tests/eval/baseline.json` before
  its PR, which carries the Score; a track over 2 points under its baseline blocks it.
- **Releases** follow `docs/RELEASING.md`. The executor prepares and rehearses; the signed
  tag and the approval at the brake are the owner's. The tool scans itself, clean, first.
- **Documents an agent can hold:** this file under 200 lines; comments state invariants;
  closed work goes to `docs/history/`; the README cites only measured numbers (R7.1).

## 10. Prohibited without explicit owner approval

- Any network call in the `offline` Profile beyond the approved, recorded fetches of public
  data: absent data since 24.1, stale data under ADR-0025, and KEV's and EPSS's daily files
  and the malicious list under ADR-0027 (the owner, 2026-09-29).
- Any dependency requiring an account, API key or token.
- Any feature that writes to the scanned source tree. The exceptions: the Results Folder,
  and `init --write` (the owner, 2026-09-28), which never overwrites.
- Any autonomous remediation.
- Any claim of reachability analysis, proprietary detection, or coverage we do not have.
- Bundling a GPL-licensed tool into the image.

## 11. Things that cost a day to learn

- Killing `docker run` does not stop its container. Stop by name or label; confirm gone.
- Claude Code gives a stdio tool call a 30-minute idle window, backgrounds it after two
  minutes, and hands the model only `structuredContent` when a reply has both forms. It sets
  `CLAUDE_PROJECT_DIR`, answers `roots/list`, and health-checks a project server only once approved.
- GitHub's macOS runners cannot run containers (measured 2026-09-22).
- Listing 109,521 files: 1.6 s on a Mac's host, 16.6 s through Docker Desktop's mount.
- The release constraint suite may not shrink below 48 tests (54 since R3); a new test that
  is not a constraint goes in its own file. More lessons: section 1 of the archived `CLAUDE.md`.
