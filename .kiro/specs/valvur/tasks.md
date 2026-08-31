# valvur — Implementation Plan

**Status:** ready to execute · **Version:** 2.0 · **Date:** 2026-08-30

Implements [design.md](./design.md) against [requirements.md](./requirements.md).
Vocabulary is [CONTEXT.md](../../../CONTEXT.md); decisions are
[docs/adr/](../../../docs/adr/).

---

## How to execute this plan

**One phase = one commit**, with one documented exception. Each phase states its goal,
its TDD cycles, an exit criterion, and its commit message. Do not span phases.

The rule exists to keep changes reviewable. **Phase 3 is large enough that obeying its
letter would defeat its purpose** — a single commit containing a refactor, the failure
model, concurrency and five Scanner adapters is the opposite of reviewable. Phase 3
therefore commits per sub-phase (3.0 … 3.4), each self-contained and green. Any future
phase that grows past roughly one reviewable diff should do the same, deliberately and
noted here — not silently.

**TDD is vertical, never horizontal.** Each numbered cycle below is one
RED→GREEN pass: write *one* test for *one* behaviour, watch it fail, write the
minimum code to pass, move on. **Never write a batch of tests and then a batch of
implementation** — tests written in bulk describe imagined behaviour and end up
asserting the shape of data structures instead of what the system does.

```
RIGHT:  test → impl → test → impl → test → impl
WRONG:  test, test, test → impl, impl, impl
```

**Cycles are written as behaviours, not implementation steps.** A cycle reads like a
sentence about what valvur does. If a cycle can only be verified by reaching into
internals, it is the wrong cycle — restate it in terms of observable behaviour.

**Refactor only when green.** At the end of each phase, refactor with tests passing,
then commit.

**These cycles are the priority list, not the whole test suite.** They cover critical
paths and the constraints that define the product. Add edge-case tests as you learn
what actually breaks — do not pre-emptively expand this list.

---

## Phase 0 — Preflight

> **✅ COMPLETE 2026-08-30 — 18 of 19; 0.2 skipped as optional, 0.14 deferred to Phase 12.**
> Repo: https://github.com/MaverickHQ/valvur (private) · ECR:
> `556632219584.dkr.ecr.eu-north-1.amazonaws.com/valvur` · first commit `8d9674a`, signed and verified.

**Goal:** every account, credential, runtime and tool the plan depends on is verified
working *before* any code exists. No implementation.

Recon performed 2026-08-30 on the target machine; re-verify each line, since these
drift.

### Local environment

- [x] **0.1** Start the Docker daemon and confirm `docker info` succeeds.  
  **STATUS 2026-08-30:** ✅ Docker 29.2.1 daemon running
  *(Recon: Docker 29.2.1 installed, daemon was not running.)*
- [ ] **0.2** *(Optional in this phase)* Install Podman. Not needed until Phase 8,
  where F1.4 requires proving Results Folder ownership on Docker *and* rootless
  Podman. **It becomes mandatory at Phase 8** — either install it then, or downgrade
  F1.4 deliberately and drop the dual-runtime claim from the README. Do not simply
  leave the test unwritten. *(Recon: not installed.)*
- [x] **0.3** Create the project virtualenv with `uv` and pin the toolchain there.  
  **STATUS 2026-08-30:** ✅ .venv Python 3.12.10 · pytest 9.1.1 · ruff 0.16.5 · mypy 2.3.1
  *(Recon: `pytest` currently resolves to a Python 3.10 framework install while
  `python3` is 3.12 — never run project tests against that.)*
- [x] **0.4** Install `cosign` (release signing, F10.3) and `syft` + `trivy` on the  
  **STATUS 2026-08-30:** ✅ cosign v3.1.3 · syft 1.51.1 · trivy 0.74.0 · gitleaks 8.30.1
  host for adapter development against real output.

### Local git

Do all of this **before the first commit**. Git history is append-only in practice —
a secret or a stray artifact committed here is permanent, and for this project it
would be the worst possible opening line.

- [x] **0.5** `git init` with default branch `main`.  
  **STATUS 2026-08-30:** ✅ initialised on `main`
- [x] **0.6** Write `.gitignore` **before staging anything**: `.security-scan/`,  
  **STATUS 2026-08-30:** ✅ written before anything was staged
  `.venv/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `dist/`, `build/`, `*.egg-info/`,
  `.env`, `.DS_Store`. The **Results Folder** entry matters most — a tool that
  promises results are never committed must not commit its own.
- [x] **0.7** Write `.gitattributes` pinning text line endings, so **Fingerprints**  
  **STATUS 2026-08-30:** ✅ written
  computed on a Windows checkout match those on macOS. *(Guards F5.4 at the VCS
  layer, where it is otherwise easy to miss.)*
- [x] **0.8** Confirm identity resolves to `MaverickHQ`. *(Verified 2026-08-30.)*  
  **STATUS 2026-08-30:** ✅ MaverickHQ
- [x] **0.9** **Configure commit signing** and enable `commit.gpgsign`. *(Recon: both    
  **STATUS 2026-08-30:** ✅ SSH signing configured, repo-local. Key loaded via `--apple-use-keychain`.
  unset.)* A security tool with unsigned history is the first thing a reviewer
  notices, and signed commits are the same promise as the signed release image.
- [x] **0.10** Install a `gitleaks` pre-commit hook so a secret cannot enter history  
  **STATUS 2026-08-30:** ✅ tracked in `.githooks/`, `core.hooksPath` set — proven: scanned 97KB, no leaks
  in the first place. We ship secret scanning; we should not be the project that
  leaks one.
- [x] **0.11** Adopt Conventional Commits — the phase commit messages in this plan  
  **STATUS 2026-08-30:** ✅ `.githooks/commit-msg` — proven: rejected a non-conventional message
  already follow it, and it makes release notes generatable.
- [x] **0.12** Make the initial commit and verify `git log --show-signature` confirms    
  **STATUS 2026-08-30:** ✅ commit `8d9674a` — *Good git signature for MaverickHQ*, registered as a GitHub signing key.
  it is signed.

### GitHub

**GitHub only.** GitLab is out of scope; the image is published to GHCR, and to ECR
for AWS execution.

- [x] **0.13** Create the repository — private initially — and push. `gh` is already  
  **STATUS 2026-08-30:** ✅ https://github.com/MaverickHQ/valvur (private), `origin` set
  authenticated as MaverickHQ. This also **reserves the name** while changing it is
  still free.
- [ ] **0.14** Enable branch protection on `main`: require a passing CI check, and    
  **STATUS 2026-08-30:** ⏳ **DEFERRED to Phase 12.** GitHub returns 403 — branch protection on *private* repos needs GitHub Pro. It becomes free when the repo goes public at release, and it guards nothing on a solo private repo. Re-attempt at 12.5, immediately after the repo is made public.
  require signed commits.
- [x] **0.15** Verify you can push a package to GHCR under this account, so the    
  **STATUS 2026-08-30:** ✅ `docker login ghcr.io` succeeded with the refreshed `write:packages` scope.
  container publishing path is proven before it is needed.

### AWS

- [x] **0.16** Confirm STS identity. *(Verified: account `556632219584`, IAM user  
  **STATUS 2026-08-30:** ✅ account 556632219584, IAM user Tromso-Aura-Hunter-dev
  `Tromso-Aura-Hunter-dev`.)*
- [x] **0.17** Verify that identity can create an ECR repository and push to it. It is  
  **STATUS 2026-08-30:** ✅ simulate-principal-policy: CreateRepository, InitiateLayerUpload, PutImage, GetAuthorizationToken all **allowed**
  an IAM **user**, not a role — check the policy rather than assuming.
- [x] **0.18** Create the ECR repository with immutable tags and scan-on-push.  
  **STATUS 2026-08-30:** ✅ 556632219584.dkr.ecr.eu-north-1.amazonaws.com/valvur — IMMUTABLE tags, scan-on-push
- [x] **0.19** Decide whether a dedicated least-privilege publishing role replaces the    
  **STATUS 2026-08-30:** ✅ **DECIDED 2026-08-30: keep `Tromso-Aura-Hunter-dev` for now.** Its ECR permissions are verified sufficient. Revisit only if the account gains other users or the image is published from CI rather than from Harvey's machine.
  dev user before first release. Record the answer here; do not leave it implicit.

**Exit:** every box ticked, every recon line re-verified, and any deviation recorded
in this file. **Do not start Phase 1 with a failing preflight** — every one of these
becomes a confusing failure later if skipped.

**Commit:** `chore: preflight — verify toolchain, remotes, and AWS access`

---

## Phase 1 — Walking skeleton

> **✅ Cycles 1–8 complete 2026-08-30.** 12 tests green (10 unit, 2 e2e), CI green on
> Linux. Only 1.12, the usability gate, remains — it needs a person.
>
> **Three defects found by tests, not review:**
> 1. The e2e test caught container paths (`/workspace/…`) leaking into **Findings**,
>    which would have broken **Fingerprint** portability (F5.4).
> 2. The first fixture used AWS's published example key, which gitleaks allowlists —
>    the fixture was unscannable by construction.
> 3. **CI on Linux caught a design hole macOS hid.** Rootful Docker does not translate
>    UIDs the way Docker Desktop does, so the container could not write its report —
>    and `scan()` reported the broken run as **clean**. Exactly the silent failure the
>    project calls worse than no scan. Now raises `ScannerFailed` (F2.5, N3.1).
>
> Defect 3 is the argument for ADR-0001's dual-runtime requirement, arriving seven
> phases before Phase 8 was due to test it.

**Goal:** `valvur scan` works end to end, for a real user, with a single **Scanner**.
Thin but complete: install → scan → read results.

This is the tracer bullet. It exists because usability is a requirement, and the only
way to know the install and first-run experience is right is to have one on day two
rather than month two. Every later phase adds depth to a system that already works.

### TDD cycles

1. Scanning a **Workspace** with a planted secret reports one **Finding**.
2. Scanning a clean **Workspace** reports no **Findings** and still writes a
   **Results Folder** with an explicit clean status. *(F7.11)*
3. A **Scan Run** writes `.security-scan/` containing `SUMMARY.md`. *(F7.1, F7.4)*
4. The **Results Folder** ignores itself — `.security-scan/.gitignore` contains `*`.
   *(F7.2)*
5. `git status` in a scanned **Workspace** shows no untracked scan output. *(F7.2 —
   the guarantee, verified the way a user would see it.)*
6. A secret's value never appears in any written file. *(F5.7, N2.4)*
7. The **Workspace** is unchanged after a **Scan Run** — no file added, modified or
   removed outside `.security-scan/`. *(F1.3, N2.2)*
8. A **Scan Run** exits zero when **Findings** exist. *(N3.2)*

### Also in this phase

- [x] **1.9** Minimal container image with Gitleaks pinned; non-root, read-only root  
  **STATUS 2026-08-30:** ✅ `Dockerfile` — gitleaks v8.30.1 pinned, alpine 3.22, UID 10001, read-only rootfs, all caps dropped.
  filesystem. *(F10.2)*
- [x] **1.10** Shim invokes it with `-v ws:/workspace:ro` and a host scratch mount.  
  **STATUS 2026-08-30:** ✅ `ContainerRunner` — `--network=none --read-only --cap-drop=ALL -v ws:/workspace:ro` + host scratch.
  *(F1.1)*
- [x] **1.11** Fixture **Workspace** at `tests/fixtures/broken-repo/` — for now just a  
  **STATUS 2026-08-30:** ✅ `tests/fixtures/{broken,clean}-repo/`. **Note:** the first fixture used AWS's published example key, which gitleaks allowlists — it was unscannable by construction. Replaced with generated credentials.
  planted fake secret; grows each phase.
- [x] **1.11b** CI check failing the build if any path under `.security-scan/` appears  
  **STATUS 2026-08-30:** ✅ `.github/workflows/ci.yml` guard job. Verified both ways: passes clean, fails on output committed via `--no-verify` with hooks bypassed.
  in the tree or in a pushed commit. The `pre-commit` hook is the first line, but a
  hook can be bypassed with `--no-verify`; CI cannot. *(ADR-0011)*
- [ ] **1.12** **MOVED to Phase 10 (task 10.0) on 2026-08-30**, at Harvey's request.
  Rationale for moving: there is no truthful install path yet — the README describes
  v1 while we have built Phase 1 — so a participant today would only discover that the
  software is not published, which we already know. Participants cannot be reused;
  first-run impressions do not reset.
  **Cost accepted:** Phase 1 was ordered as a walking skeleton specifically to get this
  signal early. Deferring means Phase 10's task list rests on our own assumptions until
  the gate runs, which is why it now runs *first* in Phase 10 rather than last.


**Exit:** a real user can install valvur and scan a real repository. Cycle 5 passes.

**Commit:** `feat: end-to-end scan skeleton with gitleaks`

---

## Phase 2 — Finding identity

> **✅ COMPLETE 2026-08-30.** All 12 cycles green; 24 tests total.
> Rescan loop verified end-to-end against the real container: two findings reported
> `new`, one secret removed, rescan reports one `persisting` and one `fixed`.
>
> Cycles 2, 3 and 9 passed with no new code — deriving identity from the secret rather
> than its location already delivered them. That is the design working, not a gap in
> the tests: they are written in user-visible terms precisely so they *prove* the
> mechanism rather than restate it.
>
> Classes for dependency_vuln, iac_misconfig, licence and dependency_reality are
> implemented and tested now, though the Scanners that produce them arrive in Phase 3.
> Identity is Phase 2's subject; who reports it is not.

**Goal:** **Findings** survive editing, so the scan → fix → rescan loop can tell
progress from noise. The highest-value code in the system; ADR-0003 makes it the most
expensive thing to change later.

### TDD cycles

1. A **Finding** reported twice for unchanged code keeps the same **Fingerprint**.
2. A **Finding** keeps its **Fingerprint** when unrelated lines above it move.
   *(The behaviour ADR-0003 exists for.)*
3. A **Finding** keeps its **Fingerprint** when the file is reformatted.
4. Fixing the underlying problem changes the **Finding**'s **Status** to `fixed`.
5. A **Finding** present in both runs has **Status** `persisting`.
6. A **Finding** absent from the previous run has **Status** `new`.
7. A **Finding** that was `fixed` and returns has **Status** `regressed`.
8. On a first-ever **Scan Run**, every **Finding** is `new`. *(F5.9)*
9. **Fingerprints** are identical for the same **Workspace** on a different machine
   and OS. *(F5.4)*
10. Two identical patterns in one file yield two distinct **Findings**.
11. A **Finding** reported by two **Scanners** appears once, naming both. *(F5.8)*
12. Bumping a vulnerable dependency marks its **Finding** `fixed`. *(The dependency
    class earns its own cycle — its key is unrelated to location.)*

Each cycle covers one **Finding Class** as it becomes relevant. Do not write all six
classes' tests before implementing any of them.

**Exit:** a scripted edit-then-rescan sequence reports exactly what changed.

**Commit:** `feat: stable per-class finding identity and status diff`

---

## Phase 3 — Scanner fleet

**Goal:** the remaining five **Scanners** contribute **Findings** through one
normalised model, inside an orchestrator that already handles failure, profiles and
concurrency correctly.

> **Reordered 2026-08-30 after reviewing Phases 1–2.** The original plan added five
> Scanners and *then* defined what happens when one fails. That is backwards: failure
> handling is the fleet's architecture, so building it afterwards means rewriting every
> adapter. Failure semantics, profile selection and concurrency now come first, and
> each Scanner slots into a structure that already works.

### 3.0 — Refactor to adapters *(no behaviour change)*

- [x] **3.0.1** Extract a `ScannerAdapter` per tool, each owning: invoke, parse,  
  **STATUS 2026-08-30:** ✅ `adapters/{base,gitleaks}.py`. `api.scan()` is now orchestration only: sequence adapters, merge, diff, write. `_relative()` became `container_relative()` in `base.py`, shared because every Scanner sees the same mount.
  path-normalise, and fingerprint by **Finding Class**. `scan()` becomes orchestration
  only. Do this while there is *one* adapter to move rather than six.
  `_relative()` is gitleaks-shaped and moves into the adapter — Trivy reports target
  names, Checkov file paths, OSV lockfile paths.
- [x] **3.0.2** All 24 existing tests must pass unchanged. If a test needs editing,  
  **STATUS 2026-08-30:** ✅ **Zero test files modified**, 24 pass, ruff and mypy clean.
  the refactor changed behaviour and has gone wrong.

**Commit:** `refactor: extract scanner adapters`

### 3.1 — Failure semantics

> **✅ COMPLETE 2026-08-30.** All 5 cycles green, 31 tests total.
> Phase 1's `ScannerFailed` test survived unchanged, because with one Scanner a single
> failure *is* total failure — the rule generalised cleanly rather than needing a
> rewrite.
> Added beyond the cycles: `run.json` carries an explicit `"complete"` flag, because
> `"status": "clean"` on a run where every Scanner crashed is a lie of omission. It is
> the first field an agent should read.

> **This changes existing behaviour.** Phase 1 raises `ScannerFailed` when the single
> Scanner fails, which was right for one and is wrong for six — it contradicts cycle 1
> below. `test_a_scanner_that_produced_no_report_is_not_reported_as_clean` therefore
> **changes meaning**: failure becomes a per-Scanner record, and the exception is
> reserved for total failure. This is deliberate, not a broken test to "fix".

1. A crashing **Scanner** is reported at the top of `SUMMARY.md` and the **Scan Run**
   completes with the other Scanners' results. *(F2.5, F7.7)*
2. A **Scanner** that times out is recorded as failed, never as clean. *(F2.7)*
3. A **Scanner** exiting non-zero *because it found issues* is a successful run.
   *(F2.4)*
4. When every **Scanner** fails, the **Scan Run** fails and exits non-zero. *(N3.2)*
5. `run.json` records which Scanners ran, which failed, and why. *(F7.12, N3.1)*

**Commit:** `feat: per-scanner failure isolation`

### 3.2 — Profile selection and concurrency

> **✅ COMPLETE 2026-08-30.** All 3 cycles green, 34 tests.
> Scanners run in a thread pool — each is a container invocation, so the work is
> I/O-bound and threads are the right tool. Results are collected back into
> *declaration* order, so a **Scan Run** is reproducible regardless of which Scanner
> finished first.

> Neither appeared in the original Phase 3 despite both being required. Concurrency
> especially: six Scanners run serially will not meet the 5-minute `full` budget
> (N1.2), and discovering that in Phase 11 means restructuring the orchestrator after
> everything depends on it.

6. The `offline` **Profile** runs only its designated **Scanners**, per the matrix in
   [design.md](./design.md) §2. *(F2.3)*
7. Independent **Scanners** run concurrently, and a slow one does not serialise the
   rest. *(F2.6)*
8. A per-**Scanner** timeout fires independently and is recorded per cycle 2. *(F2.7)*

**Commit:** `feat: profile selection and concurrent scanner execution`

### 3.3 — The Scanners

> **✅ COMPLETE 2026-08-30.** All five Scanners contribute. Full real scan of the
> fixture: 29 findings across gitleaks, trivy, osv-scanner, checkov and syft in
> **11.8s** — well inside the 5-minute standard budget (N1.2).

One vertical slice each. **Capture that Scanner's real output as a golden fixture at
the moment you write its cycle**, not in a batch beforehand.

9. Trivy dependency vulnerabilities become **Findings** with the `dependency_vuln`
   identity already built in Phase 2.
10. OSV-Scanner findings become **Findings** and merge with Trivy's where they agree,
    keeping both sources. *(F5.8)*
11. Opengrep results become **Findings** using the `sast` identity, including ordinal
    disambiguation for repeats.
12. Checkov IaC misconfigurations become **Findings** carrying the resource address.
13. Syft produces `sbom.cdx.json`.

**Commit:** `feat: full scanner fleet`

### 3.4 — Safety and supporting work

> **✅ COMPLETE 2026-08-30.** 45 tests (42 unit, 3 e2e).

14. A **Workspace** path containing shell metacharacters reaches the **Scanner**
    unaltered and unexecuted. *(N2.3)*

- [x] **3.4.1** **Golden fixture version discipline.** Fixture filenames carry the  
  **STATUS 2026-08-30:** ✅ `conftest.golden()` resolves fixtures by pinned version and fails loudly on a mismatch, rather than silently re-baselining.
  Scanner version, asserted against the version pinned in the image. Without this, a
  Scanner upgrade silently re-baselines the goldens and parsing changes go unnoticed.
- [x] **3.4.2** Grow `tests/fixtures/broken-repo/` per cycle: a dependency manifest  
  **STATUS 2026-08-30:** ✅ Fixture grew per cycle: `requirements.txt` (urllib3 1.24.1, PyYAML 5.1 — long-standing advisories), `main.tf`, `handler.py` incl. a byte-identical pair to exercise ordinal disambiguation.
  with a **stable** known-vulnerable package (one whose advisory will not be
  withdrawn), Terraform with a misconfigured resource, and code with a SAST issue.
  Keep it strictly inside `tests/fixtures/` — Phase 11's self-scan will otherwise flag
  our own test data in our own release gate.
- [x] **3.4.3** **Measure the image and record it.** We are at 30.4MB with gitleaks;  
  **STATUS 2026-08-30:** ✅ **Measured: image 674MB, host DB cache 1.2GB fetched once via `valvur update`.** Decision: accept 674MB and keep a single image. The DB dominates and is out-of-image by ADR-0012, so it does not gate first run — a machine without it records Trivy as *skipped*, honestly, rather than reporting clean. Revisit only if the image passes ~1GB.
  the fleet will be roughly 1GB, mostly the Python layer. P1 promises useful output in
  under 60 seconds, and for a first-time user that includes pulling the image. Decide
  now whether `offline` warrants a smaller image or whether we accept and document the
  download. This is a Phase 3 decision because by Phase 10 the image is fixed.
- [x] **3.4.4** `state.json` should remember *what* was fixed, not only that something  
  **STATUS 2026-08-30:** ✅ `state.json` stores titles alongside fingerprints; `SUMMARY.md` gained a **Fixed since the last scan** section naming each one. Old list-shaped state is migrated silently.
  was. `SUMMARY.md` currently cannot say "you fixed the AWS key in config.py". A title
  alongside each fingerprint is a few lines now and awkward later.

**Exit:** all six **Scanners** contribute; killing any one still yields a complete,
honest run; the `offline` **Profile** runs only its Scanners, concurrently.

**Commit:** `feat: scanner fleet safety and supporting work`

---

## Phase 4 — AI-specific Checks

**Goal:** the differentiator — the Checks nobody else ships.

> **Reordered and sub-phased 2026-08-30 after reviewing Phases 1–3.** The original
> order put the Dependency Reality Check first, which carries all of this phase's new
> infrastructure — registry clients, caching, rate limits, a popularity dataset. The
> AI Artifact Check needs none of that and is the most differentiated feature, so it
> goes first and establishes the **Check** contract on the simplest case.

### 4.0 — The Check protocol

**Checks are not Scanners.** [CONTEXT.md](../../../CONTEXT.md) already draws the line:
a **Scanner** is a third-party tool, a **Check** is ours. The adapter contract models
"invoke an external tool in a container, parse its output", and forcing our own code
through it would mean fabricating a fake stdout to parse back.

- [x] **4.0.1** Add a `Check` protocol — `run(workspace) -> list[Finding]` — that the  
  **STATUS 2026-08-30:** ✅ `checks/` package with a `Check` protocol, in-container entry point, and a `CheckAdapter`. **No orchestrator change was needed** — see 4.0.2.
  orchestrator sequences alongside adapters, sharing failure isolation, **Profile**
  selection, concurrency and **Provenance**.
- [x] **4.0.2** **Checks run inside the container**, like Scanners. The tempting  
  **STATUS 2026-08-30:** ✅ Checks run in-container (ADR-0013). Because they emit JSON they fit the *existing* adapter contract, so they inherit failure isolation, profiles, concurrency and provenance for free. Adapters gained `kind` (`scanner`/`check`) so credit stays honest (P4).
  shortcut is running them host-side in the shim, which is simpler and needs no image
  rebuild. It is wrong: the Dependency Reality **Check** makes registry calls, and
  host-side those sit entirely outside `--network=none`. The moat would revert from a
  property to a policy. In-container, `offline` *cannot* reach a registry, so F3.5's
  "reports skipped" is enforced by architecture rather than by remembering.
- [x] **4.0.3** All 45 existing tests pass unchanged.  
  **STATUS 2026-08-30:** ✅ No existing test file modified by the refactor. Three tests were then updated for a **behaviour** change — adding `licence-file` to the defaults — and were over-specified anyway: they counted *total* findings rather than asserting the behaviour under test, so any new Check would have broken them.

**Commit:** `refactor: add the Check protocol alongside scanner adapters`

### 4.1 — AI Artifact Check

> **✅ COMPLETE 2026-08-30.**

Pure static file inspection: no network, no new machinery, and the feature nothing
else ships.

1. Zero-width Unicode in an agent instruction file is a **Finding**. *(F3.7)*
2. Bidirectional and tag characters are likewise detected. *(F3.7)*
3. An MCP server pinned to a mutable git ref is a **Finding**. *(F3.8)*
4. Blanket tool auto-approval is a **Finding**. *(F3.9)*
5. A permission-bypass directive is a **Finding**. *(F3.9)*
6. An agent file containing "ignore previous instructions" is reported as a
   **Finding** whose evidence is quoted, not obeyed. *(F3.12)*
7. **That quoted evidence is neutralised in every written artifact** — hidden Unicode
   escaped rather than reproduced, directive text fenced and labelled untrusted.
   *(F3.13)*

> **Cycle 7 is the one that matters, and the original plan missed it.** valvur is
> deterministic code and cannot "obey" anything, so cycle 6 tests the wrong end of the
> problem. The real risk is downstream: an agent reads `SUMMARY.md` first and *by
> instruction*. Reproduce a payload verbatim and we launder an attack out of a file the
> agent might never have opened into one we tell it to read. **valvur must not become
> the delivery mechanism.**

- [x] **4.1.8** Fixture: agent artifacts carrying each planted problem — a `CLAUDE.md`  
  **STATUS 2026-08-30:** ✅ Fixture gained `CLAUDE.md` (U+200B/200D/FEFF), `AGENTS.md` (injection + U+202E), `.mcp.json` (@main + blanket autoApprove), `.claude/settings.json` (bypassPermissions).
  with zero-width characters, an `.mcp.json` on `@main` with blanket `autoApprove`,
  and an injection payload. Keep them inside `tests/fixtures/`, and confirm they do
  not trip our own self-scan in Phase 11.

**Commit:** `feat: AI artifact check with evidence neutralisation`

### 4.2 — Opengrep rules

> **✅ COMPLETE 2026-08-30.**

Extends the ruleset already shipped in Phase 3. No new infrastructure.

8. Model output flowing into a shell, `eval`, `exec`, SQL or `innerHTML` is a
   **Finding**. *(F3.10, OWASP LLM05)*
9. An unpinned dependency range is a **Finding**. *(F3.11)*
10. A missing lockfile is a **Finding**. *(F3.11)*
11. A dependency on a mutable git ref is a **Finding**. *(F3.11 — the same defect we
    found in the AWS sample that started this project.)*

**Commit:** `feat: LLM-output-to-sink and pinning hygiene rules`

### 4.3 — Licence Check

> **✅ COMPLETE 2026-08-30.**

12. A **Workspace** with no licence file is a **Finding**. *(F4.2)*
13. A licence file contradicting package metadata is a **Finding**. *(F4.3)*
14. A copyleft dependency inside a permissive-declared project is a **Finding**.
    *(F4.5)*
15. A dependency whose licence cannot be determined is a **Finding**. *(F4.6)*

Dependency licences come from the Syft SBOM already produced in Phase 3, so this
Check reads an artifact rather than re-scanning.

**Commit:** `feat: licence hygiene and dependency licence policy`

### 4.4 — Dependency Reality Check

> **✅ COMPLETE 2026-08-30.** 63 tests. Full fleet scan of the fixture: 56 findings
> across 9 Scanners and Checks, all green. `offline` runs 4 of them and sends nothing.

Last, because it carries all of this phase's new infrastructure.

16. A dependency that does not exist on its registry is a critical **Finding**.
    *(F3.2 — the headline slopsquat behaviour, and the one no advisory database can
    catch, because the package is new rather than known-bad.)*
17. A recently published, barely adopted dependency is flagged as a possible
    **Slopsquat**. *(F3.3)*
18. A dependency one character from a far more popular package is flagged. *(F3.4)*
19. With no network, the **Check** reports *skipped* — and its packages are **not**
    reported clean. *(F3.5 — the honesty behaviour.)*

- [x] **4.4.20** **Popularity dataset.** Cycle 18 needs to know what is popular. Decide  
  **STATUS 2026-08-30:** ✅ 3000 top PyPI names, 49KB, from hugovk/top-pypi-packages. **CC0-1.0**, so redistribution is unencumbered. Refresh quarterly.
  the source, size, refresh cadence and licence of a bundled top-N package list per
  ecosystem. Unplanned work that will otherwise surface mid-cycle.
- [x] **4.4.21** **Disclose the registry lookups.** Querying PyPI or npm reveals your  
  **STATUS 2026-08-30:** ✅ `run.json` carries a `network` block naming exactly what left the machine; README states it plainly; `--offline` disables it. `offline` never had it.
  dependency list to those registries. It is metadata, not source — but it is exactly
  what we criticise Snyk for, so it must be stated plainly in the README and recorded
  in `run.json`, with an opt-out flag. `offline` stays fully offline. Being quietly loose
  here would cost more credibility than the feature is worth.
- [x] **4.4.22** Registry client with caching and rate-limit handling; a registry  
  **STATUS 2026-08-30:** ✅ Registry client with 404-vs-unreachable distinction. Unreachable raises, so the run records the Check as failed and the scan as incomplete — never clean (F3.5).
  refusing us must degrade per cycle 19, never silently.

**Commit:** `feat: dependency reality check for slopsquat detection`

**Exit:** every planted problem in the fixture **Workspace** is caught by the intended
**Check**; the offline path degrades honestly; and no injection payload from a scanned
repository appears as live directive text in any artifact we write.

---

## Phase 5 — Enrichment and ranking

**Goal:** the top of the list is genuinely the most urgent thing.

> **Reordered and sub-phased 2026-08-30 after reviewing Phases 1–4.** The original
> plan assumed a **Finding** model that does not exist. `design.md` §3 specifies
> `severity`, `rank`, `exploit{}` and `dependency{}`; **none of them are implemented**,
> and the adapters currently parse Trivy's `Severity`, `FixedVersion`, `CVSS` and
> `PkgIdentifier` and throw them away. Cycle 4's inversion had nothing to invert.

### 5.0 — Extend the Finding model

> **✅ COMPLETE 2026-08-30.** 68 tests.

- [x] **5.0.1** Add `severity`, `rank`, `exploit` and `dependency` to `Finding`, per  
  **STATUS 2026-08-30:** ✅ `Exploit` and `Dependency` dataclasses, plus `severity` and `rank` on `Finding`. All optional, so Checks needed no change.
  `design.md` §3. Keep them optional so existing Checks need no change.
- [x] **5.0.2** Populate them in each Scanner adapter. Trivy already hands us  
  **STATUS 2026-08-30:** ✅ All six adapters populate them. Trivy's `Severity`/`FixedVersion`/`PURL` were previously parsed and discarded; gitleaks findings are `critical` by definition — a live credential is not a matter of degree.
  `Severity`, `FixedVersion`, `PURL`, `CVSS` and `PublishedDate`; OSV and Checkov
  carry equivalents. This re-touches all six adapters, which is why it comes first.
- [x] **5.0.3** **Fingerprints must not change.** Enrichment is additive metadata, and  
  **STATUS 2026-08-30:** ✅ **Fingerprint digest identical before and after** (`dc6c522534a90b3d`, 46 fingerprints). Now a permanent regression test with pinned literal values, not a one-off check.
  a fingerprint shift would silently invalidate every **Suppression** in every project
  using valvur (ADR-0003). Assert the fixture's fingerprints are byte-identical
  before and after this sub-phase.
- [x] **5.0.4** All 63 existing tests pass unchanged.  
  **STATUS 2026-08-30:** ✅ All 63 existing tests passed unchanged; 68 now.

**Commit:** `feat: carry severity and dependency metadata on findings`

### 5.1 — KEV

> **✅ COMPLETE 2026-08-30.**

1. A **Finding** with a CVE carries its KEV status. *(F6.1, F6.2)*
2. A KEV entry used in ransomware campaigns is marked as such. *(352 of 1,685 current
   entries carry this flag — it is the strongest call to action we can print.)*
3. A CVE absent from KEV is marked as such, not left unknown. *(Absence of evidence is
   reportable; silence is not.)*

- [x] **5.1.4** **Bundle a KEV snapshot as a floor, refresh into the host cache.**  
  **STATUS 2026-08-30:** ✅ 74KB trimmed snapshot bundled as an offline floor; `valvur update` refreshes into the host cache and the fresher copy wins.
  F6.2 says bundle it, and at 1.6MB size is not the concern — freshness is. A CVE
  added to KEV yesterday would not be flagged by a three-month-old image, which is
  precisely the reasoning that moved the Trivy DB out in ADR-0012. Bundle so `offline`
  works offline immediately; refresh on `valvur update`; prefer the cached copy when
  it is newer.

**Commit:** `feat: KEV enrichment with ransomware flag`

### 5.2 — EPSS and disclosure

> **✅ COMPLETE 2026-08-30.**

4. A **Finding** with a CVE carries its EPSS score where the network permits. *(F6.3)*
5. EPSS is fetched in one batched request for the CVEs actually found, not one call
   per finding. *(F6.3)*
6. With no network, ranking uses KEV alone and **Provenance** records the degradation.
   *(F6.4)*

- [x] **5.2.7** **Disclose the EPSS lookup (F6.10).** Sending our CVE list to FIRST is  
  **STATUS 2026-08-30:** ✅ `run.json` and README now name the CVE disclosure alongside the package-name one; `--offline` covers both.
  a map of the project's *unpatched vulnerabilities* — a more sensitive disclosure
  than the dependency names of 4.4.21. Extend the `network` block in `run.json` and
  the README, and honour `--offline`. Having made a point of the lesser leak, silence
  about the greater one would be worse than never having claimed it.

**Commit:** `feat: batched EPSS enrichment with explicit disclosure`

### 5.3 — Ranking

> **✅ COMPLETE 2026-08-30.**

7. **The inversion:** a CVSS 6.5 **Finding** in KEV ranks above a CVSS 9.8 at 0.04%
   EPSS. *(F6.5 — the behaviour the whole feature exists for.)*
8. Ranking actually reorders the written output. *(`SUMMARY.md` currently iterates in
   adapter order, so a correct `rank` field that nothing sorts by would be a silent
   no-op.)*
9. **Enrichment** older than 30 days produces a staleness warning. *(F6.7)*

- [x] **5.3.10** **The inversion needs test data that does not exist.** None of the  
  **STATUS 2026-08-30:** ✅ Both halves done. Synthetic pairs prove the ranking function; **Pillow 10.0.0 / CVE-2023-4863** proves the wiring against real scanner output — one of very few PyPI-reachable CVEs in KEV.
  fixture's 15 CVEs appear in KEV — verified against the live catalogue. Do both:
  a synthetic pair for the unit test, which is stable and proves the ranking function;
  and one real KEV-listed dependency for an e2e, which proves the wiring. Neither
  alone is sufficient.
- [x] **5.3.11** Give low-value classes a floor so they cannot crowd the top. A scan  
  **STATUS 2026-08-30:** ✅ Class urgency now competes with exploit urgency. Real output showed hallucinated packages sinking below any CVE with a non-zero EPSS, because they have no EPSS at all.
  of our own toy fixture returns 56 findings, of which 6 are
  `licence.dependency-unknown` from our own SBOM, while two hallucinated packages and
  an injection payload sit below them in arbitrary order. **Phase 6's 200-line cap is
  only safe after this** — truncating an unranked list discards at random.

**Commit:** `feat: exploit-aware ranking`

### 5.4 — Dependency path and scope

> **✅ COMPLETE 2026-08-30.**

10. A transitive vulnerability reports its **Dependency Path** and the direct package
    to change. *(F6.9)*
11. A **Finding** in a development-only dependency ranks below the same **Finding** in
    a production dependency. *(F6.6)*

- [x] **5.4.12** **Verify Trivy gives us the parent chain before committing to cycle  
  **STATUS 2026-08-30:** ✅ **Verified, and the answer was no.** Trivy exposes no `PkgID`/`Relationship`/`PkgPath` on vulnerabilities, and Syft emits no `dependencies` section. The graph is in `Packages[].DependsOn` and exists **only for lockfiles** — `requirements.txt` is flat and carries no transitive information at all. Implemented where the data exists; reporting a path for a flat manifest would be invention.
  10.** `fs` mode may not expose it without `--list-all-pkgs`, in which case the path
  comes from the Syft SBOM instead. Confirm first; do not assume.
- [x] **5.4.13** Determine dev-vs-production scope per ecosystem — `devDependencies`,  
  **STATUS 2026-08-30:** ✅ Scope from path segments and filename parts, demoted a full tier in ranking.
  `[dependency-groups]`, and filename convention for `requirements-dev.txt`. The
  fixture already carries the test material; no adapter marks scope yet.

**Commit:** `feat: dependency paths and development-scope demotion`

**Exit:** cycle 7 passes and the ranking demonstrably reorders real output; nothing
that matters is buried beneath noise.

---

## Phase 6 — Results contract

**Goal:** every artifact, each serving one consumer, all consistent.

> **Reordered and sub-phased 2026-08-30 after reviewing Phases 1–5.** Measured against
> the contract, five of nine artifacts do not exist, and `SUMMARY.md` is already at
> **185 lines for 84 findings on a toy fixture** against a 200-line cap. The original
> cycle 2 reads as a truncation task; it is a **reformat**. And two cycles understate
> real work — see 6.4 and 6.5.

### 6.0 — The consistency invariant, first

> **✅ COMPLETE 2026-08-30.** 84 tests. `assert_artifacts_agree()` is a reusable
> assertion, and a second test deliberately corrupts the SARIF to prove the invariant
> can actually fail — a guarantee that cannot fail is not a guarantee.
>
> Building it first immediately earned its place: it exposed that the `offline` Profile
> was missing the **ai-artifact** Check entirely, because an earlier edit matched a
> trailing comma that `QUICK` did not have. The differentiator was silently absent
> from the fast path.

1. Every **Finding** in `findings.json` appears in `results.sarif` and is counted in
   `SUMMARY.md`. *(F7.13)*

> Built **first** deliberately. This is the guarantee that keeps five artifacts
> honest, and each one added afterwards is checked as it lands rather than five being
> reconciled at the end.

**Commit:** `test: cross-artifact consistency invariant`

### 6.1 — findings.json and SARIF

> **✅ COMPLETE 2026-08-30.** 88 tests.
> SARIF is validated against the **real OASIS 2.1.0 schema** (109KB, bundled), not
> merely declared. Confirmed non-vacuous: the schema rejects a missing
> `driver.name` and the wrong version, so the test would actually fail if our output
> drifted.

2. `findings.json` carries a schema version. *(F7.10)*
3. `findings.json` carries neutralised evidence, not raw **Workspace** content.
   *(F3.13 — an agent queries this per finding, so it is an injection surface exactly
   as `SUMMARY.md` is.)*
4. `results.sarif` validates against the SARIF 2.1.0 schema. *(F7.9)*
5. `results.sarif` carries **Fingerprints** in `partialFingerprints`, so an IDE's
   suppression survives an edit for the same reason ours does. *(F7.9)*

**Commit:** `feat: findings.json and SARIF output`

### 6.2 — SUMMARY.md within its budget

> **✅ COMPLETE 2026-08-30.** 92 tests. 185 lines → 50.

6. `SUMMARY.md` opens with the machine-facing header. *(F7.6)*
7. Failures and skips appear before any **Finding**. *(F7.7)*
8. `SUMMARY.md` stays within 200 lines given 10,000 **Findings**. *(F7.5)*
9. When findings are truncated, the count omitted is stated. *(Silent truncation
   reads as "that is everything", which is a lie of omission.)*

- [x] **6.2.10** **Reformat to the budget in [design.md](./design.md) §6**: header ~25,  
  **STATUS 2026-08-30:** ✅ **185 lines → 50**, for 57 findings. One line per finding; evidence moved to `findings.json`. Verified against 10,000 synthetic findings.
  failures ~15, counts by class and status ~20, **top 15 Findings ~100**, pointers
  ~10. We currently print every finding at ~2.2 lines each, which tops out near 85.
  This is only safe because Phase 5 landed — truncating an unranked list discards at
  random.

**Commit:** `feat: bounded summary with explicit truncation`

### 6.3 — REMEDIATION.md

> **✅ COMPLETE 2026-08-30.** 97 tests.

10. `REMEDIATION.md` orders **Remediation Items** by rank. *(F7.14)*
11. **Findings resolved by a single change appear as one item.** *(F7.14 — our own
    fixture has four CVEs in `loader-utils@1.4.0`, all fixed by "change webpack".
    Emitting four items would be exactly the noise Phase 5 removed.)*
12. Each item names the change to make, not merely the problem.

- [x] **6.3.13** Define the grouping key per **Finding Class**: dependency findings  
  **STATUS 2026-08-30:** ✅ Dependency findings group by the **Dependency Path root**, secrets by file, agent artifacts by file, licence together. **13 actions resolve 57 findings** on the fixture, summing exactly — grouping is a partition, pinned by test.
  group by the package the developer can actually change (the **Dependency Path**
  root, from 5.4); secrets group by file; IaC by resource. **This grouping is most of
  the work in this sub-phase**, and the original plan did not acknowledge that a
  Remediation Item is an *action* rather than a Finding.

**Commit:** `feat: remediation proposal grouped by action`

### 6.4 — raw/ and its own redaction

> **✅ COMPLETE 2026-08-30.** 101 tests. Phase 6 complete.

13. `raw/` preserves each **Scanner**'s unmodified output. *(F2.8, P2 — the artifact a
    reviewer uses to verify we did not mangle a Scanner's findings.)*
14. **No secret value appears in `raw/`.** *(F5.7)*
15. `raw/` prunes to the most recent N **Scan Runs**. *(N3.3)*

- [x] **6.4.16** **`raw/` needs a redaction pass of its own.** Our **Redaction** happens  
  **STATUS 2026-08-30:** ✅ `rawoutput.scrub()` uses the secret values Gitleaks itself reports, longest-first so a Match containing a Secret leaves no fragment. Proven non-vacuous by a test that confirms the scrubber had something to remove.
  at the **Finding** boundary; `raw/` is *pre-model* Scanner output and bypasses it
  entirely, and Gitleaks emits live credential values in its JSON. Tractable —
  Gitleaks tells us exactly which strings are secrets — but it is a different
  mechanism from the one we have, and the original cycle read as though it were
  covered.

**Commit:** `feat: raw scanner output with pre-model redaction`

**Exit:** a full **Results Folder** is produced, every artifact test passes, and no
**Workspace** content can act as an instruction in any of them.

> **`report.html` was cut before implementation** — see
> [ADR-0014](../../../docs/adr/0014-no-html-report.md). Phase 6 is five sub-phases,
> not six.

---

## Phase 7 — Suppressions

**Goal:** accepted risks are recorded, shared and reviewed rather than forgotten.

> **Reordered and sub-phased 2026-08-30 after reviewing Phase 6.** The original five
> cycles covered the lifecycle but omitted every integration point, and F8.2 as
> written contradicted the reason we chose per-class identity at all.

### 7.0 — Parse and match

> **✅ COMPLETE 2026-08-30.** 107 tests.

- [x] **7.0.1** **Bump `requires-python` to `>=3.11`.** `tomllib` is 3.11+, and the  
  **STATUS 2026-08-30:** ✅ `requires-python = ">=3.11"`. We claimed 3.10 where `tomllib` does not exist and suppression parsing would simply fail — invisible, since our venv is 3.12.
  shim is stdlib-only by design (F10.6) so adding `tomli` would cost us that
  property. Today we *claim* 3.10 and suppression parsing would simply fail there —
  invisible to us, since our own venv is 3.12.
- [x] **7.0.2** Parse `.security-scan.toml` from the **Workspace** root. *(F8.1)*  
  **STATUS 2026-08-30:** ✅ `suppressions.load()` parses `.security-scan.toml`; a missing file is not an error.

1. A **Suppression** carries a **Fingerprint**, an expiry date, a reason, **and
   human-readable context**. *(F8.2, sharpened.)*
2. A **Suppression** matching a **Finding** marks it suppressed rather than removing
   it. *(F8.6)*

> **Why context is mandatory.** A pull request containing only
> `fingerprint = "4e4dff39…"` tells a reviewer nothing about what is being accepted.
> That is the opposite of the argument for per-class identity: suppressing
> `aws_s3_bucket.logs / CKV_AWS_18` is a decision a human can read. The hash is the
> matching key; it is never the whole entry.

**Commit:** `feat: suppression parsing and matching`

### 7.1 — Lifecycle

> **✅ COMPLETE 2026-08-30.**

3. A **Suppression** without an expiry date is rejected and raises a **Finding**.
   *(F8.3 — an unexpiring suppression is how a real finding gets buried for years.)*
4. An expired **Suppression** reports its **Finding** normally, **and is itself
   flagged**. *(F8.4 — a lapsed risk acceptance is a decision someone must retake,
   which is the entire purpose of mandatory expiry.)*
5. A **Suppression** matching nothing is reported as stale. *(F8.5)*
6. valvur never writes to `.security-scan.toml`. *(F8.7)*

- [x] **7.1.7** Pin the expiry semantics: UTC, and the expiry date **inclusive** — a  
  **STATUS 2026-08-30:** ✅ UTC, inclusive, pinned by test.
  suppression expiring today is still valid today. Ambiguity here means two machines
  disagree about whether a build passes.

**Commit:** `feat: suppression lifecycle with mandatory expiry`

### 7.2 — Integration

> **✅ COMPLETE 2026-08-30.** The F7.13 invariant caught the counting change as it happened — see the commit.

> Three interactions the original plan did not mention. Each one is a way for
> suppression to quietly break something Phases 5 and 6 established.

7. Suppressed **Findings** are excluded from ranking positions. *(F8.9 — otherwise
   they crowd out live ones, the exact noise problem F6.5 solved.)*
8. `SUMMARY.md` counts active and suppressed **Findings** separately. *(F8.9 —
   `Findings: 84` when 30 are suppressed misstates the result.)*
9. The F7.13 cross-artifact invariant still holds with suppressions present.
   *(Suppressed Findings stay in `findings.json` — F8.6 says distinct section, not
   omitted — so they must still appear in the SARIF.)*
10. `results.sarif` uses **SARIF's own** `result.suppressions` with
    `kind: "external"`, `status: "accepted"` and the justification. *(An invented
    property would make IDEs show suppressed findings as live — worse than emitting
    no SARIF, because the tool would look wrong rather than misconfigured.)*
11. Suppressing a **Finding** does not mark it `fixed`, and un-suppressing does not
    make it `new`. *(Suppression is a **policy** layer, not an identity layer;
    `state.json` tracks presence regardless.)*

**Commit:** `feat: suppression integration with ranking, counts and SARIF`

### 7.3 — `valvur suppress`

> **✅ COMPLETE 2026-08-30.** 120 tests. Phase 7 complete.

12. `valvur suppress <fingerprint>` prints a ready-to-paste **Suppression** block with
    its context filled in, and writes nothing. *(F8.8, F8.7)*

> Without this, writing a suppression means hand-copying a 32-character hash out of
> `findings.json`, which nobody will do. **Printing is not writing** — F8.7 stands,
> and the feature becomes usable rather than theoretical.

**Commit:** `feat: valvur suppress prints a paste-ready block`

**Exit:** the suppression lifecycle is fully covered, nothing suppressed can crowd out
something live, and a reviewer can tell from the diff alone what is being accepted.

---

## Phase 8 — Runtime portability and hardening

> **✅ COMPLETE 2026-08-30.** 135 tests, 14 e2e across Docker and rootless Podman.
>
> **The dual-runtime requirement found three distinct silent failures**, each of which
> would have reported a vulnerable repository as clean, and none of which any Scanner
> could detect. All three appeared only on **Podman under Linux** — local Docker and
> local Podman on macOS were both green throughout.
>
> 1. `--user` on rootless Podman made the bind-mounted workspace unreadable. Every
>    Scanner read an empty tree and exited 0.
> 2. The scratch mount was then unwritable, so Scanners produced no report — and all
>    three read paths treated a missing report as an empty one.
> 3. Both flags were needed: `--userns=keep-id` maps the host user in, but the image's
>    own `USER 10001` still applied and mapped to a subuid.
>
> Our fail-loudly rules all assumed a Scanner *errors*. These failures succeed
> perfectly at scanning nothing, which no exit code reveals. The runner now verifies
> the workspace is readable before scanning, and treats a missing report as a failure.

**Goal:** identical behaviour on Docker and Podman, with the isolation guarantees
proven rather than intended.

> **Reordered and sub-phased 2026-08-30 after reviewing Phase 7.** The review found
> **F10.4 was unsatisfiable as written** and had been since we chose a base image, and
> that our runtime detection misses a real, common Podman installation.

### 8.0 — Correct and verify the licence claim

> **✅ COMPLETE 2026-08-30.** 125 tests. **961 base → 2003 ours = 1042 added, zero GPL among them.**

1. The image adds no GPL or AGPL component **as a Scanner, Check or installed
   library**. *(F10.4, corrected.)*
2. The verification uses **syft against our own image**, not hand-parsed package
   metadata.

> **Why the correction.** Measured on our own image: **12 GPL components** —
> `busybox`, `apk-tools`, `alpine-baselayout`, `musl-utils`, `xz-libs`, `gdbm`,
> `readline` and more — every one from the base OS. No Linux container can avoid
> them. A requirement that can never pass either blocks every release or is quietly
> ignored, and the second is worse: it teaches people to skip the check.
>
> **And why syft.** A hand-rolled check over Python package metadata reported *96
> packages, all clean*. Syft found **2,227 components and the 12 above**. The Python
> layer was never where the risk was, and we ship an SBOM generator — using it on
> ourselves is the dogfooding the release gate is meant to prove.

- [x] **8.0.3** Publish the image SBOM per release (F10.3), disclosing base-OS  
  **STATUS 2026-08-30:** ✅ The check itself produces the SBOM; publishing it per release is task 12.2, already planned.
  licences rather than pretending they are absent. For a tool that ships licence
  analysis, disclosure is the only defensible answer.

**Commit:** `fix: correct the licence claim and verify it with syft`

### 8.1 — File ownership across runtimes

> **✅ COMPLETE 2026-08-30.** Ownership proven on Docker **and rootless Podman**; the dual-runtime claim now rests on evidence.

3. **Results Folder** files are owned by the invoking user on Docker. *(F1.4)*
4. **Results Folder** files are owned by the invoking user on rootless Podman.
   *(F1.4 — the reason ADR-0001 exists.)*

> **Podman is installed** (6.0.2, machine running), so the deferral from task 0.2 is
> discharged and the dual-runtime claim can stand on evidence.

**Commit:** `test: file ownership on docker and rootless podman`

### 8.2 — Isolation and runtime detection

> **✅ COMPLETE 2026-08-30.** 127 tests.

5. The container cannot write to `/workspace`. *(F1.1)*
6. A **Workspace** path containing spaces scans correctly.
7. **A symlink pointing outside the Workspace resolves to nothing inside the
   container.** *(Not merely "symlinks work": the read-only mount should make an
   escape structurally impossible, and that is worth asserting rather than assuming.)*
8. With no container runtime present, valvur refuses with actionable remediation
   text. *(F1.5)*

- [x] **8.2.9** **Runtime detection must find Podman Desktop's install.** `shutil.which`  
  **STATUS 2026-08-30:** ✅ Detection now probes known install locations as well as `PATH`, and found the real Podman 6.0.2 at `/opt/podman/bin`.
  missed a working Podman 6.0.2 at `/opt/podman/bin/podman`, because Podman Desktop
  does not add itself to `PATH`. A user with a perfectly good runtime would be told
  they have none — the worst kind of first-run failure, since the advice would be to
  install what they already have. Probe known locations as well as `PATH`.

**Commit:** `feat: robust runtime detection and proven isolation`

### 8.3 — Version compatibility

> **✅ COMPLETE 2026-08-30.** 134 tests. Phase 8 complete.

10. A shim/image major version mismatch refuses to run and states both versions.
    *(F1.9)*

- [x] **8.3.11** **Design the version relationship first — none exists.** `_VERSION`  
  **STATUS 2026-08-30:** ✅ Designed: the image stamps `org.opencontainers.image.version` from `pyproject` at build time; the shim reads it and compares. Below 1.0 a **minor** difference breaks compatibility, because semver permits 0.x minors to break. An image with no label predates the check and is accepted.
  strings sit in two files, unconnected, and nothing compares them. The image should
  declare its version as an OCI label, the shim should read it, and they should
  compare on major. ADR-0001 accepted two artifacts on the condition this check
  existed; it does not yet.

**Commit:** `feat: shim and image version compatibility check`

### 8.4 — Air-gapped operation

> **✅ COMPLETE 2026-08-30.** 134 tests. Phase 8 complete.

12. Vulnerability databases load from a user-specified OCI registry. *(F10.5)*

- [x] **8.4.13** Expose Trivy's `--db-repository` through configuration, and document  
  **STATUS 2026-08-30:** ✅ `VALVUR_DB_REPOSITORY` passes through to Trivy's `--db-repository` for both scan and update, documented in the README.
  the mirroring workflow. This is the hardest enterprise requirement and ADR-0012
  already made it reachable — the DB lives outside the image, so mirroring needs no
  special build.

**Exit:** the full suite passes on Docker **and** Podman; the licence claim is one we
can actually defend; and a runtime that is installed is a runtime we find.

---

## Phase 9 — MCP surface

**Goal:** an agent can scan, browse and understand **Findings** — and cannot change
anything.

> **Reordered and sub-phased 2026-08-30 after reviewing Phase 8.** The original six
> cycles described the tools but not the two decisions that shape them: what the MCP
> SDK costs us, and what happens when a scan outlasts a client's timeout.
>
> **Corrected the same day.** My first rewrite made MCP an opt-in extra, reasoning
> that the CLI was the wider audience. That had the priority backwards: valvur is
> agent-native, and adding it to Kiro or Claude Code *is* the product. MCP is the
> primary interface, and ADR-0015 keeps it dependency-free by implementing stdio
> directly.

### 9.0 — Hand-rolled stdio transport

> **✅ COMPLETE 2026-08-30.** 149 tests.

**MCP is the primary interface.** `pip install valvur` gives a working server; there
is no extra to opt into. The CLI is the second way in.

- [x] **9.0.1** Implement MCP stdio directly — newline-delimited JSON-RPC 2.0 on  
  **STATUS 2026-08-30:** ✅ `mcp/protocol.py` — newline-delimited JSON-RPC 2.0 over stdio, stdlib only. `dependencies = []` still holds, asserted by test.
  stdin/stdout — keeping **zero runtime dependencies** (F10.6, ADR-0015). The
  official SDK pulls 22 packages including `starlette`, `uvicorn`, `pyjwt` and
  `cryptography`: an HTTP server, an OAuth stack and a crypto library, all to support
  transports Kiro and Claude Code do not use. Installing a web server into a security
  tool enlarges what must be audited and patched whether or not a port is ever bound —
  and it is precisely the dependency footprint our own Dependency Reality Check
  exists to warn people about.
- [x] **9.0.2** Implement `initialize`, `tools/list` and `tools/call`. That is the  
  **STATUS 2026-08-30:** ✅ `initialize`, `tools/list`, `tools/call`, plus `ping` and the `notifications/initialized` no-op.
  whole protocol for a tools-only server.
- [x] **9.0.3** **Pin the protocol version we declare**, and record it. We own  
  **STATUS 2026-08-30:** ✅ Declares `2025-06-18`, negotiates down to `2025-03-26` and `2024-11-05`. An unknown version gets ours to decide on rather than a refusal.
  compatibility now: if the handshake changes we fix it rather than upgrading a
  package. Phase 9's exit criterion — a real client completing scan → list → explain —
  is what makes that risk manageable rather than theoretical.
- [x] **9.0.4** A malformed request produces a JSON-RPC error, never a traceback on  
  **STATUS 2026-08-30:** ✅ Malformed JSON → `-32700`; unknown method → `-32601`; an unhandled exception → `-32603` with the diagnostic on **stderr**. A crashing *tool* is a tool error, not a protocol fault, so the agent sees the real problem.
  stdout. Anything written to stdout that is not a response corrupts the stream.

**Commit:** `feat: MCP stdio transport with zero dependencies`

### 9.1 — The read-only tool surface

> **✅ COMPLETE 2026-08-30.** 162 tests. Four tools: `scan`, `list_findings`,
> `explain_finding`, `scan_status` — and a test pins that set exactly, so adding a
> fifth is a deliberate act visible in a diff.
>
> Preparing cycle 5 (F9.9) exposed that **SAST findings carried raw workspace lines
> as evidence**: neutralisation lived in the AI-artifact check rather than at the
> model boundary. Now fixed in `Finding.__post_init__`, one place, applied to
> everything — with fencing selective, so our own advice is not buried in warnings,
> and unconditional for content whose *source* is an agent instruction file.

1. An MCP client runs a **Scan Run** and receives a summary. *(F9.1)*
2. `list_findings` returns **Findings** in rank order, filterable by **Status**.
3. `list_findings` is **bounded by default and states what it omitted**. *(F9.10 —
   several thousand Findings in an agent's context is the problem F7.5 solved for
   `SUMMARY.md`, arriving by another door.)*
4. `explain_finding` returns evidence, **Exploit Signals**, **Dependency Path** and
   the originating source. *(F9.8)*
5. **MCP responses carry neutralised evidence.** *(F9.9 — an MCP response reaches an
   agent's context with no file in between. It is the most direct injection path we
   have, and the only one the agent cannot decline to read.)*
6. No exposed tool modifies the **Workspace**. *(F9.2)*
7. **No tool named `scan_and_fix`, `apply`, `write` or `remediate` exists in the
   registry.** *(ADR-0009 is a safety property, so a contributor adding one should
   fail a test rather than merely fail review.)*
8. Editing a file triggers no **Scan Run**. *(F9.4)*

**Commit:** `feat: read-only MCP tool surface`

### 9.2 — Long scans

> **✅ COMPLETE 2026-08-30.** 168 tests. Verified end to end against a real container: scan → poll → DONE in 5s → list.

9. A **Scan Run** started over MCP returns promptly, and `scan_status` reports its
   progress and result.

> **Measured: 20 seconds for the `full` Profile on our toy fixture.** A real
> project is minutes, and many MCP clients time out at 30–60 seconds.
> [design.md](./design.md) §8 already listed `scan_status` alongside `scan`, implying
> this pattern — but the original cycles did not mention it, so the implementation
> would have defaulted to synchronous and discovered the problem in Phase 10's
> usability gate.

**Commit:** `feat: asynchronous scan with status polling`

### 9.3 — CLI parity by construction

> **✅ COMPLETE 2026-08-30.** 174 tests. Phase 9 complete.

10. Every MCP tool has a CLI equivalent producing the same result. *(F9.3)*

- [x] **9.3.11** Make parity **structural, not compared**: both surfaces call the same  
  **STATUS 2026-08-30:** ✅ Operations lifted into `valvur/operations.py`; both surfaces call them. A test asserts every MCP tool's handler *is* a shared operation, so a second implementation fails the build.
  function, so they cannot drift. Asserting equality of formatted output would be
  brittle and would keep passing while the semantics diverged.

**Commit:** `feat: CLI and MCP parity by construction`

**Exit:** a real MCP client completes scan → list → explain against the fixture repo;
no tool can change anything; and nothing an agent receives can act as an instruction.

---

## Phase 10 — First-run experience

**Goal:** usability, treated as a feature with its own phase rather than as polish.

> **Reordered 2026-08-31 after reviewing Phase 9.** Two problems. The phase could not
> run at all — nothing is published, so the usability gate had nothing for a
> participant to install. And its tasks were written when the **CLI** was primary;
> since ADR-0015 the first run is an MCP configuration flow with entirely different
> failure modes.

### 10.0 — Pre-release publish

> **✅ COMPLETE 2026-08-31.** The gate now has something real to install.
>
> **Caught before upload:** the sdist would have shipped **14 occurrences** of the
> planted AWS credentials and the injection payload to PyPI — the test fixtures are
> deliberately full of them. Tests are now excluded from the sdist. Publishing fake
> credentials from a tool that detects credentials would have been found by someone
> else's scanner, not ours.

The gate needs something real to install. A source checkout tests a path no user will
take, and participants cannot be re-used.

- [x] **10.0.1** **The name decision comes due here, not at 12.1.** Publishing an rc to  
  **STATUS 2026-08-31:** ✅ **`valvur` kept.** Confirmed 2026-08-31; the name is now claimed on PyPI and cannot be released.
  PyPI *claims the name*. `valvur` was chosen as provisional on the understanding that
  renaming stayed free until first publish — this is first publish. Decide now or
  rename now; there is no third option.
- [x] **10.0.2** Publish `0.1.0rc1` to PyPI and the image to GHCR. This is most of  
  **STATUS 2026-08-31:** ✅ `valvur 0.1.0rc1` on PyPI, `ghcr.io/maverickhq/valvur:0.1.0rc1` and `:latest` on GHCR. Verified as a stranger would: fresh venv, `pip install valvur`, scanned a repo, 57 findings, zero runtime dependencies.
  tasks 12.2 and 12.5 brought forward, and doing it early de-risks the real release
  rather than duplicating it.
- [x] **10.0.3** **Measure the image pull honestly.** The `offline` scan itself is  
  **STATUS 2026-08-31:** ✅ **Measured: 302MB compressed** (not the 674MB uncompressed figure I had been quoting). ~24s at 100 Mbit, 48s at 50, 97s at 25. With a 5.6s scan, P1's 60 seconds holds at 50 Mbit and above and fails below it. README now states the figures rather than the promise — a claim someone can check beats one they must accept.
  **5.6s**, comfortably inside P1's 60 seconds — but the image is **674MB**, roughly
  110 seconds on a 50 Mbit connection. P1 is at risk entirely from the download.
  Measure it, then either state the figure plainly in the README or reconsider a
  smaller image for `offline`. Do not let the claim stand unmeasured.

**Commit:** `chore: publish 0.1.0rc1 for the usability gate`

### 10.1 — The usability gate

- [ ] **10.1.1** **Run it before any other task in this phase.** Protocol:
  [docs/usability-gate.md](../../../docs/usability-gate.md). A developer who has never
  seen valvur, repository URL only, no verbal help, scanning **their own** project.
  **The findings become the rest of this phase's task list**, so everything below is
  provisional until it has run. Moved here from Phase 1 task 1.12.
- [ ] **10.1.2** Have them install it **the way the README says** — the MCP path
  first, since that is now primary — rather than however we would do it.

**Commit:** `docs: record usability gate findings`

### 10.2 — The MCP first run *(the primary path)*

1. Pasting the README's config block into Kiro produces a working server.
2. Pasting it into Claude Code produces a working server. *(Their config shapes
   differ; one working and the other not would be found by users rather than by us.)*
3. A malformed config, or `valvur-mcp` not on `PATH`, produces a diagnosable failure
   rather than silence. *(Agents commonly swallow a server's stderr, so a server that
   dies at startup can look like a server that does nothing.)*
4. The first tool call states plainly that the image is being pulled and how large it
   is, rather than appearing to hang.

- [ ] **10.2.5** Verify the copy-pasteable `CLAUDE.md` / `AGENTS.md` snippet against a
  real agent in a real repository. *(P6)*

**Commit:** `feat: MCP first-run experience`

### 10.3 — The CLI first run

5. `uv tool install valvur` and `pipx install valvur` work on a clean machine with no
   **Scanners** present. *(F10.6)*
6. `valvur scan` with no arguments does the right thing in any directory. *(P1)*
7. The `offline` **Profile** completes within P1's budget on a ≤50k-line repository,
   **including** the image pull on a first run, or the README states the real figure.
   *(P1, N1.1, and see 10.0.3.)*

**Commit:** `feat: CLI first-run experience`

### 10.3b — False positives, found by scanning a real project

> **✅ COMPLETE 2026-08-31.** 182 tests. Re-scanned the same project: **20 findings →
> 14**, six vendored excluded and reported, `.env` secrets down from critical to
> medium with the reason in the title, and the licence-unknown findings now ranked
> 11–14 instead of near the top.

> **Added 2026-08-31.** A scan of a real 260k-line project (62s, standard profile, all
> nine scanners green) returned 20 findings. Two genuine secrets, seven real IaC
> misconfigurations — and three defects our synthetic fixture could not have revealed,
> because it has no vendored code and no `.env`.

13. **Build and vendor directories are excluded by default.** `.aws-sam/build/`,
    `node_modules/`, `site-packages/`, `dist/`, `.venv/`. Six of the twenty findings —
    **30%** — came from numpy's own test fixtures inside a build artifact directory.
    That is not the user's code, they cannot fix it, and it is precisely the noise
    Phase 5 exists to prevent.
14. **A gitignored `.env` is not a critical finding.** Every developer has one, and
    keeping secrets out of git is the *correct* practice we would be penalising. A
    secret in a **tracked** file is critical; a secret in an ignored one is a note.
    Ranking must consult git, not just the filesystem.
15. `licence.dependency-unknown` still crowds real findings: five of the fourteen
    findings in the user's own code. The class floor is not low enough.

**Commit:** `fix: exclude vendored code and rank gitignored secrets honestly`

### 10.4 — Error messages as a usability surface

8. **Docker installed but not running** produces a message naming the exact next
   command. *(The commonest first-run failure on macOS, and currently the worst
   handled: detection finds the binary, the run fails, and the user gets a generic
   "every scanner failed" with Docker's raw stderr attached.)*
9. An image pull failure is diagnosed as such.
10. A **Workspace** with no manifests at all says so, rather than reporting clean.
11. A corrupt `.security-scan.toml` names the line.

> Five failure modes already produce good messages — `NoContainerRuntime`,
> `IncompatibleImage`, `WorkspaceUnreadable`, `ScannerFailed`, `RegistryUnreachable`.
> These are the gaps.

- [ ] **10.4.12** Decide what a **human** sees first in `SUMMARY.md`. It currently
  opens with twelve lines addressed to an agent, so a developer reads instructions
  meant for something else before reaching their findings. Correct for the MCP path;
  worth deciding deliberately rather than inheriting.

**Commit:** `feat: actionable errors for every first-run failure`

### 10.5 — The second gate

12. A different developer, README only, clean machine, reaches a useful result in
    under five minutes without asking a question.

**Exit:** an unfamiliar user reaches a useful result without asking a question —
by the MCP path first, and by the CLI second.

---

## Phase 11 — Constraint verification

**Goal:** convert the product's central claims from assertions into tests CI runs on
every commit.

> **Reordered 2026-08-31 after auditing two real GitHub repositories.** Phase 11 was
> written on the assumption that the risk was *constraint violation* — valvur
> reaching the network, writing where it should not, running too long. That audit
> found roughly twenty defects and **almost none were constraint violations.** They
> were silent coverage loss: scanners succeeding perfectly at scanning nothing, and
> valvur reporting a confident clean result. The worst of them reported a repository
> with 24 CVEs as clean.
>
> Not one would have been caught by the cycles below as originally written. So a
> coverage canary and a profile-equivalence check are now cycles in their own right,
> ahead of the timing budget.
>
> The other change is that **cycle 3 turned out to be a design problem, not a test.**
> The README's verification command does not work, and cannot be repaired by fixing
> the image name — see 11.0. It moves to the front because its answer may change what
> the README is allowed to claim.

### 11.0 — Decide the real non-exfiltration proof *(design, before any test)*

The README's central claim is that non-exfiltration is *"a property you can check
yourself in one command"*:

```bash
docker run --rm --network=none -v "$PWD:/workspace:ro" valvur scan
```

**Measured 2026-08-31: that command fails twice.** The image `valvur` does not exist,
and with the real name it fails again — `exec: "scan": executable file not found`,
because the image's `Cmd` is `python3`. It is not a typo. It describes a **fat
container**, which is the model [ADR-0001](../../../docs/adr/0001-thin-host-shim-read-only-container.md)
rejected: valvur is a host shim that *launches* containers, so there is no
"run valvur in a container" path to document.

- [ ] **11.0.1** Establish what a reviewer can actually run. On Linux
  `unshare -n valvur scan --profile offline` is a genuine proof — the container
  runtime is reached over a unix socket, so the scan still completes with no network
  namespace at all. Confirm this, because the whole claim rests on it.
- [ ] **11.0.2** Answer the same question for macOS, where there is no `unshare` and
  the runtime lives in a VM. If no single honest command exists, say so: a
  per-platform instruction that works beats one universal instruction that does not.
- [ ] **11.0.3** Rewrite the README claim to match whatever 11.0.1 and 11.0.2
  establish, and **only then** write cycle 11.1's test against it. *(P5 — a
  documented command that does not run is worse than no documentation, because it is
  the one thing a sceptical reviewer will try first.)*

**Commit:** `docs: a non-exfiltration proof that actually runs`

### TDD cycles

1. **The `offline` Profile makes no network connection — the test fails on any socket
   attempt, anywhere in the process tree.** *(N2.1, ADR-0010. The single most
   important test in the suite: it is what makes the README's central claim true
   rather than asserted.)*
   > **Scope tightened 2026-08-30.** Asserting only that the container was launched
   > with `--network=none` is insufficient: something host-side could reach the
   > network freely and the test would still pass. It must assert over everything
   > valvur starts.
   >
   > **Rationale corrected 2026-08-31.** The original note named a host-side
   > **Check** as the risk; [ADR-0013](../../../docs/adr/0013-checks-run-inside-the-container.md)
   > moved Checks into the container, so that specific hole is closed. The real
   > host-side network user is now **enrichment** — EPSS is fetched from FIRST by the
   > shim — and it is gated by a single boolean threaded from the Profile. One
   > inverted condition and the offline guarantee is gone with no visible symptom.
   > The scope is unchanged; only what it is guarding against.

2. **The canary fixture yields at least its known findings, per Scanner.** *(New
   2026-08-31. The regression net for silent coverage loss.)*

   `tests/fixtures/broken-repo` exercises all nine Scanners. Measured on the `full`
   Profile, 2026-08-31 — **73 findings**:

   | trivy | osv-scanner | opengrep | checkov | ai-artifact | gitleaks | dep-reality | licence-file |
   |---|---|---|---|---|---|---|---|
   | 36 | 37 | 12 | 12 | 6 | 2 | 2 | 1 |

   Assert a **floor per Scanner**, not exact totals: advisory databases grow, and a
   test that breaks every time OSV publishes is a test people delete. A Scanner
   dropping to zero is the signal — that is what every silent failure looked like.

   This is the cycle that would have caught all three of the worst defects found on
   2026-08-31: Trivy's dev-dependency exclusion (24 CVEs → 0), the ecosystem
   mismatch that double-reported every shared CVE (24 → 48), and "no package sources
   found" being treated as a scan failure.

3. **`offline` and `full` report the same dependency vulnerabilities on the canary.**
   *(New 2026-08-31. N2.1, [ADR-0016](../../../docs/adr/0016-two-profiles-split-on-the-network-boundary.md).)*

   ADR-0016 claims the offline Profile gives up a second advisory source and the
   slopsquat Check — and nothing else. **That claim was false until 2026-08-31**, when
   `offline` returned 0 CVEs on a repository where `full` found 24, in the same
   lockfile in the same minute. An offline Profile that quietly finds less makes
   *"no network required"* worth nothing, because the honest advice becomes "run the
   networked one anyway".

4. No write occurs outside the **Results Folder** and host scratch. *(N2.2)*

5. **Both budgets, not just the slow one.** *(N1.1, N1.2, N1.4)*
   - `offline` completes in under 60 seconds on a ≤50k-line repository. *(N1.1 —
     now the tighter constraint. ADR-0016 moved Checkov into `offline`, and Checkov
     is **13.7s of its measured 18.1s**. The old `quick` had no Checkov and no risk
     here; `offline` does.)*
   - `full` completes within 5 minutes and 2 GB on the same repository. *(N1.2, N1.4
     — comfortable at ~19s measured, but unverified for memory.)*

### Also in this phase

- [ ] **11.6** **Verify the self-scan** — mostly done 2026-08-31, restated as
  verification rather than work. Current state under `offline`: **1 live Finding, 2
  suppressed with reasons and a one-year expiry, 61 excluded** by
  `[scan] exclude = ["tests/fixtures"]` and reported in both `SUMMARY.md` and
  `run.json`. `LICENSE` is Apache-2.0. The one open decision is whether the remaining
  Finding — *4 dependencies declare no licence*, all genuinely ours — is acceptable
  to ship or wants a suppression with a reason.
- [ ] **11.7** Wire the self-scan into CI as a release gate. *(N2.5)* It must fail on
  three things, not one:
  1. any unsuppressed **Finding**;
  2. any **expired suppression** — the lapse already re-reports the Finding, but if
     nothing fails the build then "mandatory expiry" is decoration;
  3. any **skipped runtime-parity test**. Four Podman tests skip today because the
     GHCR package is private (task 12.6). Dual-runtime parity is an F1 claim, and a
     green CI that never ran those tests is asserting something it did not check.
     "Skipped" and "passed" must not look the same to the gate.

**Exit:** CI proves non-exfiltration on every commit, proves coverage has not
silently narrowed, and valvur passes its own scan. The README's verification command
runs as written on every platform it claims.

**Commit:** `test: constraint verification and self-scan release gate`

---

## Phase 12 — Release

- [ ] **12.1** ~~**Decide the final name.**~~ **MOVED to task 10.0.1 on 2026-08-31.**
  Publishing the `0.1.0rc1` needed for the usability gate *is* first publish, and
  claims the name. The deadline moved with it.
- [ ] **12.2** Sign the image with cosign; publish SBOM and build provenance. *(F10.3)*
- [ ] **12.3** Repo furniture: `LICENSE`, `SECURITY.md` with a disclosure policy,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates.
- [ ] **12.4** Verify every README claim traces to
  [POSITIONING.md](../../../docs/POSITIONING.md), and every **Scanner** is credited
  with its licence. *(P3, P4)*
- [ ] **12.5** Publish the release to GitHub, and the signed image to GHCR.
- [ ] **12.6** **Make the GHCR package public — owner action, blocks every other
  user.** *(F1.5, 10.1, 10.2)* Deliberately held private during development
  (decision 2026-08-31); the tool is unusable by anyone else until it is flipped.

  **Verify the problem, before and after:**
  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' \
    "https://ghcr.io/token?scope=repository:maverickhq/valvur:pull&service=ghcr.io"
  ```
  403 anonymously today. Must be 200 before the usability gate means anything.

  **Do it:** GitHub → Packages → `valvur` → Package settings → Change visibility →
  Public. Then confirm a genuinely cold pull works — an authenticated machine
  proves nothing, because a locally cached image hides this completely:
  ```bash
  docker logout ghcr.io && docker pull ghcr.io/maverickhq/valvur:0.1.0rc1
  ```

  **Why this is its own task.** Measured 2026-08-31: local scans passed only
  because docker had the image cached from the build. A new user's first run
  failed at the pull, and the failure was reported as *"the container cannot read
  the workspace"* — advice about mount permissions for an authentication problem.
  The message is fixed; the visibility is not. Tasks 10.1 and 10.2 cannot be
  evaluated honestly until this is done, because their entire subject is the
  first run.
- [ ] **12.7** Tag v1.0.0.

**Exit:** v1.0.0 released, self-scan clean, signature and SBOM published.

**Commit:** `chore: release v1.0.0`

---

## Traceability

The not-cuttable set from `requirements.md` maps to: F1 → Phase 8 · N2.1 → Phase 11
cycle 1 · F5.3 → Phase 2 cycles 1–3 · F7.2 → Phase 1 cycles 4–5 · F9.2 → Phase 9
cycle 4 · F9.4 → Phase 9 cycle 5. Each is a test that fails the build if broken.
