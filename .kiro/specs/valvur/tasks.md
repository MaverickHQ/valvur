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
  **STATUS 2026-08-30:** ✅ The check itself produces the SBOM; publishing it per release is task 12a.7, already planned.
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
  task 12a.7 brought forward, and doing it early de-risks the real release
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

- [x] **11.0.1** Establish what a reviewer can actually run.  
  **STATUS 2026-08-31:** ✅ Done, and the claim turned out to have **two halves** that
  the original task ran together. `--network=none` covers the Scanner containers.
  It says nothing about the **host shim**, which is not in a container and does have
  a reason to reach out: enrichment fetches EPSS from FIRST, gated by one condition
  threaded from the Profile.

  Built `scripts/verify-offline.py`, which checks both, and measured on a real
  repository carrying 24 CVEs — chosen so enrichment is actually reached, because a
  clean repository never calls it and passes vacuously:

  | Profile | connection attempts from the host process |
  |---|---|
  | `offline` | **0** (26 findings reported) |
  | `full` | **1**, blocked — `create_connection` |

  The `full` row is the point: the same check fails where the network is genuinely
  used, so the `offline` pass means something. `unshare -rn` confirmed working
  unprivileged on Linux (Fedora 44); the container runtime is reached over a unix
  socket, so the scan is unaffected by having no network namespace.
- [x] **11.0.2** Answer the same question for macOS.  
  **STATUS 2026-08-31:** ✅ **There is no macOS equivalent, and the README now says
  so.** `unshare` is Linux-only; Docker Desktop's seccomp profile blocks it even
  inside a container (measured: `unshare failed: Operation not permitted`), and
  running the shim in a Linux container instead breaks the mount paths, because the
  daemon resolves them on the host rather than in the container.

  The platform-independent substitute is to **disconnect the machine and scan**: once
  the image and database are cached, `offline` needs nothing else. Weaker than an OS
  denial — it shows valvur does not *need* the network rather than that it never
  *tries* — so it is documented alongside the script rather than instead of it.
- [x] **11.0.3** Rewrite the README claim to match.  
  **STATUS 2026-08-31:** ✅ The fictional one-liner is gone from `README.md`, replaced
  by the two halves, the script, the Linux `unshare` proof and the macOS limit. P5 in
  [POSITIONING.md](../../../docs/POSITIONING.md) and moat item 1 in
  [CLAUDE.md](../../../CLAUDE.md) were making the same one-command claim and now
  state the platform limit too. *(P5 — a documented command that does not run is
  worse than no documentation, because it is the one thing a sceptical reviewer will
  try first. This one had never been run.)*

  **Left for 11.1:** `verify-offline.py` is reviewer-facing and runs a real scan, so
  it is too slow for the unit suite. Cycle 11.1 needs the same assertion as a fast
  test over a stubbed runner, plus the `unshare -rn` end-to-end on Linux in CI, which
  cannot run from macOS.

**Commit:** `docs: a non-exfiltration proof that actually runs`

### TDD cycles

1. ✅ **The `offline` Profile makes no network connection — the test fails on any socket
   attempt, anywhere in the process tree.** *(N2.1, ADR-0010. The single most
   important test in the suite: it is what makes the README's central claim true
   rather than asserted.)*
   > **DONE 2026-09-01** — `tests/test_constraints.py`, 6 tests. Both halves asserted,
   > each paired with a check that it can fail:
   >
   > | mutation | caught by |
   > |---|---|
   > | enrichment ignores the Profile | host-process test |
   > | `--network=none` removed | container-argv test |
   > | `--network=none` unconditional | the falsifiability guard |
   >
   > The stub carries a real CVE deliberately. Enrichment short-circuits on a finding
   > set with none, so a stub without one passes while testing nothing — which is
   > exactly how this passed vacuously on 2026-08-31.
   >
   > **Gap, recorded not omitted:** these cover the shim (in-process) and the
   > containers (argv). Neither covers a **subprocess** opening a socket — the docker
   > CLI, or a future helper binary. Only an OS-level denial does, and `unshare -rn`
   > is Linux-only. Present as a skipped test carrying its own reason, to be enabled
   > by 11.7 in CI. It is not claimed as passing.
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

2. ✅ **The canary fixture yields at least its known findings, per Scanner.** *(New
   2026-08-31. The regression net for silent coverage loss.)*
   > **DONE 2026-09-01.** Two tests. Floors per Scanner, plus a dedicated dev-only
   > dependency check.
   >
   > **The claim below was wrong when written, and is now true.** The fixture had
   > **zero** dev-marked packages, so it could not have caught Trivy's
   > dev-dependency exclusion — the worst defect of the three. Added `minimist`,
   > reachable only through `devDependencies`, and verified against the image both
   > ways: with `--include-dev-deps` it is reported, without it the production tree
   > still reports and `minimist` alone vanishes. Mutation-tested: removing the flag
   > fails the test.

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

3. ✅ **`offline` and `full` report the same dependency vulnerabilities on the canary.**
   *(New 2026-08-31. N2.1, [ADR-0016](../../../docs/adr/0016-two-profiles-split-on-the-network-boundary.md).)*
   > **DONE 2026-09-01, asserted at package level rather than advisory level.**
   > Measured on the canary: `offline` 37 dependency findings, `full` 38, and the
   > difference is entirely `PYSEC-2023-175`, an advisory OSV carries and Trivy's
   > database does not. **Nothing was offline-only.** Requiring identical advisory
   > IDs would encode "Trivy and OSV ship the same data", which is false and not what
   > ADR-0016 claims. What must never happen is a vulnerable *package* disappearing —
   > the CLU failure, seven packages to zero. Mutation-tested against exactly that.
   >
   > **Found while writing it:** `Pillow` and `pillow` were being proposed as two
   > separate upgrades, the second to 10.0.1 *after* the first to 12.3.0, so
   > following the proposal in order downgraded the package it had just fixed.
   > Fingerprints already normalise case, so identity and suppressions were
   > unaffected — only the proposal. Fixed and covered.

   ADR-0016 claims the offline Profile gives up a second advisory source and the
   slopsquat Check — and nothing else. **That claim was false until 2026-08-31**, when
   `offline` returned 0 CVEs on a repository where `full` found 24, in the same
   lockfile in the same minute. An offline Profile that quietly finds less makes
   *"no network required"* worth nothing, because the honest advice becomes "run the
   networked one anyway".

4. ✅ No write occurs outside the **Results Folder** and host scratch. *(N2.2)*
   > **DONE 2026-09-01.** Three tests. The existing workspace-unchanged test runs
   > against a fake runner, so it proves the orchestration does not write; these run
   > the real containers.
   >
   > - Every Scanner in **both** Profiles mounts the Workspace `:ro`, asserted over
   >   the whole adapter set so a Scanner added without it fails the build rather
   >   than review. Mutation-tested.
   > - A real scan changes nothing in the Workspace's **parent** directory either.
   >   A path-handling bug that escaped the mount would land beside the Workspace,
   >   where a test watching only inside it cannot see.
   > - The `:rw` scratch directory does not survive the run. Raw Scanner output
   >   contains live credentials (F5.7); leaving it in `/tmp` puts them in a second
   >   cleartext location nobody knows to clean up.

5. **Both budgets, not just the slow one.** *(N1.1, N1.2, N1.4)*
   - `offline` completes in under 60 seconds on a ≤50k-line repository. *(N1.1 —
     now the tighter constraint. ADR-0016 moved Checkov into `offline`, and Checkov
     is **13.7s of its measured 18.1s**. The old `quick` had no Checkov and no risk
     here; `offline` does.)*
   - `full` completes within 5 minutes and 2 GB on the same repository. *(N1.2, N1.4
     — comfortable at ~19s measured, but unverified for memory.)*

### Also in this phase

- [x] **11.6** **Verify the self-scan** — mostly done 2026-08-31, restated as
  verification rather than work.  
  **STATUS 2026-09-01:** ✅ **N2.5 passes: 0 unsuppressed Findings**, 3 suppressed
  with reasons, 62 excluded. The open decision is resolved, and investigating it
  found the Finding was **false**. All four packages *do* declare licences — through
  PyPI Trove classifiers, which Syft does not read: `docutils` (BSD/GPL/public
  domain), `id` (Apache-2.0), `markdown-it-py` (MIT), `pathspec` (MPL-2.0). Syft
  records licences for 36 of 140 components here, so the blind spot is detection,
  not declaration.

  Two changes followed. The message no longer asserts what it cannot know —
  *"N dependencies have no licence recorded"*, with the evidence saying the SBOM is
  the source and detection is partial. And the Finding is suppressed with that as
  the reason, because valvur cannot fix it generally: it holds only the SBOM, and a
  scanned project's packages are not installed on the host to read classifiers from.

  Original text follows. Current state under `offline`: **1 live Finding, 2
  suppressed with reasons and a one-year expiry, 61 excluded** by
  `[scan] exclude = ["tests/fixtures"]` and reported in both `SUMMARY.md` and
  `run.json`. `LICENSE` is Apache-2.0. The one open decision is whether the remaining
  Finding — *4 dependencies declare no licence*, all genuinely ours — is acceptable
  to ship or wants a suppression with a reason.
- [x] **11.7** Wire the self-scan into CI as a release gate. *(N2.5)*  
  **STATUS 2026-09-01:** ✅ New `selfscan` job, plus two fixes to the existing `e2e`
  job. Each failure condition was verified by planting it and watching the gate
  fail — an ungated gate is the thing this phase exists to prevent.

  **The e2e job could not have been passing.** It builds `valvur:dev` and never set
  `VALVUR_IMAGE`, so every container test ran against the published GHCR tag it had
  not built and cannot pull while the package is private (task 12a.1). Now set.

  **Runtime parity is asserted to have run.** The parity tests skip when a runtime
  has no local image — right locally, wrong in CI, where both runtimes have it. A
  skip there means the F1 dual-runtime claim went unverified while CI stayed green.
  The job now fails if `tests/test_runtimes.py` reports any skip.

  Original text follows. It must fail on three things, not one:
  1. any unsuppressed **Finding**;
  2. any **expired suppression** — the lapse already re-reports the Finding, but if
     nothing fails the build then "mandatory expiry" is decoration;
  3. any **skipped runtime-parity test**. Four Podman tests skip today because the
     GHCR package is private (task 12a.1). Dual-runtime parity is an F1 claim, and a
     green CI that never ran those tests is asserting something it did not check.
     "Skipped" and "passed" must not look the same to the gate.

**Exit:** CI proves non-exfiltration on every commit, proves coverage has not
silently narrowed, and valvur passes its own scan. The README's verification command
runs as written on every platform it claims.

**Commit:** `test: constraint verification and self-scan release gate`

---

## Phase 12 — Release

**Goal:** make valvur obtainable, verifiable and trustworthy by someone who is not
us — then release it.

> **Split in two on 2026-09-05, after reviewing what Phase 11 actually built.** The
> phase as written could not reach its own exit criterion.
>
> **It was circular.** Task 12.6 unblocks Phase 10's usability gate; the gate's
> findings *become* Phase 10's task list; and Phase 12 then tagged `v1.0.0`. Those
> cannot all hold. Tagging 1.0.0 before one external person has installed the tool
> inverts the order, so the phase is now **12a — make it obtainable**, the gate runs
> against that, and **12b — release** acts on what the gate finds.
>
> **The target version changed with it.** `v1.0.0` is a promise about stability that
> nothing has tested. ADR-0016 was a breaking change, the published artifact is still
> `0.1.0rc1`, and the next publish has a licence-metadata correction to carry (12a.7).
> 12a ships **0.2.0**; 1.0.0 waits for the gate.
>
> **And four assumptions had gone stale.** 12.6 named the package while the
> *repository* is private too; the README's headline performance figure is wrong by
> roughly 4×; the published PyPI artifact declares a licence the repository no longer
> uses; and the version literal turned out to live in five places while F1.9 compares
> two of them.

- [x] **12.1** ~~**Decide the final name.**~~ **MOVED to task 10.0.1 on 2026-08-31.**
  Publishing the `0.1.0rc1` needed for the usability gate *is* first publish, and
  claims the name. The deadline moved with it. ✅ `valvur` kept.

---

### 12a — Make it obtainable and trustworthy

Nothing below is optional for the gate. A participant who cannot obtain the tool,
or cannot check the claims we make about it, is not testing the product.

- [ ] **12a.1** **Push, then make the repository public, then the package.**
  *(F1.5, blocks 10.1 and 10.2)* — **owner action.**

  > ⛔ **BLOCKED BY [Phase 13](#phase-13--portability), added 2026-09-05.** The
  > published image is `linux/arm64` only, so going public today hands every amd64
  > user an artifact that cannot run. Publishing an unusable image is worse than
  > publishing nothing: it converts a private repository into a public first
  > impression that fails.

  Held private during development (decision 2026-08-31). **Measured 2026-09-05:**

  | | |
  |---|---|
  | `api.github.com/repos/MaverickHQ/valvur` | **404** anonymously |
  | `ghcr.io/token?scope=…valvur:pull` | **401** anonymously |
  | local commits ahead of `origin/main` | **17** |

  The original task named only the package. The **repository** is private too, which
  matters more: the README now tells a reviewer to run
  [`scripts/verify-offline.py`](../../../scripts/verify-offline.py) as the central
  proof of the central claim, and they cannot obtain it. The ADRs, which are where
  every decision's reasoning lives, are equally unreachable.

  Order matters — push first, or the public repository is missing all of Phase 11:
  ```bash
  git push origin main
  # GitHub → Settings → Change visibility → Public
  # GitHub → Packages → valvur → Package settings → Change visibility → Public
  ```
  Then confirm a genuinely **cold** pull. An authenticated machine proves nothing,
  because a locally cached image hides this completely — which is exactly how it went
  unnoticed until 2026-08-31:
  ```bash
  docker logout ghcr.io && docker pull ghcr.io/maverickhq/valvur:0.2.0
  curl -s -o /dev/null -w '%{http_code}\n' https://api.github.com/repos/MaverickHQ/valvur
  ```
  **Why it earns its own task.** Local scans passed only because Docker had the image
  cached from the build. A new user's first run failed at the pull, and the failure
  was reported as *"the container cannot read the workspace"* — advice about mount
  permissions for an authentication problem. The message is fixed (11.0); the
  visibility is not.

- [x] **12a.2** **One source of truth for the version, and a check that it holds.**
  *(F1.9)* ✅ **DONE 2026-09-05.**

  > `src/valvur/version.py` derives `__version__` from installed package metadata;
  > `runner._VERSION`, `runner.IMAGE`, `results._VERSION` and `compat.shim_version()`
  > all read it. **Five places became two:** `pyproject.toml`, which a human edits,
  > and the README's status line, which a test now maintains. Remaining mentions are
  > historical prose about which version the retired Profile names came from.
  >
  > The image tag is derived too — `default_image()` returns
  > `ghcr.io/maverickhq/valvur:{__version__}` — so a shim asks for the tag it was
  > built alongside and cannot drift from it. `VALVUR_IMAGE` still overrides, for
  > local builds and air-gapped mirrors.
  >
  > **Centralising it exposed the bug it was meant to prevent, already live.** The
  > editable install's metadata was six days stale: `importlib.metadata` reported
  > `0.1.0.dev0` while `pyproject.toml` declared `0.1.0rc1`. Every local scan for a
  > week ran as one version and wrote the other into `results.sarif`. F1.9 stayed
  > quiet because the two share a compatibility series — it compares `(0, 1)` against
  > `(0, 1)`. The hardcoded literal is exactly what hid it.
  >
  > Tests cover both failure modes, each verified by planting it: a **partial bump**
  > (pyproject moved, environment stale) fails two tests, and a **non-canonical
  > version string** fails one. That second matters at release: CI labels the image
  > with the raw `pyproject.toml` value while the shim reports the PEP 440 normalised
  > one, so `0.2.0-rc1` would have them disagree at the moment F1.9 compares them.

  Measured 2026-09-05 — the literal appears in **five** places:
  `pyproject.toml`, `src/valvur/runner.py` twice (`IMAGE` and `_VERSION`),
  `src/valvur/results.py`, and `README.md`.

  F1.9 refuses to run a mismatched shim and image, comparing exactly two of those. A
  partial bump therefore ships a pair that either refuses to start or, worse, agrees
  while being wrong. Derive them from package metadata, and add a CI step asserting
  every remaining literal agrees — a release is the one moment this breaks, and the
  one moment nobody is running the test suite.

- [x] **12a.3** **Decide whether Checkov runs unconditionally — this is a product
  decision and it gates 12a.4.** ✅ **DECIDED 2026-09-05: gate it.**

  > **DONE.** `src/valvur/applicability.py` + `CheckovAdapter.applies_to`. Measured
  > after, on real repositories and a warm cache:
  >
  > | repository | files | Checkov | offline |
  > |---|---|---|---|
  > | crucible-autoresearcher (Python) | 69 | skipped | **7.1s** |
  > | CLU (TypeScript, GH Actions) | 109 | ran — `.github/workflows/release.yml` | 17.7s |
  > | fixture | 12 | ran — `main.tf` | 16.8s |
  >
  > Application-only repositories go from ~18s to ~7s; repositories with
  > infrastructure still pay for it, correctly.
  >
  > **The three rules the risk demanded**, all enforced by tests: detection is
  > **biased to running** (an unreadable or unrecognised file counts as
  > infrastructure); the skip is **never silent** (`run.json.scanners_skipped` and a
  > `SUMMARY.md` line, `complete` unchanged — a skip is not a failure); and **both
  > branches are tested**, because a detector rotted to always-False would sail
  > through a suite that only checked the skip. Mutation-tested: forcing it to
  > always-False fails 20 unit tests *and* the e2e coverage canary.
  >
  > **A measurement error caught in passing.** The first re-measurement showed CLU
  > and crucible at 6.4s with Checkov skipped — both were empty directories, cleaned
  > from the scratchpad between sessions. A scan of nothing is fast and proves
  > nothing. Re-cloned and re-measured; CLU does have infrastructure and does pay.

  Measured 2026-09-05 on the offline Profile, per Scanner, against a 12-file fixture:

  | gitleaks | trivy | opengrep | **checkov** | syft | licence-file | ai-artifact |
  |---|---|---|---|---|---|---|
  | 1.0s | 0.6s | 3.1s | **11.2s** | 1.3s | 1.0s | 1.1s |

  Checkov is a fixed startup cost, not proportional to the work. A repository with no
  Dockerfile, no terraform and no Kubernetes manifests pays 11 seconds for a Scanner
  that has nothing to look at.

  Gating it on the presence of IaC files would return most projects to ~8s scans. The
  argument against is that a conditional Scanner is a Scanner that can silently stop
  running — the exact failure class Phase 11 exists to catch — so if this is done,
  the trigger belongs in the coverage canary (11.2) with a fixture that has no IaC.

- [x] **12a.4** **Re-verify every README claim by measurement, not by reading.**
  *(P3, P4)*

  This was written as a read-through. It cannot be one: the claims changed under it
  in Phase 11, and at least one is now wrong.

  **Measured 2026-09-05 — the README says an offline scan takes `5.6s`:**

  | repository | size | offline |
  |---|---|---|
  | fixture | 12 files | **20.3s** |
  | CLU | ~100 files | 18.0s |
  | valvur itself | 38,697 lines | 23.4s |

  Roughly 4× out, and not because of repository size — the 5.6s was measured when
  `quick` had five Scanners and no Checkov, before ADR-0016. Correct the figure, or
  change the product first (12a.3) and then correct it.

  > **DONE 2026-09-05.** Two passes. The timing table was corrected against 12a.3
  > (`~7s` application code, `~17s` with infrastructure, basis stated). The sweep
  > then found five more claims that were wrong rather than merely stale, every one
  > checked against the code or the image rather than read:
  >
  > | claim | reality |
  > |---|---|
  > | Trivy credited for "Dependencies, IaC, container images, SBOM, licences" | we invoke `trivy fs --scanners vuln` — **dependencies only** |
  > | `valvur scan --profile deep`, "including container images" | `deep` is retired, and valvur **never scans container images** |
  > | "Fast, fully offline pre-commit check (~60s)" | ~7s, and `offline` is now the default rather than an option |
  > | "on standard and deep" | retired names |
  > | "No GPL-licensed tools are included in the distributed image" | contradicted by ADR-0005's own correction *and* by the Opengrep LGPL-2.1 row two lines above |
  >
  > **And one claim that traced to nothing at all.** *"The same image runs on
  > ECS/Fargate via ECR — identical artifact, no AWS-specific code paths, no
  > behavioural difference."* It appears in no requirement, nothing in
  > POSITIONING.md backs it (its only AWS mentions are about the competitor), there
  > is no AWS code anywhere, and it has never been run. It is also architecturally
  > doubtful: ADR-0001's shim *launches* containers, and Fargate exposes no Docker
  > socket and no privileged mode. Rewritten to what is defensible — the image is a
  > plain OCI artifact that pushes anywhere, and orchestration needs a runtime the
  > shim can reach. `CLAUDE.md` §1 carried the same claim and now records the
  > correction rather than the claim.
  >
  > **Verified rather than assumed:** all six Scanner licences against their
  > repositories (P4 — all correct); every Scanner present in the image at the
  > credited version; F10.4 by running `scripts/check_image_licences.py` against the
  > published image (passes — valvur adds no GPL component); every README link
  > resolves; `VALVUR_DB_REPOSITORY` is the real variable name; the comparison table
  > traces to POSITIONING.md lines 57–79; and the advertised MCP entry point starts,
  > reports `valvur 0.1.0rc1` and exposes its four read-only tools.
  >
  > Also fixed: two sections shared the heading *"For AI coding agents"*, one about
  > installing and one about reading output.

  Also re-check: the Profile names throughout (ADR-0016 renamed them), the
  verification instructions (rewritten in 11.0, and platform-split), and that every
  Scanner is still credited with its licence (P4).

- [x] **12a.5** **Repo furniture.** ✅ **DONE 2026-09-05** — was one of seven.

  - [x] `LICENSE` — Apache-2.0, added 2026-08-31
  - [x] `SECURITY.md` — private reporting route, and commitments a solo maintainer
        can keep (5 working days to acknowledge, 15 to assess) rather than ones that
        read well. **The scope section is the part that matters**: for this product a
        *false clean result* is a vulnerability, not a bug, along with a silent
        scanner failure, evidence that survives neutralisation, and anything leaving
        the machine on `offline`. Findings from the bundled Scanners are explicitly
        out of scope and pointed upstream.
  - [ ] **Enable GitHub private vulnerability reporting** — ⚠️ **STILL OPEN, owner
        action**, same category as 12a.1. `SECURITY.md` now points at
        `/security/advisories/new`, and until the setting is on, that link 404s. A
        disclosure route that does not exist is the security-tool equivalent of a
        verification command that does not run — which is exactly what 11.0 found.
  - [x] `CONTRIBUTING.md` — setup, the spec/ADR/vocabulary conventions, and a
        **"what will be turned down"** section so the moat is stated before someone
        spends a weekend on a feature that sends code somewhere. Encodes the testing
        discipline this project actually uses: every assertion must be able to fail,
        prove the fixture reaches the code under test, mutation-test anything
        load-bearing.
  - [x] `CODE_OF_CONDUCT.md` — original and short, because the Contributor Covenant
        could not be fetched and a standard document reproduced from memory with
        subtly wrong wording is worse than none. Structure credited to it.
  - [x] Issue templates (bug, feature, **a finding you disagree with**) and a PR
        template whose checklist is the real gates. The accuracy template asks which
        direction the error runs and says a missed finding is treated as a security
        report. `config.yml` routes suspected vulnerabilities away from public issues.
  - [x] `CHANGELOG.md` — Keep a Changelog format, with the ADR-0016 alias table
        (`quick`→`offline`, `standard`/`deep`→`full`) a user upgrading needs, and the
        month of defect fixes written up in terms of what they meant rather than what
        they touched.
  - [x] README now links all of them.

- [x] **12a.6** **Pin our own supply chain.** ✅ **DONE 2026-09-05.**

  > Every workflow step now carries a commit SHA with the tag in a trailing comment,
  > so Dependabot can still track it. `.github/dependabot.yml` covers actions, pip
  > and Docker weekly — **necessary rather than optional now**, because a pinned SHA
  > never moves on its own, so a security update arrives only if something opens the
  > pull request.
  >
  > **The product gap is fixed too.** `valvur.pinning.mutable-action-ref` catches
  > `@v6`, `@main` and reusable-workflow refs, and ignores a 40-character SHA, a
  > local `./…` action and a `docker://` ref — verified against the real scanner in
  > all six forms. `WARNING`, not `ERROR`: unpinned actions are near-universal, and a
  > rule that fires on every repository's first workflow file teaches people to skip
  > the category.
  >
  > The fixture gained an unpinned workflow and the opengrep golden was recaptured.
  > The diff was exactly **+2 `mutable-action-ref`** and nothing else moved, which is
  > what a golden is for.
  >
  > **Rules ship inside the image**, so the new rule reaches a real scan only when
  > 12a.7 rebuilds — the golden covers it today, and the canary's opengrep count
  > moves from 12 to 14 then. Worth knowing rather than discovering.
  >
  > **A false-positive class found by the self-scan, and left recorded rather than
  > suppressed.** The older rule scans every YAML file, so the comment documenting
  > it — which quoted the string it matches — became a finding against the rule file
  > itself. Ours is reworded. Any project whose rule definitions or documentation
  > quote a pattern will hit the same thing, and narrowing `paths.include` to
  > dependency manifests would trade a false positive for a false negative. Not
  > worth that trade today; worth an issue.

- [ ] **12a.7** **Automate the release, and publish `0.2.0`.** *(F10.3)*
  ✅ **Automation done 2026-09-05. Publishing blocked on 12a.1 and owner setup.**

  > ⛔ **ALSO BLOCKED BY [Phase 15](#phase-15--our-own-supply-chain).** This workflow
  > holds `id-token: write`. Every `FROM` is pinned by tag rather than digest and the
  > Opengrep binary is fetched unverified, so a compromised input would not merely
  > build bad code — it would sign it with our identity and log it as authentic.
  > Phase 13 also changes this task: a multi-platform build obtains its digest
  > differently, and the signature must cover the index rather than one child
  > manifest.

  > `.github/workflows/release.yml`, triggered by a `v*` tag, in two jobs.
  >
  > **`verify` refuses to release a tree that disagrees with itself.** The tag must
  > match `pyproject.toml` — the one moment nobody runs the suite first and the one
  > moment a mismatch is expensive — then lint, types, the *whole* suite including
  > e2e, F10.4, and the self-scan gate (N2.5, failing on unsuppressed findings,
  > expired suppressions and an incomplete scan).
  >
  > **`release` publishes, then proves what it published.** Pushes to GHCR; **signs
  > the digest, never the tag** — a tag can be moved, which is the entire reason we
  > pin actions to SHAs, and signing one would carry that defect into our own supply
  > chain; keyless via OIDC, so there is no key to store or leak; attests SLSA
  > provenance; publishes CycloneDX *and* SPDX SBOMs **of the image**, distinct from
  > the one valvur writes for a scanned project; publishes to PyPI by trusted
  > publishing rather than a stored token; and puts the verification commands in the
  > release notes so a sceptic does not have to find them.
  >
  > Permissions are per-job. `ci.yml`'s top-level `contents: read` stays, and a test
  > now asserts it — `ci.yml` runs on pull requests including from forks, where a
  > write token is the difference between reading the repository and rewriting it.
  >
  > **Verified locally:** the tag gate accepts `v0.1.0rc1` and rejects `v0.2.0` and
  > `v1.0.0` against the current tree; both distributions build and the sdist still
  > excludes the planted credentials (10.0.2's guard holds); the new workflow passes
  > our own pinning rule and Checkov with zero findings. A second test asserts every
  > action in every workflow is SHA-pinned, mutation-tested — the opengrep rule only
  > reaches a real scan after the image is rebuilt, so this is the commit-time guard,
  > and the release workflow is exactly where a moved tag would sign bad code with
  > our identity.
  >
  > **Deliberately not done: the version is still `0.1.0rc1`.** Bumping it breaks
  > local scanning until the image is published, because the shim derives its image
  > tag from its own version (12a.2). That is the right trade — the alternative is a
  > shim silently using an image built from different code — but it means the bump
  > belongs immediately before the tag, not now.
  >
  > **Blocked on, and requires the owner:** 12a.1 (public repo and package), PyPI
  > trusted publishing configured against this workflow, and a `release` GitHub
  > environment. All three are in [docs/RELEASING.md](../../../docs/RELEASING.md),
  > along with the release procedure and how to verify a release as a user would.

  There is no release automation at all today — 12.2 and 12.5 were both hand-run
  steps, which is how a mismatched artifact ships. A tag-triggered `release.yml`
  covering: cosign keyless signing, an SBOM **of the image** (distinct from the
  `sbom.cdx.json` valvur writes for a scanned project — reuse the Syft invocation
  already in `scripts/check_image_licences.py`), SLSA build provenance via
  `actions/attest-build-provenance`, the GHCR push and the PyPI publish.

  **Permissions wrinkle.** `ci.yml`'s top-level `permissions: contents: read` is
  correct and must stay — we report `CKV2_GHA_1` in other people's repositories.
  Signing needs `id-token: write` and `attestations: write`, scoped to the release
  job alone.

  **This publish carries a correction.** Measured 2026-09-05: PyPI's metadata for
  `0.1.0rc1` declares **MIT**, because the artifact predates the Apache-2.0 change of
  2026-08-31. PyPI metadata cannot be edited in place. Until `0.2.0` ships, valvur's
  own published package contradicts its own `LICENSE` file — which, for a tool that
  performs licence analysis, is the first thing a reviewer will find.

**Exit (12a):** a stranger can find the repository, read the reasoning, install the
tool, pull the image cold, and verify the non-exfiltration claim unaided. `0.2.0` is
published, signed, with an SBOM and provenance, and its metadata tells the truth.

**Commit:** `chore: release 0.2.0 — obtainable, signed, and honestly described`

---

### → The usability gate runs here

[Task 10.1](#101--the-usability-gate) has never run, because until 12a there was
nothing a participant could obtain. It runs now, against `0.2.0`, and **its findings
become the task list for 12b.** Everything below is provisional until it has.

---

### 12b — Release

- [ ] **12b.1** Act on the usability gate's findings. Phase 10 tasks 10.1–10.5 close
  here or are explicitly deferred with a reason.
- [ ] **12b.2** Re-run the Phase 11 constraint suite and the self-scan gate against
  the release artifact rather than the working tree. *(N2.5)*
- [ ] **12b.3** Tag `v1.0.0` — the first version claiming stability, and the first one
  a person outside this repository has successfully used.

  > ⛔ **REQUIRES [Phase 17](#phase-17--traceability-and-seams).** A version claiming
  > stability should not ship with a Traceability section that is untrue, a
  > compatibility surface nothing reads, and a load-bearing seam wired by `getattr`.

**Exit (12b):** v1.0.0 released. CI proves non-exfiltration on every commit, the
self-scan is clean, the signature and SBOM are published, and someone who has never
seen valvur has installed it and got a useful answer.

**Commit:** `chore: release v1.0.0`

---

## Phases 13–17 — added 2026-09-05 after a step-back review

**Why these exist.** Phase 12 was written on the assumption that what remained was
publishing. A review against the requirements rather than against the task list found
one release blocker, one live instance of this project's signature defect, and two
supply-chain gaps in the build that is about to hold signing credentials. None was
caught by a test, because none was the kind of thing the tests were pointed at.

**Running order.** These phases sit *between* the two halves of Phase 12, not after
it. The document cannot show that, so it is stated here:

```
12a.2–12a.7  ✅ done
     ↓
Phase 13  Portability          ✅ multi-arch build; published artifact under test
Phase 14  Stale data           ✅ inconclusive verdict, --if-stale, DB age surfaced
Phase 15  Our own supply chain ✅ digests pinned, Opengrep verified, 98MB smaller
     ↓
Phase 16  Operations           ✅ MCP carries the verdict; Ctrl-C stops the scan;
                                 one writer per workspace and per database
     ↓
12a.1 + 12a.7   publish 0.2.0   ← here. Nothing in the code blocks it now;
                                  the remaining steps are owner actions
     ↓
Phase 10 usability gate  →  12b.1, 12b.2
     ↓
Phase 17  Traceability and seams  ← before claiming stability
     ↓
12b.3  tag v1.0.0
```

> **Note added 2026-09-05.** Each of 13, 14 and 15 found something worse than the
> defect it was written for: the Dockerfile could always build amd64 and only the
> *push* was single-arch; the database age measured the download rather than the
> data, so an air-gapped mirror was guaranteed to read as fresh; and Opengrep shipped
> three times in every image because deleting a file in a later layer reclaims
> nothing. In each case the measurement, not the reasoning, was what found it.

---

## Phase 13 — Portability

**Goal:** the published artifact runs on the machines people actually have.

> **Measured 2026-09-05.** `docker manifest inspect` reports the published image as
> **`linux/arm64` only**. Every amd64 user — most CI runners, most Linux desktops,
> every cloud VM, every Intel Mac — cannot run it. `docker pull --platform
> linux/amd64` warns on an arm64 host and fails outright on a real amd64 one.
>
> The Dockerfile is already arch-aware: it takes `TARGETARCH` and fetches both
> Opengrep binaries. Nothing is missing but a multi-platform build. It was published
> single-arch from an Apple Silicon Mac.
>
> **The gap that let it through matters more than the defect.** Both workflows
> `docker build` locally and neither ever pulls the published image, so CI cannot
> catch this class at all — not this bug, and not the next one like it.

### TDD cycles

1. **A scan using the *published* image succeeds on amd64.** Not a locally built one.
   This is the cycle that closes the blind spot; the multi-arch build is what makes it
   pass. It must fail today.
2. The published manifest lists both `linux/amd64` and `linux/arm64`.

- [x] **13.1** Build multi-arch in `release.yml`. ✅ **DONE 2026-09-05.**

  > buildx with QEMU, both platforms in one index. The digest now comes from
  > `--metadata-file` rather than `docker inspect` — buildx pushes directly, so there
  > is no local image to inspect — and it is the **index** digest, because signing a
  > child manifest would leave the other architecture unsigned: the same defect as
  > signing a tag. A following step asserts the published index really carries both,
  > because a `--platform` flag silently ignored, or a builder falling back to the
  > runner's own architecture, both produce a successful-looking push.
  >
  > **The Dockerfile was never the problem, and now that is measured rather than
  > assumed.** Built `linux/amd64` locally under emulation and ran a real scan
  > through it: **74 findings, `complete: True`, no scanner failures**, every scanner
  > contributing. The Opengrep binary's ELF machine type is `0x3e` — x86-64 — so
  > `TARGETARCH` had been selecting correctly all along.
  >
  > Two scanners appeared to fail first, and did not. `opengrep` and `checkov` both
  > died on `/tmp` permissions because a bare `docker run` lacks the tmpfs the runner
  > mounts (Opengrep needs `exec`, Checkov a writable cache as non-root). Diagnosed
  > rather than reported: an emulation artifact and a real defect look identical
  > until you read the error.
- [x] **13.2** A CI job and a test, both pointed at the **published** artifact.
  ✅ **DONE 2026-09-05.**

  > New `published` job in `ci.yml`, plus `tests/test_portability.py`. Both check
  > whether an anonymous client can obtain a pull token and, while the package is
  > private, **skip loudly with the reason** — the job emits a `::warning::` saying
  > the published artifact is unverified on amd64. A skip that reads as a pass is how
  > this shipped in the first place.
  >
  > **Verified it catches the real defect**: forcing the public check to pass makes
  > the test fail against today's published image with
  > *"missing ['linux/amd64', 'linux/arm64'] — it advertises a single platform with
  > no manifest list"*. So the moment 12a.1 lands, this fails until 13.1's build has
  > run, which is exactly the ordering the phase needs.
- [x] **13.3** **Decide Windows, and say so either way.** ✅ **DECIDED 2026-09-05:
  WSL2 supported, native Windows not claimed.**

  > Not blocked, and not claimed. A hard refusal would be wrong — it may genuinely
  > work and nobody has checked — and silence would be worse, because silence reads
  > as "supported". `unsupported_platform_warning()` says which it is at startup and
  > points at WSL2, where valvur is running on Linux and is tested on every commit.
  >
  > **In MCP mode the warning goes to stderr, never stdout**, because stdout is the
  > JSON-RPC channel and a line of prose there corrupts the stream for every client.
  > A test asserts the server writes nothing to stdout.
  >
  > The README now carries a platform table. It says `linux/amd64` and `linux/arm64`
  > are both published **from 0.2.0** — `0.1.0rc1` is arm64 only, and writing "both
  > published" today would have been the same class of untrue claim 12a.4 spent a
  > morning removing.

**Exit:** ✅ **Reached, pending publication.** The build produces both architectures
and CI is pointed at the published artifact rather than a local build. The remaining
step is not code: `0.2.0` must actually be published (12a.1 + 12a.7) before the
`published` job stops skipping. Until then it warns on every run that the artifact is
unverified — which is true, and is the point.

**Commit:** `build: publish a multi-arch image, and test the published one`

---

## Phase 14 — Confident answers from stale data

**Goal:** valvur never reports clean from a database too old to know otherwise.

> **This is the last live instance of this project's signature defect**, and it sits
> in the one place it matters most. `cache.db_age_days()` exists and is consulted
> **nowhere**. Measured 2026-09-05: the local database was 6 days old and nothing said
> so. At six months, a user gets a confident clean result with no warning.
>
> We already warn when *KEV enrichment* data is over 30 days stale — that is the data
> that ranks findings. We say nothing about the database that determines whether
> findings exist at all. The wrong one is instrumented.

### TDD cycles

1. **A scan with a stale database does not report an unqualified clean.** The age and
   its consequence appear in `SUMMARY.md` and `run.json`, with at least the prominence
   of the existing KEV warning. Paired, as ever, with a check that a *fresh* database
   produces no warning — or the caveat becomes noise a reader learns to skip.
2. `run.json` records the database's age and source, so a clean result stays
   falsifiable after the fact (N3.1).
3. The threshold is justified in the code rather than chosen. Trivy's own database
   rebuilds every 6 hours; pick a number against that and say why.

- [x] **14.1** Surface it, and decide the threshold. ✅ **DONE 2026-09-05.**

  > **Threshold: 7 days, and it is derived rather than chosen.** Trivy stamps
  > `NextUpdate` at `UpdatedAt + 24h`, so it rebuilds daily — seven days is seven
  > missed rebuilds. KEV's 30 days stays looser on purpose: it changes how findings
  > *rank*, not whether they are *found*.
  >
  > **The age now measures the data, not the file.** `db_age_days()` read the
  > metadata file's mtime, which is when it was *downloaded*. For an air-gapped
  > mirror (F10.5) those diverge completely: a mirror can hand over a six-month-old
  > database this morning and mtime reads as fresh. It now reads Trivy's `UpdatedAt`,
  > with mtime as the fallback. Tested with a 180-day-old build stamp written this
  > second — the case that motivated it.
  >
  > **Two different claims, because they are different claims.** Stale with no
  > findings: *"this scan found nothing, and that is not evidence there is nothing"*.
  > Stale with findings: *"the list is not complete"*. Saying "found nothing" in the
  > second case would be false, and a warning that overstates gets ignored.
  >
  > Surfaced in `SUMMARY.md` **above** the exploit-intelligence warning, in
  > `run.json` as a `database` block (age, overdue, stale, threshold), and in the
  > terminal — a user may never open `SUMMARY.md`, and the case where that matters
  > most is the one where there is nothing in it to draw them there. Unknown is
  > reported as unknown, never as zero. Mutation-tested both ways: removing the
  > staleness check fails three tests, reverting to mtime fails the mirror test.
- [x] **14.2** ✅ **DECIDED 2026-09-05: valvur never updates the database itself, on
  any Profile.** Three reasons, in order of weight.

  > **It is a 1.2GB download.** Starting one inside a scan the user asked to be fast
  > is hostile, and starting it silently is worse.
  >
  > **It would make the Profiles disagree for a reason unrelated to coverage.** If
  > `full` refreshed and `offline` could not, the two would scan different data — and
  > Phase 11 cycle 3 asserts they find the same packages. That test would start
  > failing for a difference *we* introduced, which is the worst kind.
  >
  > **Updating on the user's behalf is the same move as fixing on their behalf**, and
  > §4 refuses that. So valvur says it, loudly, in three places, and the developer
  > decides.
  >
  > A test asserts `scan()` never calls `update_db`, so this stays decided rather
  > than drifting.
  >
  > **REOPENED and properly resolved 2026-09-05, after "how do we make sure the data
  > is current?" exposed the above as detection dressed as a solution.** Two of the
  > three reasons did not survive scrutiny, and one was simply wrong.
  >
  > **The 1.2GB was never measured.** The published artifact is **116MB compressed**;
  > 1.2GB is the uncompressed size on disk. Our own help text had quoted the wrong
  > figure for months, discouraging the very update the tool depends on. The
  > profile-divergence argument only applied to the design already rejected, and §4 is
  > about *remediation* decisions — refreshing reference data is not accepting risk on
  > someone's behalf.
  >
  > **What actually solves it, in three parts:**
  >
  > 1. **The verdict carries the claim.** A stale scan with no findings now reports
  >    **`inconclusive`**, not `clean`. Phase 14 had fixed only the prose — a
  >    400-day-old database still produced `"status": "clean"`, and the results
  >    contract tells agents to read `SUMMARY.md` *bounded* while querying
  >    `findings.json`, so the consumer most likely to act on the verdict was the one
  >    least likely ever to see the caveat. Third status added to the contract
  >    ([CLAUDE.md §7](../../../CLAUDE.md)).
  > 2. **Staleness is knowable for free.** Trivy stamps `NextUpdate`, so being past
  >    due costs one file read and no network.
  > 3. **`valvur update --if-stale`** — a no-op when current, so it is cheap enough
  >    for a pre-commit hook, a cron entry or CI. That is the mechanism that keeps
  >    data current; the status is what makes ignoring it visible.
  >
  > **Auto-update is still refused, for the one reason that holds:** `offline` is the
  > default and cannot reach the network, so auto-updating would help only `full`
  > users while introducing exactly the profile divergence described above. It would
  > solve the problem for the minority and hide it from the majority.

**Exit:** ✅ **Reached 2026-09-05.** Verified end-to-end by ageing the real database's
build stamp to 40 days: the terminal warned, `SUMMARY.md` carried it, and `run.json`
recorded `{"age_days": 40.0, "stale": true}`. At the true 6.2 days nothing fires,
which is the half that keeps the warning worth reading.

**Commit:** `fix: a clean result from a stale database is not a clean result`

---

## Phase 15 — Our own supply chain

**Goal:** the build that signs our releases is as pinned as the releases it signs.

> **Measured 2026-09-05, and the inconsistency is ours.** Last week we pinned every
> GitHub Action to a commit SHA because a tag is a mutable pointer. In the same
> repository:
>
> - Every `FROM` is pinned by **tag**, not digest — `aquasec/trivy:0.74.0` and four
>   others. A moved tag rebuilds a different scanner into our image.
> - The Opengrep binary is fetched over HTTPS with **no verification at all**. The
>   comment beside it says *"Opengrep publishes signed static musllinux binaries"* —
>   and we check neither signature nor checksum.
>
> Both sit in the build that Phase 12a.7 gives `id-token: write`. A compromised input
> there is not merely bad code: it is bad code signed with our identity and recorded
> in a transparency log as authentic.

- [x] **15.1** Pin every `FROM` by digest. ✅ **DONE 2026-09-05.**

  > All five, by **index** digest with the tag in a comment above — Dockerfile has no
  > inline comments on `FROM`, which the first attempt discovered by failing to parse.
  >
  > **Index digests, deliberately.** Pinning a child manifest would have silently
  > broken Phase 13's multi-arch build by resolving to one architecture whatever
  > `--platform` asked for — a defect that looks like a working build.
  >
  > Also corrected while in there: the image declared
  > `org.opencontainers.image.licenses="MIT"`, stale since the Apache-2.0 change on
  > 2026-08-31. Every published image carried the wrong licence in its own metadata.
- [x] **15.2** Verify the Opengrep download. ✅ **DONE 2026-09-05 — both.**

  > Opengrep publishes no checksums but signs every binary with **sigstore,
  > keylessly**, from its own workflow. Both signatures verified with `cosign
  > verify-blob` against
  > `.../rolling-release.yml@refs/heads/main` — **Verified OK** — and the SHA256 of
  > those verified artifacts is what the Dockerfile now pins.
  >
  > Two halves, because they answer different questions. The in-build `sha256sum -c`
  > is deterministic and needs no network: it fails the build rather than baking in
  > whatever was served. `scripts/verify-opengrep.sh` runs in CI and checks
  > *provenance* — a pinned digest is only as trustworthy as the download that
  > produced it — and asserts the pin matches the artifact actually signed, because
  > pinning one artifact while verifying another proves nothing.
  >
  > **Verified the check can fail:** a deliberately wrong digest fails the build with
  > `sha256sum: WARNING: 1 of 1 computed checksums did NOT match`.
  >
  > Corroboration worth recording: the arm64 binary in the **already-published**
  > image matches the signed upstream artifact byte for byte.
- [x] **15.3** **Cache between runs.** ✅ **DONE 2026-09-05.**

  > Every build now uses `--cache-from/--cache-to type=gha`, so layers are shared
  > across jobs *and* across runs. Kept as independent builds rather than one build
  > passing a tarball between jobs: a 576MB artifact uploaded and downloaded twice
  > costs more than a cached rebuild, and the jobs stay independently runnable.
- [x] **15.4** Measure what each Scanner contributes. ✅ **DONE 2026-09-05, and the
  measurement found a defect rather than a trade-off.**

  > | layer | MB |
  > |---|---|
  > | Checkov pip install | 163 |
  > | Trivy | 156 |
  > | Syft | 81 |
  > | osv-scanner | 51 |
  > | **Opengrep — binary A** | **50** |
  > | **Opengrep — binary B** | **48** |
  > | **Opengrep — the copy** | **50** |
  > | Python build deps | 43 |
  > | Gitleaks | 22 |
  >
  > **Opengrep appeared three times.** Both architectures' binaries were `ADD`ed and
  > the unused one deleted — but layers are additive, so `rm` reclaims nothing. Every
  > image carried ~148MB of layers for a 50MB tool, including a binary that could
  > never run on it.
  >
  > Restructured into per-architecture stages selected by `FROM
  > opengrep-${TARGETARCH}`, so only the needed binary is ever fetched. **674MB →
  > 576MB uncompressed, a 98MB saving**, with the scan output unchanged: 74 findings,
  > complete, every Scanner contributing. Verified on both architectures — and
  > because the two binaries have different digests, the checksum check passing *is*
  > the proof that the right one was selected.
  >
  > Checkov is still the largest single item, which is the trade 12a.3 already made
  > deliberately.

**Exit:** ✅ **Reached 2026-09-05.** Every input is pinned by content, the Opengrep
binaries are signature-verified as well as digest-pinned, builds share a layer cache,
and the image is 98MB smaller for shipping only what it can run. Three commit-time
tests guard it: bases pinned by digest, digests actually checked rather than merely
declared, and the per-architecture selection still in place.

**Commit:** `build: pin and verify every input to the image`

---

## Phase 16 — Operations

**Goal:** the things that only break once someone else is using it.

> **Reordered 2026-09-05, after reviewing the phase against what Phases 13–15
> actually built.** Both original tasks survive, one of them re-scoped, but neither
> was the most important thing here — and one of my justifications for them was
> false.
>
> **16.1 overstated its risk.** I wrote that concurrent scans "corrupt `state.json`".
> Measured: two concurrent scans, then two more on different Profiles, left every
> artifact **valid JSON and internally consistent**. The real defect is a *lost
> update*, which is quieter and still wrong.
>
> **16.2's justification was partly false.** It claimed `docs/RELEASING.md` and *two*
> issue templates tell people to run `valvur --version`. It is **one** issue
> template; `RELEASING.md` never mentions it. The task stands — the command still does
> not exist — but a task list that overstates its own evidence is the thing this
> project keeps finding in other people's documentation.
>
> **And the phase was missing the most consequential gap entirely:** Phase 14's
> verdict never reached the MCP surface, which ADR-0015 makes the *primary*
> interface.

- [x] **16.1** **The MCP surface must carry the `inconclusive` verdict.** *(F9.9,
  ADR-0015.)* ✅ **DONE 2026-09-05.**

  > `_staleness_note()` in `operations.py`, reaching all three surfaces an agent
  > touches: the summary returned when a background scan finishes, `list_findings`,
  > and `scan_status`. It gives the age, the consequence and the command — not just
  > the label.
  >
  > **Two different claims, kept different.** Nothing found: *"that is NOT evidence
  > there is nothing"*. Findings present: *"the list is incomplete"*. What was found
  > is real however old the data; only absence needs current data to mean anything.
  >
  > `scan_status` also explains itself now. `inconclusive` beside `complete: True` and
  > seven healthy Scanners reads as a contradiction; it is not one, and the line says
  > so — every Scanner ran, and the data was too old for a nil result to be evidence.
  >
  > Mutation-tested: suppressing the note fails three tests. Paired with a
  > fresh-database case on every tool, because a caveat on every response is one an
  > agent learns to skip.

  Phase 14 taught valvur to say "we found nothing, and our data was too old for that
  to be evidence". It taught the CLI, `SUMMARY.md` and `run.json`. It did not teach
  the surface that reaches an agent's context with no file in between.

  **Measured 2026-09-05** against a scan with a 60-day-old database:

  | tool | what an agent is told |
  |---|---|
  | `list_findings` | *"No findings match. The scan itself may still have been incomplete — check `scan_status`."* |
  | `scan_status` | `status: inconclusive` · `complete: True` · every Scanner `ok` |

  The first points at the **wrong reason** — the scan was complete; it was
  inconclusive — and never uses the word. The second is accurate and reads as
  self-contradictory: an inconclusive verdict beside a complete run and seven healthy
  Scanners, with nothing saying the database is two months old.

  This is the defect Phase 14 exists to remove, still live on the surface where it
  costs most. An agent that reads "no findings match" stops looking, and unlike a
  human it will not glance at `SUMMARY.md` for a caveat it was not told to expect.

  > **Cycle:** an `inconclusive` scan must make every MCP tool say so, in its own
  > words, with the age and the consequence. Paired with a fresh-database scan that
  > says none of it — a caveat on every response is a caveat agents learn to skip.

- [x] **16.2** **Interrupting a scan must actually stop it.** ✅ **DONE 2026-09-05.**

  > Every container now carries a unique `--name`, one `_launch()` helper registers
  > and forgets them so no call site can omit it, and `kill_running()` stops whatever
  > is live. Measured end to end: **2 containers running → 0 after SIGINT**, exit
  > code **130**, and no Results Folder written.
  >
  > **Interruption is its own outcome**, as decided. Exiting happens long before
  > `results.write()`, so a cancelled scan cannot be mistaken for a failed one — "a
  > Scanner produced no report" stays reserved for a Scanner that actually failed.
  >
  > Three tests, mutation-verified: removing `--name` from the launch path fails the
  > one asserting every Scanner carries a handle. The registry is also asserted to
  > empty itself, because a registry that only grows makes an interrupt try to kill
  > containers that exited long ago — noise that hides the ones genuinely running.

  **Measured:** `SIGINT` to a running scan leaves the Scanner container
  **running to completion** — `Up 9 seconds` after the shim had exited — with the
  host scratch directory alive for that window. There is no signal handling
  anywhere: `subprocess.run` with no cleanup, inside a `ThreadPoolExecutor`.

  Both self-clean once the container finishes, so this is a window rather than a
  permanent leak. It is still wrong twice over: the developer cancelled and the
  machine kept working, and Phase 11's scratch-removal test — which exists because
  raw Scanner output carries live credentials (F5.7) — only covers a scan that was
  allowed to finish.

  > ✅ **DECIDED 2026-09-05: kill the containers.** Ctrl-C means "stop" to the person
  > pressing it, and the scratch window is where raw output with live credentials
  > sits.
  >
  > **What the measurements constrain.** `docker run` does **not** stop the container
  > on SIGINT — nor when the CLI is SIGKILLed, because the daemon owns the lifecycle.
  > So letting signals propagate is not an available design. `docker kill` by name
  > takes **0.24s**, but valvur passes no `--name` and no `--cidfile`, so today there
  > is no handle at all. The work is therefore: a unique name per invocation, a
  > registry of live containers, and a handler that kills them.
  >
  > **The hazard to design around.** "A Scanner produced no report" is already a
  > failure path (Phase 3). A killed container must be distinguishable from a crashed
  > one, or interrupting a scan produces a run marked *incomplete* — a confident wrong
  > answer of exactly the kind this project keeps removing. **Interruption is its own
  > outcome: not failure, not success.** No Results Folder is written.

- [x] **16.3** **One writer per Results Folder — and per database cache.**
  ✅ **DONE 2026-09-05.**

  > `locking.py`, `flock`, two locks taken in a fixed order so scans cannot deadlock.
  > The Workspace lock is **exclusive and fails fast**; the cache lock is **shared for
  > readers and exclusive for `update`**, which waits — mutual exclusion there would
  > serialise unrelated scans for no reason.
  >
  > **The cache hazard could not be reproduced, which is not the same as disproved.**
  > A scan racing a rewrite completed cleanly with all 37 Trivy findings — but Trivy's
  > read takes 0.6s while an update spends most of its time downloading, so the write
  > window probably never overlapped. Implemented anyway: the lock is cheap, and
  > "I could not make it fail" is weak evidence for a 1.35GB file being rewritten
  > under live readers with no lock of Trivy's own.
  >
  > **Two things fell out of it.** A refusal is an expected condition, so the CLI
  > catches `Busy` and prints one line instead of a traceback that reads as a bug in
  > valvur. And taking the Workspace lock creates the Results Folder before a scan has
  > produced anything — so `.gitignore` is now written at *creation*, because
  > ADR-0011 is a guarantee about the folder and an interrupted run (routine since
  > 16.2) would otherwise leave one git can see.
  >
  > Seven tests. `os.fork` is explicitly not used to test exclusion: flock belongs to
  > the open file description, which a fork inherits, so the child holds the same lock
  > and every assertion passes vacuously. Found the hard way.

  `jobs.py` holds a `threading.Lock`, which is in-process only. Two CLI runs, or a
  CLI run alongside the MCP server, are unguarded.

  **What actually goes wrong, measured rather than assumed:** not corruption. Both
  scans read the same `state.json`, both write their own, and the last one wins — so
  the next run computes its new/fixed/regressed diff against a view that never
  happened. That is the one artifact a developer trusts to say whether they made
  progress, and it fails silently. A mixed Results Folder is also possible, because
  `results.write()` writes several files sequentially and `rawoutput.write()` clears
  `raw/` first — but it needs unlucky timing, and two attempts did not produce it.

  > ✅ **DECIDED 2026-09-05: one module, two locks, different contention policies.**
  >
  > | resource | lock | on contention |
  > |---|---|---|
  > | Workspace | `.security-scan/.lock` | **fail fast** — `jobs.py` already says "a scan is already running here" |
  > | Database cache | `~/.cache/valvur/.lock` | **block** — erroring because a pre-commit hook is refreshing would be worse than waiting |
  >
  > The differing policies are the argument for one module rather than one policy.
  >
  > **`fcntl.flock` on a lockfile**, because the kernel releases it when the process
  > dies — a crashed scan leaves no stale lock to reap, which a PID file would.
  > POSIX-only, which task 13.3 already made acceptable by scoping Windows to WSL2.
  >
  > **Phase 14 raised this risk, and it was my doing.** Adding `valvur update
  > --if-stale` and recommending it for pre-commit hooks and cron made update-vs-scan
  > far more likely than when this task was written. Measured: Trivy takes **no lock
  > of its own** — there is no lock file in the cache — and `trivy.db` is a 1.35GB
  > BoltDB rewritten under live readers.
  >
  > **Measure before assuming the worst:** whether a concurrent rewrite corrupts a
  > reader or Trivy simply fails cleanly. If it fails cleanly the cache lock is a UX
  > improvement rather than a correctness fix, and the fail-fast/block split above may
  > want revisiting.

- [x] **16.4** **`valvur --version`.** *(Was 16.2.)* ✅ **DONE 2026-09-05.**

  > Reports the shim's version, derived from the one source 12a.2 established. The
  > image's version is checked against it at scan time (F1.9), so the two cannot
  > silently diverge.
  >
  > **Generalised rather than just fixed.** valvur has now shipped *two* documented
  > commands that did not run — the verification one-liner found in 11.0 and this
  > one. A test now extracts every `` `valvur …` `` command named in the README,
  > `CONTRIBUTING.md`, `docs/RELEASING.md` and the issue templates, and asserts each
  > appears in `--help`. Verified it catches a gap by documenting a command that does
  > not exist. Documentation naming a command that does not run is worse than no
  > documentation: it is the first thing a sceptical reader tries.

**Exit:** an agent cannot mistake an inconclusive scan for a clean one; Ctrl-C stops
the work; concurrent use cannot silently spoil the status diff or the database; and
every command the documentation names exists.

**Commit:** `fix: the operational edges that only appear with a second user`

---

## Phase 17 — Traceability and seams

**Goal:** the claims the spec makes about itself are true. Before v1.0.0, not after.

> **Reviewed and rewritten 2026-09-05, after Phases 13–16.** Two of the four original
> premises were wrong, and the phase was auditing the only direction that had not
> drifted.
>
> **The count was overstated: 31, not 40.** The original measurement looked at `src/`
> and `tests/` only. Nine more — `F10.3`, `F7.8`, `F7.15`, `F6.7`, `N2.5`, `P1`, `P3`,
> `P5`, `P6` — are cited in CI workflows, scripts or docs.
>
> **17.4 was simply wrong.** It claimed nothing reads `fp_version`.
> [`state.py`](../../../src/valvur/state.py) reads it and discards all history when it
> changes, deliberately and with a comment explaining why. The real gap is narrower
> and different, and the task is rewritten rather than tightened.
>
> **17.3's wider suspicion did not survive testing.** `results.py` reads `ScanRun`
> almost entirely through `getattr(run, …, default)`, which looked like it would make
> a renamed field silent. It does not: renaming one fails **29 tests**. A latent
> hazard and poor style for a dataclass in the same package, but not an active defect,
> and not to be conflated with the real one.
>
> **And the phase was missing the hole that matters.** See 17.0.

- [x] **17.0** **Reconcile the spec with the code.** ✅ **DONE 2026-09-05.**

  > **Nine requirements appended — 127 IDs to 136.** Appended, never renumbered (§9).
  >
  > | ID | behaviour |
  > |---|---|
  > | F1.11 | interruption is a third outcome: containers stopped, no Results Folder, not a failure |
  > | F1.12 | one **Scan Run** per **Workspace**, refused with a reason |
  > | F6.11 | database age read from the data, not the file's mtime |
  > | F7.16 | `findings` / `clean` / **`inconclusive`** |
  > | F7.17 | `run.json` records the database's age, staleness and threshold |
  > | F7.18 | the Results Folder is self-ignoring from creation, not from success |
  > | F10.7 | published for both architectures; CI tests the published artifact |
  > | F10.8 | refreshing is explicit and a no-op when current |
  > | N2.6 | writes to the database cache are serialised against readers |
  >
  > `design.md` gained §6a (freshness and the third status), §6b (concurrency and
  > interruption) and §6c (distribution) — it had **zero** mentions of `inconclusive`
  > or `lock` before. `CHANGELOG.md` now carries the contract change, which was
  > missing: anything parsing `status` and reading "not `findings`" as "safe" breaks
  > on `inconclusive`.
  >
  > **All nine are cited in code or tests**, so the drift is closed at the source
  > rather than only documented. The 31 pre-existing uncited IDs are unchanged and
  > remain 17.2's problem.
  >
  > **What I would now decide differently**, as the task asked — recording these
  > rather than rubber-stamping what the code happens to do:
  >
  > - **The `.lock` lives inside the Results Folder**, which forces that folder into
  >   existence before a scan has produced anything. Locking outside the Workspace
  >   (keyed by a hash of its path) would avoid it, at the cost of not excluding two
  >   *different users* on a shared machine. I took the simpler option and paid for it
  >   with F7.18; a shared build agent might want the other.
  > - **F1.12 fails fast rather than waiting.** It matches `jobs.py`, but a developer
  >   who fires two scans probably wants the second to queue. Worth revisiting if
  >   anyone hits it.
  > - **Seven days will feel aggressive to someone scanning weekly** — they will see
  >   the warning most times. That is arguably correct and arguably nagging; it needs a
  >   real user before it can be judged.
  > - **`inconclusive` is a breaking change to the results contract**, made while the
  >   package is private and effectively unused. If it had shipped six months later it
  >   would have needed a schema bump instead.

  **Measured 2026-09-05: five behaviours built in Phases 13–16 have no requirement ID
  and no design description.**

  | built | requirement | `design.md` |
  |---|---|---|
  | `inconclusive` status | — | 0 mentions |
  | database staleness, `--if-stale` | — | — |
  | multi-arch publication | — | — |
  | interruption semantics | — | — |
  | workspace and cache locking | — | 0 mentions |

  No requirement mentions the status vocabulary **at all** — not even `clean`. The
  results contract lives in [CLAUDE.md §7](../../../CLAUDE.md) and in the code, but
  not in `requirements.md`.

  17.2 proposes a check that every requirement appears in the code, which enforces
  **requirement → code**. The direction actually drifting is **code → requirement**,
  and it drifted faster than the audit would have fixed it: five unrequirement'd
  behaviours were added across four phases while this task waited to fix citations of
  the older ones. *"Spec-driven"* is currently untrue for the most recent quarter of
  the work, and the phase as written would not have noticed.

  > **This is a spec-writing task, and the easy way to do it badly is to invent
  > requirements that match whatever the code happens to do.** Record what exists,
  > and mark anything that would now be decided differently — the reconciliation is
  > worth nothing if it only rubber-stamps.
  >
  > **Requirement IDs are load-bearing and must never be renumbered** (§9), so new
  > ones append: a new group for behaviour that has none, and extensions to F7 for the
  > results-contract changes. Where a decision already lives in an ADR, cite it rather
  > than restating it.

- [x] **17.1** Audit the not-cuttable set. ✅ **DONE 2026-09-05.**

  > `tests/test_not_cuttable.py` — six tests for the negative requirements nobody had
  > written, because it is easy to test that a thing happens and awkward to test that
  > a thing never does. Awkward is not unnecessary: a negative requirement with no
  > test is a promise nobody is keeping.
  >
  > **F9.4 now has one**, along with F1.7 (no credential is read), F1.8 (no
  > telemetry) and F1.10 (no cloud-specific branch). Mutation-tested by planting the
  > defect each forbids — a `watchdog` import, a runtime dependency, and a
  > `VALVUR_API_TOKEN` read all fail the right test. F5.3, F1.2 and F1.11 were
  > already covered by tests that never named them; they cite the ID now, so the
  > claim and the check are connected.
  >
  > **Sixteen of seventeen IDs in the set are now cited. The seventeenth is not
  > implemented at all** — F1.6, SELinux labelling, has no `:z` or `:Z` anywhere.
  > Measured: Podman's Fedora VM is `Enforcing` and a full scan through it succeeded
  > with 74 findings and no failures, identical to Docker, with no label applied —
  > host directories reach that VM through virtiofs. **A native RHEL or Fedora host is
  > untested and is the target market.** Recorded against the requirement itself with
  > the evidence, because could-not-reproduce is not the same as does-not-happen, and
  > leaving an unmet requirement unmentioned is the one option that is not honest.

  > **`F9.4` still has no test**, while the Traceability section states *"Each is a
  > test that fails the build if broken."* That sentence remains false, and it is the
  > one a reviewer checks first. There is also no watching code, so the requirement
  > holds in fact — it simply is not enforced, and nothing would fail if someone added
  > a watcher tomorrow.

- [x] **17.2** A CI check that requirements and code stay in step — **in both
  directions.** ✅ **DONE 2026-09-05.**

  > `scripts/check_traceability.py`, in CI. **Requirement → code** finds an ID nobody
  > implemented. **Code → requirement** is approximated by requiring every ADR to cite
  > at least one requirement — decisions land in ADRs before they land in code, so
  > that is where the drift becomes visible earliest.
  >
  > **Both are ratchets against a recorded baseline** (`docs/traceability-baseline.toml`).
  > Neither fails on today's debt; both fail the moment it grows, and the check tells
  > you when the baseline could shrink. A check that fails on day one is a check
  > somebody disables in week two.
  >
  > Baseline today: **25 uncited requirements** — down from 31, because 17.1's
  > citations landed — and **8 ADRs citing no requirement**. Verified in both
  > directions by planting each: a new requirement nobody implements, and a new ADR
  > citing nothing.
  >
  > **Its first run was wrong and said so loudly.** The baseline file lists exactly
  > the uncited IDs, so scanning `docs/` counted it as a citation and reported 25
  > requirements resolving simultaneously. `requirements.md` was already excluded for
  > the same reason; the file being written needed excluding too. Requirement → code catches an ID nobody implemented; code → requirement
  is the direction that drifted, and needs a convention to check against (every ADR
  and every user-visible behaviour cites an ID, say). **31** IDs are uncited today;
  the check should start from that baseline rather than fail the build on day one.

- [x] **17.3** **Promote `applies_to` to the `ScannerAdapter` protocol.**
  ✅ **DONE 2026-09-05.**

  > On the protocol with a default, and every adapter — including the four test stubs
  > — now implements `ScannerAdapter` explicitly rather than structurally. The
  > orchestrator calls it unconditionally, so an adapter cannot forget to be asked.
  >
  > **It does not do what I claimed, and the comment saying so is corrected.** I wrote
  > that a misspelled override would become "a type error". It does not: mypy sees an
  > extra method plus an inherited default and is content. Verified by misspelling it
  > — **mypy passes, the test fails.** The protocol removes one failure mode, not
  > both, and the code now says which.
  >
  > **`artifact` was promoted too, and reverted.** Same seam by appearance, different
  > by mechanism: a Protocol's *method body* is inherited by an explicit subclass, an
  > annotated class attribute's *default* is not — so every adapter without one raised
  > `AttributeError` and 96 tests failed. It stays a `getattr`, with a note in
  > `base.py` explaining why the two hooks are treated differently. Symmetry was the
  > wrong instinct.

  > Note, but do **not** fold in, the defensive `getattr` over `ScanRun` in
  > `results.py`. Tested 2026-09-05: renaming a field fails 29 tests, so it is a style
  > problem and a latent risk for a *removed* field, not a live defect. Conflating
  > them would inflate a real finding with a speculative one.

- [x] **17.4** **Say when `fp_version` changes.** ✅ **DONE 2026-09-05.**

  > `state.load()` already discarded history correctly; it now records *why*, and
  > `SUMMARY.md` and `run.json` say so. The wording matters: **"this is not a
  > regression — nothing got worse"**, plus a warning that committed suppressions
  > keyed on the old identities have stopped matching too, which is the part a
  > developer would otherwise discover much later.
  >
  > **My first test for it was vacuous and the mutation caught it.** It constructed
  > `ScanRun(identity_reset=…)` directly, so it exercised the reporting and not the
  > detection — removing the detection entirely left all 15 tests green. The test now
  > goes through `state.load()`, and the same mutation fails it. Exactly the trap
  > CONTRIBUTING warns about, walked into while implementing the phase about
  > traceability.

  `state.py` already reads it and starts clean when it moves, which is correct. It
  does so **silently**: every finding reappears as `new`, every previous `fixed`
  vanishes, and committed suppressions stop matching — with no explanation in
  `SUMMARY.md`, `run.json` or the terminal.

  A developer sees a scan that looks like a catastrophic regression and has nothing to
  tell them it was an identity change. That is the same class as everything Phase 14
  removed: a confident output whose meaning silently changed.

**Exit:** the spec describes the product that exists; every not-cuttable requirement
is a failing test when broken; and no described mechanism is inert or silent.

**Commit:** `docs: make the spec describe the product, and the claims true`

---

## Traceability

The not-cuttable set from `requirements.md` maps to: F1 → Phase 8 · N2.1 → Phase 11
cycle 1 · F5.3 → Phase 2 cycles 1–3 · F7.2 → Phase 1 cycles 4–5 · F9.2 → Phase 9
cycle 4 · F9.4 → Phase 9 cycle 5. Each is a test that fails the build if broken.

> ⚠️ **That last sentence is currently false, found 2026-09-05.** **F9.4** — no
> watchers, no save hooks, no scan started other than by explicit invocation — has no
> test at all. There is also no watching code, so the requirement holds in fact; it
> simply is not *enforced*, and nothing would fail if someone added a watcher
> tomorrow. [Phase 17](#phase-17--traceability-and-seams) fixes the claim and the
> gap. Recorded here rather than quietly corrected, because a traceability section
> that has been wrong once is worth reading sceptically.
