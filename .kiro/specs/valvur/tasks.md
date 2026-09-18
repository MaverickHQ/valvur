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
> `<aws-account-id>.dkr.ecr.eu-north-1.amazonaws.com/valvur` · first commit `cc67403`, signed and verified.

**Goal:** every account, credential, runtime and tool the plan depends on is verified
working *before* any code exists. No implementation.

Recon performed 2026-08-30 on the target machine; re-verify each line, since these
drift.

### Local environment

- [x] **0.1** Start the Docker daemon and confirm `docker info` succeeds.  
  **STATUS 2026-08-30:** ✅ Docker 29.2.1 daemon running
  *(Recon: Docker 29.2.1 installed, daemon was not running.)*
- [x] **0.2** *(Optional in this phase)* Install Podman.  
  **STATUS 2026-09-10:** ✅ **podman 6.0.2**, machine running. The dual-runtime claim
  is kept rather than downgraded: five parity tests in `tests/test_runtimes.py` run
  against it, and task 17.1 used it to test valvur under **enforcing SELinux** — the
  one environment reachable from this machine where F1.6 could be exercised at all.
  The original *(Recon: not installed.)* note stood for six weeks after it stopped
  being true.
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
  **STATUS 2026-08-30:** ✅ commit `cc67403` — *Good git signature for MaverickHQ*, registered as a GitHub signing key.
  it is signed.

### GitHub

**GitHub only.** GitLab is out of scope; the image is published to GHCR, and to ECR
for AWS execution.

- [x] **0.13** Create the repository — private initially — and push. `gh` is already  
  **STATUS 2026-08-30:** ✅ https://github.com/MaverickHQ/valvur (private), `origin` set
  authenticated as MaverickHQ. This also **reserves the name** while changing it is
  still free.
- [x] **0.14** Enable branch protection on `main`: require a passing CI check, and    
  **STATUS 2026-09-13:** ✅ **Done, the morning the repository went public.** Five required checks (every `ci.yml` job), signed commits required, linear history, no force-push or deletion, **enforced for administrators** — so every change since, this one included, arrives by pull request and lands on `main` only after the five checks pass. GitHub's merge button creates merge commits, which linear history forbids, so a PR lands by fast-forwarding `main` to its checked, signed head. Applied with two API calls; recorded under 23.1.1.
  **STATUS 2026-08-30:** ⏳ **DEFERRED to Phase 12.** GitHub returns 403 — branch protection on *private* repos needs GitHub Pro. It becomes free when the repo goes public at release, and it guards nothing on a solo private repo. Re-attempt immediately after [12a.1](#12a--make-it-obtainable-and-trustworthy) makes the repo public. *(Corrected 2026-09-10: this said "re-attempt at 12.5", a task number that stopped existing when Phase 12 split into 12a/12b.)*
  require signed commits.
- [x] **0.15** Verify you can push a package to GHCR under this account, so the    
  **STATUS 2026-08-30:** ✅ `docker login ghcr.io` succeeded with the refreshed `write:packages` scope.
  container publishing path is proven before it is needed.

### AWS

- [x] **0.16** Confirm STS identity. *(Verified: account `<aws-account-id>`, IAM user  
  **STATUS 2026-08-30:** ✅ account <aws-account-id>, IAM user <iam-user>
  `<iam-user>`.)*
- [x] **0.17** Verify that identity can create an ECR repository and push to it. It is  
  **STATUS 2026-08-30:** ✅ simulate-principal-policy: CreateRepository, InitiateLayerUpload, PutImage, GetAuthorizationToken all **allowed**
  an IAM **user**, not a role — check the policy rather than assuming.
- [x] **0.18** Create the ECR repository with immutable tags and scan-on-push.  
  **STATUS 2026-08-30:** ✅ <aws-account-id>.dkr.ecr.eu-north-1.amazonaws.com/valvur — IMMUTABLE tags, scan-on-push
- [x] **0.19** Decide whether a dedicated least-privilege publishing role replaces the    
  **STATUS 2026-08-30:** ✅ **DECIDED 2026-08-30: keep `<iam-user>` for now.** Its ECR permissions are verified sufficient. Revisit only if the account gains other users or the image is published from CI rather than from Harvey's machine.
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
- [x] **1.12** **MOVED to Phase 10 (task 10.0) on 2026-08-30**, at Harvey's request.  
  **CLOSED 2026-09-10:** ✅ superseded — [10.0](#100--pre-release-publish) completed on
  2026-08-31 and `0.1.0rc1` was published. This entry stayed open as a pointer to work
  that had already moved and finished, which made the count of remaining tasks wrong.
  The *gate* it once referred to is [10.1](#101--the-usability-gate), still open.
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
>
> ⚠️ **This phase was complete for what it tested, and one requirement it names was
> not.** F1.6 — SELinux mount labelling — had never been implemented, and this note
> read as though every runtime-portability requirement was finished on 2026-08-30.
> It was found on 2026-09-05 (task 17.1) and closed on 2026-09-10 by
> [Phase 20](#phase-20--close-phase-8-runtime-portability-debt), which reproduced it on
> a native enforcing host: **all three of valvur's mounts were denied**, and valvur was
> unusable on its primary target platform. The fourth silent failure of the set, found
> six weeks after the phase that should have caught it.

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

- [x] **10.2.5** Verify the copy-pasteable `CLAUDE.md` / `AGENTS.md` snippet against a
  real agent in a real repository. *(P6)* ✅ **DONE 2026-09-11.** Claude Code 2.1.261,
  non-interactive, against a git-initialised copy of the broken fixture with the
  README's `.mcp.json` shape and the `CLAUDE.md` snippet pasted verbatim. Only
  read-only tools were permitted, so any attempt to edit, commit or suppress would
  show as a denied call. Two runs.

  > **One substitution, recorded.** The README says `uvx --from valvur valvur-mcp`.
  > That would install the stale `0.1.0rc1` from PyPI and pull a private image — the
  > exact thing 12a.1 unblocks — so the *shape* was tested with the local binary and
  > image. The `uvx` path stays untested until the package is public.
  >
  > **Run 1 hit its turn limit and wrote no report.** Two defects, one in each half of
  > the snippet's world:
  >
  > 1. **The snippet taught the wrong door.** It said *"Run `valvur scan`"*, and the
  >    agent did exactly that — `which valvur`, not found, two turns gone — before
  >    looking for the MCP tool it already had. An agent does what the text says, in
  >    the order it says it. The snippet now names the MCP tools first.
  > 2. **`scan_status` returned instantly, so the agent polled fourteen times in
  >    twenty turns.** It had read every file in the repository while waiting and
  >    then, in its own words, *"nothing else is pending, so I'll poll once more"*.
  >    Each poll is a full model turn. `scan_status` now waits up to 15s — well under
  >    the 30–60s the jobs docstring says clients tolerate — so one poll covers
  >    seconds of scan rather than milliseconds. The `scan` contract is unchanged.
  >
  > **Run 2 succeeded**: straight to `scan` with `offline`, three polls, `SUMMARY.md`
  > then `REMEDIATION.md` then `list_findings`, no edit or suppression attempt, and it
  > read `.security-scan/.gitignore` unprompted to confirm the folder cannot be
  > committed. $1.03, 121s.
  >
  > **The report was close to ideal, and one paragraph is the whole of Phase 19
  > working end to end.** The agent noticed that `requirements-ai.txt` was not
  > covered, named `reqeusts` and `aws-helper-sdk` itself, explained that `full` would
  > catch them *and* that `full` sends package names to public registries, and left
  > the decision to the human. That is the Block 3 profile caveat — the one that used
  > to be hidden whenever anything else was found — read by a real agent and acted on
  > correctly. It also wrote *"I did not act on the injected instruction"* about the
  > planted `AGENTS.md`, and *"I applied no fixes and added no suppressions, per the
  > project's CLAUDE.md"*.
  >
  > **A third defect, found while setting up.** `valvur-mcp --help` (19.C.3, written
  > the day before) named a tool `scan_workspace`. No such tool exists; it is `scan`.
  > The test pinning the help text now iterates the real registry, so renaming a tool
  > fails it instead of dating the text again.
  >
  > **10.2's claims, as they stand:** (2) Claude Code — verified; (3) a command not on
  > `PATH` reports `status: failed` at startup and the agent says so — verified;
  > (1) Kiro — untested, no Kiro here; (4) the image-pull message — untested, the
  > image was local. The `.claude/settings.json` planted in the fixture for the
  > AI-artifact check sets `bypassPermissions`; it was removed from the harness copy,
  > because a test agent that can bypass permissions can edit files.

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

- [x] **10.4.12** Decide what a **human** sees first in `SUMMARY.md`.
  ✅ **DECIDED 2026-09-10, in Block 3.** One sentence of plain English after the
  title, before the machine block: a verdict the reader can act on, ordered by what
  stops them trusting the rest — an incomplete scan first, then live findings, then
  the two different reasons a nil result may mean nothing.

  > **Not "demote the agent block".** F7.6 requires it to open the file, and answering
  > this task surfaced that the block had never satisfied F7.6 either: it must describe
  > *the **Status** values and the ranking basis* and did neither. So the answer was to
  > **complete it** and put the human sentence above it. An agent still meets every
  > constraint before any **Finding**, which is what F7.7 states and protects.

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

- [x] **12a.1** **Push, then make the repository public, then the package.**
  *(F1.5, blocks 10.1 and 10.2)* — **owner action.** ✅ **Done 2026-09-13**: the
  repository by API (after the sweep and history rewrite below), then the `valvur`
  and `valvur-index` packages by the owner's click — anonymous API `200`, anonymous
  GHCR tokens issued for both. The full account is under 23.1.1.

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

  > **Pre-public sweep, 2026-09-13.** gitleaks over all 155 commits: clean. A read
  > of the tree found the AWS account ID, the IAM user name and the ECR registry
  > host recorded in this file's Phase 0 notes since the second commit — not
  > credentials, but an account ID beside a username is more than a public
  > repository needs to carry. **History was rewritten** (`git filter-repo
  > --replace-text`, the two strings → `<aws-account-id>` and `<iam-user>`), every
  > one of the 155 commits re-signed with the same SSH key with its dates preserved
  > (`git rebase --root -f --committer-date-is-author-date`; GitHub shows the new
  > head verified), `v0.1.0rc1` recreated as a signed annotated tag on the rewritten
  > rc commit with its original tagger date, and `main` and the tag force-pushed.
  > The tree is byte-identical to the old head except the five redacted lines
  > (`diff -r` over `git archive` of both). A mirror and a bundle of the old
  > history are at `/private/tmp/valvur-tests/backup-before-rewrite-20260913.*`.
  > Two things this does not do: GitHub keeps the old objects until it garbage
  > collects, and the three closed Dependabot branches (#1–#3) still point at old
  > commits — deleting those branches is the owner's click; and the Rekor entries
  > from the rehearsals and the index workflow name the old SHAs forever, which is
  > what a transparency log is for.

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
  - [x] **Enable GitHub private vulnerability reporting** — ✅ **Done 2026-09-13**,
        by API with the rest of Block 1 (21.A.3); this box was left unticked and
        found on 2026-09-17, when `GET /repos/MaverickHQ/valvur/private-vulnerability-reporting`
        answered `{"enabled": true}`. Was: ⚠️ owner action, same category as 12a.1.
        `SECURITY.md` points at `/security/advisories/new`, and until the setting
        was on, that link 404ed. A disclosure route that does not exist is the
        security-tool equivalent of a verification command that does not run —
        which is exactly what 11.0 found.
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

- [x] **12a.7** **Automate the release, and publish `0.2.0`.** *(F10.3)*
  ✅ **Automation done 2026-09-05. Published 2026-09-13** — `v0.2.0` tagged on
  `fc5a221`, the exact commit rehearsal #7 had passed end to end an hour earlier;
  `ghcr.io/maverickhq/valvur:0.2.0` for both architectures, signed and attested,
  `valvur 0.2.0` on pypi.org, the GitHub release with wheel, sdist, both SBOMs and
  the publish attestations. What the rehearsals found on the way is under 23.1.1.

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

## Execution order for Phases 19–21 — run in blocks, not one task at a time

> **Added 2026-09-10.** The three remaining phases hold **33 open tasks**. Run
> sequentially they are 33 review cycles; grouped by the files they touch and the
> decisions they share, **27 of them collapse into 7 blocks**. The remaining 6 are
> genuinely serial or wait on a person, a host, or an artifact that does not exist yet.
>
> **This regrouping is a reading order, not a renumbering.** Every task keeps its ID
> and its own text, which stays authoritative where the two disagree.
>
> **It produced one real re-sequencing:** 19.F.1 and 19.F.2 move to the **front**.
> They sit last in Phase 19's own ordering, but 19.F.1 says *"before implementing
> fixes"* and is right — run last the corpus only verifies; run first it also says
> which of the other blocks are worth doing.

```
Block 0  corpus staging   ─┐
Block 1  build + release  ─┼─ share no files; any order, or all three at once
Block 5  SELinux          ─┘   (5 whenever an enforcing host exists)
                               ↓
                          Block 2  coverage       (rebuild the image to verify)
                               ↓
                          Block 3  status
                               ↓
                          Block 4  corpus verification  ← uses Block 0's corpus
                               ↓
                          Block 6  owner actions → the serial release tail
```

### Block 0 — Stage the corpus · 19.F.1, 19.F.2

No source changes, no commit. Copy a mixed corpus to `/private/tmp/valvur-corpus/`,
scan it, and record what today's build does. That recording is the baseline Blocks 2
and 3 are measured against, which is the reason this runs first rather than last.

### Block 1 — Build and release plumbing · 19.A.1, 19.A.2, 19.A.3, 19.B.1, 19.B.2, 19.B.3

Touches `.github/workflows/ci.yml`, `release.yml`, `pyproject.toml`, a new lockfile,
a new local verification script, and `docs/RELEASING.md`. Nothing under `src/`.

Together because **19.A.3's script is the answer to 19.A.2**: write the verification
command once, call it from both workflows, and the divergence cannot return. Doing
19.A.2 alone produces an edit that 19.A.3 overwrites. 19.B.1–19.B.3 are three edits to
those same two YAML files, proved by one CI run.

> **Measured 2026-09-10.** `ci.yml:38` lints `src tests`; `release.yml:47` lints
> `src tests scripts`. Four Python files under `scripts/` are therefore linted for the
> first time on tag day. Neither workflow declares `concurrency`. There is no
> lockfile of any kind — not `uv.lock`, not `constraints.txt`.

**Commit:** `chore: one verification path, used everywhere`

### Block 2 — Coverage: what gets inspected · 19.D.1, 19.D.2, 19.E.1 — ✅ DONE 2026-09-10

> **All four Block 2 corpus defects verified fixed on the real projects, through a
> rebuilt image.** C1: the Rust gap now appears on the default `offline` Profile with
> no network used. C4: the monorepo that reported `npm`, `npm (pnpm)` and `Python`
> reports **none** — both are genuinely covered now — and the Rust project reports
> exactly one. C6: the reported path is `Cargo.toml`, not `Cargo.lock`.
>
> **C4's fix already existed in the codebase.** `ecosystems.py` canonicalises `pnpm`
> and `yarn` to `npm`, and its docstring describes the identical bug — 24 CVEs
> reported twice because Trivy said "pnpm" where osv-scanner said "npm". 19.D.3 built
> a second table keyed on display labels right beside it. The gap table is keyed on
> the canonical name now.
>
> **A mutation that should have failed did not.** Keying the gap fingerprint on the
> display label passed all 42 tests, because the table has one entry per ecosystem so
> the *count* assertions could not tell the difference. The property they missed:
> a label is prose, and prose gets edited — "Rust (Cargo)" becoming "Rust" would
> silently invalidate every committed suppression on that gap (ADR-0003). Now pinned.
>
> **A test claimed to check something it had patched out.** The scoped-package test
> monkeypatched `_lookup` and then asserted about the URL `_lookup` builds, proving
> only that `@types/node` survived JSON parsing. Rewritten against the real URL — and
> then **measured**: `@types/node`, `@types%2Fnode` and `@types%2fnode` all return 200
> from registry.npmjs.org, so the encoding was never a live bug there. Changed anyway,
> because private mirrors are stricter and this product's users are behind them.
>
> **Left for Block 3, deliberately:** a coverage gap is a Finding, so `status` is now
> `findings` for any repository with an uncovered ecosystem. `clean` is unreachable for
> a polyglot repo. §7 already has the right word — `inconclusive` means *we looked,
> found nothing, and could not support the claim* — but deciding it here would
> pre-empt 19.C.2 and 19.E.2. A test pins today's behaviour so Block 3 has to change
> it on purpose.

Together because **19.E.1 is the general form of what 19.D.3 did by hand**. Declaring
each adapter's coverage contract before 19.D.1 widens the Dependency Reality Check
means declaring it twice. 19.D.2's two surviving `standard` strings live in
`results.py` and `checks/dependency_reality.py` — both files this block already has
open.

Closes the F3.1 gap, and clears valvur's own deliberately-red self-scan finding.

> ⚠️ **Needs an image rebuild to verify.** Checks ship inside the image (ADR-0013), so
> unit tests can pass while a real scan runs the published image's older copy. Third
> time this trap applies: 12a.6, 19.D.3, and now here.

**Commit:** `feat: the reality check covers the ecosystems people use`

### Block 3 — Status: what the result means · ✅ DONE 2026-09-10

Ran as one change because it was one decision. 19.C.2 chose the model, 19.E.2
implemented it, 19.C.1 exposed it on four surfaces, and 10.4.12 decided what a human
meets first. Split apart, the status model would have been rewritten three times.

> **10.4.12, and an unmet requirement found while answering it.** F7.6 requires the
> machine-facing block to describe *the folder, the **Status** values, the ranking
> basis, and the F9.5–F9.7 constraints*. It described the first and the last, and had
> never mentioned the middle two — so an agent reading `inconclusive` had nothing
> telling it not to report that as clean, which is the entire reason F7.16 put the
> claim in the verdict rather than in prose.
>
> The answer to *what does a human see first* is therefore not "demote the agent
> block": it is **complete it, and put one sentence of plain English above it**. F7.6's
> protection is that an agent meets the constraints before any Finding — F7.7 states
> that at the content level and it still holds.
>
> **Six mutations, all failing**, including re-gating the C3 caveat and counting
> coverage notes as active. The first attempt at running them was itself invalid: zsh
> does not word-split unquoted variables, so `pytest $FILES` passed one long filename
> and every mutation "passed" against zero tests. Caught by reading `no tests ran`
> rather than the absence of failures.

### Rider — 19.C.3

`valvur-mcp --help` / `--version`. One function; `mcp/server.py` already takes `argv`
and never reads it. No dependency in either direction — attach it to whichever block
runs first.

### Block 4 — Corpus verification · 19.F.3, 19.F.4, 19.F.5, 19.E.3 — ✅ DONE 2026-09-10

The block that could not be sized in advance, and the one that paid best. Three
defects, all false positives valvur produced on ordinary repositories, none of which
any unit test would have found — because each needed a *shape* of real project rather
than a behaviour anyone thought to write down.

> **Two of the three were introduced by Block 2, four hours earlier, with tests
> passing.** Widening the Dependency Reality Check to `pyproject.toml` immediately
> started reporting monorepo workspace members as hallucinated, and started comparing
> names against a popular-package list without PEP 503 normalisation. Neither is
> visible from a synthetic fixture; both are the first thing a real monorepo does.
>
> **The third had been latent for weeks.** `.uv-cache/` was 40% of one project's
> report. The exclusion mechanism worked perfectly and the name simply postdated the
> list — a denylist ageing quietly, which is the same silent-drift class as everything
> else this phase removed, pointed the other way.

### Block 5 — SELinux · 20.1, 20.2, 20.4 — ✅ DONE 2026-09-10

Not environment-gated after all. The block was written assuming no enforcing host was
reachable from a macOS machine; **the Podman machine already running on it is Fedora
CoreOS with SELinux enforcing**, and a workspace created on its own xfs filesystem —
rather than shared in over virtiofs — is exactly the native case F1.6 names.

> **20.3 was not taken.** It was the branch for *the defect does not reproduce*, and it
> reproduced on the first attempt, in both rootful and rootless Podman.
>
> The measurements settled three things no amount of reading would have: that valvur
> was unusable on its primary target platform; that `:Z` is incompatible with running
> Scanners concurrently; and that `restorecon -R` does not undo `:z`, which had already
> been written into the remediation text as though it did.

### Block 6 — Owner actions, one sitting · 12a.1, 0.14, 12a.7 (setup half)

All at github.com plus one push, in this order: push → repository public → package
public → branch protection → PyPI trusted publishing, the `release` environment, and
private vulnerability reporting.

### The 6 that do not group

| Task | Why it stays alone |
|---|---|
| ~~**10.2.5**~~ | ✅ Done 2026-09-11 — two real Claude Code runs; found three defects, fixed all three. |
| **10.1.1**, **10.1.2** | Need a person who has never seen valvur. Cannot be batched, cannot be simulated, and participants cannot be reused — first impressions do not reset. |
| **12a.7** (publish) → **12b.1** → **12b.2** → **12b.3** | A release ordering. Each step's input is the previous step's artifact. |

---

## Phase 19 — Reliability, release and portfolio hardening

**Goal:** remove the remaining ways valvur can look green while being ambiguous,
environment-dependent, or confusing to a first-time user. This phase is about
repeatable builds, release gates that fail in the right place, clearer operational
signals, broader AI-code coverage, and portfolio-grade polish.

> **Added 2026-09-10 from build/deploy/operations/functionality/architecture audit.**
> The repo is already strong: lint, types, traceability and non-e2e tests pass; the
> wheel builds and installs; release signing, provenance, SBOMs, redaction and
> self-scan gates exist. The work below is the next layer: make success reproducible,
> make failures explicit, and remove confusing-but-technically-true outputs.
>
> **Runs before public release.** The earlier "Everything that remains" phase mixed
> hardening and publication. That ordered the public-release actions before the
> optimisation work that should precede them. Publication now waits until Phases 19
> and 20 are complete.

### A — Build

- [x] **19.A.1** Add a committed dependency lockfile for development and build tooling.
  ✅ **DONE 2026-09-10.** `uv.lock`, 19 packages. Every CI and release job installs it
  with `uv sync --extra dev --locked`; Dependabot's `pip` entry became `uv`, because
  pointing it at `pyproject.toml` would bump the declared ranges and leave the lock —
  the thing actually installed — untouched.

  > **The risk was already realised.** The open ranges `pytest>=8` and `mypy>=1.11`
  > had floated to **pytest 9.1.1** and **mypy 2.3.1** — two major versions nobody
  > chose. Locking froze what currently works rather than preventing a future problem.
  >
  > **`--locked`, not `--frozen`.** The first version used `--frozen` and three
  > comments claimed it caught drift. It does not: both install the lock instead of
  > re-resolving, but only `--locked` *fails* when `pyproject.toml` has moved past it.
  > Measured — adding a dev dependency without re-locking passed under `--frozen` and
  > fails under `--locked`. A lockfile nothing checks is decoration.
  >
  > **`hatchling` is bounded rather than locked**, to `>=1.27,<2`. Build backends are
  > resolved outside the lock at build time, so an unqualified `hatchling` means a 2.0
  > could change the wheel this repository produces with no commit here.

- [x] **19.A.2** Align CI and release verification commands.
  ✅ **DONE 2026-09-10.** Not by aligning two lists — by deleting one. Both workflows
  now call `scripts/verify.sh`. Aligning the lists fixes the divergence until the next
  edit; sharing one file is what stops it returning.

  > The gap was real: `ci.yml` linted `src tests`, `release.yml` linted
  > `src tests scripts`, so four files under `scripts/` were first checked on tag day.
  > `pyproject.toml` already carried a `"scripts/*"` per-file-ignore — the configuration
  > for linting them had been written; the invocation never was.

- [x] **19.A.3** Add a single local verification command that mirrors CI.
  ✅ **DONE 2026-09-10.** `scripts/verify.sh` — sync from the lock, then lint, types,
  traceability, non-e2e tests and package build. Takes names for a subset
  (`./scripts/verify.sh lint types`). Redirects `UV_CACHE_DIR`, `RUFF_CACHE_DIR`,
  `MYPY_CACHE_DIR` and `XDG_CACHE_HOME` to a temp root when `$HOME` is not writable,
  and never overrides a value the caller set.

  > **Its first version passed by running nothing.** The selection helper counted its
  > own arguments, so `$#` was never 0, no check ever matched, and the script printed
  > *all checks passed* having executed zero of them. Found by reading the output
  > rather than the exit code.
  >
  > It now counts what ran and **fails when that is zero**. A verifier that can pass
  > vacuously is worse than no verifier — it is the exact defect this repository
  > exists to find, written into the tool meant to catch it.

### B — Deploy

- [x] **19.B.1** Gate published-image verification on the declared tag existing.
  ✅ **DONE 2026-09-10.** The job asked only whether the *repository* was anonymously
  pullable, then inspected `:$VERSION` regardless. A release-prep commit bumps
  `pyproject.toml` before the tag workflow pushes that version, so the moment the
  package goes public every such PR would fail on a manifest that legitimately does
  not exist yet. It now requests that specific manifest and skips with a `::notice`
  on anything but 200.

  > **Both branches exercised against real GHCR**, since the tag path could not be
  > tested on a private package: an existing tag returns 200 (verify) and a fabricated
  > one returns 404 (skip). Today, valvur's own package yields no anonymous token at
  > all, and the job warns loudly — unchanged, and still correct.

- [x] **19.B.2** Add release workflow concurrency.
  ✅ **DONE 2026-09-10.** `group: release`, **global rather than per-tag**: two
  different tags are the dangerous case, not two pushes of one. Both build `:latest`,
  so the slower workflow can leave `latest` on the older version while its signature,
  attestation and GitHub release all say otherwise.

  > `cancel-in-progress: false`, deliberately. A release cancelled between
  > `docker buildx --push` and `cosign sign` leaves an **unsigned image published under
  > a real version tag** — strictly worse than a queued job.

- [x] **19.B.3** Update release documentation to use the same build path as CI.
  ✅ **DONE 2026-09-10.** `docs/RELEASING.md` and `CONTRIBUTING.md` now use
  `docker buildx build --load` and `./scripts/verify.sh`. RELEASING held a third copy
  of the lint/type/test commands; third copies drift too.

  > **Premise corrected 2026-09-10.** This said the documented `docker build` in
  > `docs/RELEASING.md` fails because the Dockerfile relies on `TARGETARCH`. It does
  > not — **measured: plain `docker build` exits 0** and produces a working image,
  > because modern Docker enables BuildKit by default and BuildKit supplies
  > `TARGETARCH`.
  >
  > The task is still worth doing, for a different reason: the build silently depends
  > on BuildKit being on. With `DOCKER_BUILDKIT=0`, or on an older Docker, `FROM
  > opengrep-${TARGETARCH}` has nothing to resolve. Documenting `docker buildx build
  > --load` makes that dependency explicit rather than lucky, and matches what CI and
  > `release.yml` actually run.

### C — Operations

- [x] **19.C.1** Make active versus suppressed findings explicit in terminal output,
  `run.json`, and `SUMMARY.md`. ✅ **DONE 2026-09-10.** Three counts, on four surfaces
  — the MCP `scan_status` response too, which ADR-0015 makes primary and which the task
  did not name.

  > **The motivating case, measured on valvur itself.** The self-scan printed
  > `findings: 4 finding(s)`, where all four were accepted risks recorded in a
  > committed file with expiry dates. It now prints `clean: 0 active, 4 suppressed`.
  > A portfolio reviewer previously met what looked like four live failures.
  >
  > `run.json`'s `findings` is a breakdown rather than an integer:
  > `{active, suppressed, not_covered, total}`. One number made an accepted risk, a
  > live problem and a note about our own missing coverage indistinguishable to every
  > machine consumer. The MCP surface reads it with a fallback, so an older `run.json`
  > still renders.
  >
  > **Corpus defect C3 fixed.** The Profile caveat was gated on `not findings`, so one
  > missing-licence finding suppressed the notice that dependency-reality never ran —
  > the reader was told least about missing coverage exactly when there was most else
  > on screen. Now reported either way.
  >
  > **Corpus defect C2 fixed.** `scanners_not_run` reaches `SUMMARY.md` and
  > `scan_status`, not just `run.json`. And a coverage note is reported *separately*
  > from a Profile omission, because they are different claims and both can be true:
  > one says a Scanner did not run, the other says nothing here reads a whole
  > ecosystem even when it does.
  >
  > **Corpus defect C5 fixed, and it was wider than the corpus showed.** Every Finding
  > from `licence-file` *and* `ai-artifact` arrived as `unknown` severity — including
  > every AI-artifact detection, which is what this product is most distinctive for. An
  > instruction-override directive planted in `CLAUDE.md` ranked identically to a
  > missing licence file. Now stated per rule, and a structural test fails when any
  > Check reports without one.
  >
  > **The non-exfiltration disclosure was wrong.** `what_left_the_machine` still named
  > PyPI alone after 19.D.1 added the npm registry, and never mentioned osv-scanner's
  > destination at all. That sentence **is** the §3 claim, not a description of it, so
  > a registry added without amending it makes the claim false. Now enumerated exactly
  > and pinned by a test.

- [x] **19.C.2** Decide whether suppressed-only results need a distinct status.
  ✅ **DECIDED 2026-09-10: no.** Three statuses stay. `clean-with-suppressions` was
  rejected — three values are a documented contract (§7, F7.16), every consumer
  switches on them, and a fourth is a breaking change buying a count that now appears
  beside the verdict on every surface anyway.

  > `active` became the human-facing gate instead, as the task's second option
  > proposed. A suppression is a decision this project recorded in a committed file, so
  > a scan whose only Findings are accepted risks *is* clean by that project's own
  > policy — provided the count is impossible to miss, which is 19.C.1's job.

- [x] **19.C.3** Add `valvur-mcp --help` and `--version` without writing to stdout
  during normal MCP operation. ✅ **DONE 2026-09-10.** Both answer on **stdout** —
  deliberately, because a person ran the command, so the JSON-RPC channel is not in
  use. Verified that a `ping` still returns nothing but JSON-RPC.

  > No argparse. This entry point takes no options beyond these two, and a parser
  > invites adding some — every flag here is a way for a client's configuration to
  > change what the server does behind the agent's back.
  >
  > **An unrecognised flag is refused with exit 2, not ignored**, and the usage goes to
  > stderr. A flag that starts the server anyway is how a typo in an agent config
  > becomes a silent misconfiguration nobody notices for weeks.

### D — Functionality

- [x] **19.D.1** Expand the Dependency Reality Check beyond `requirements*.txt`.
  ✅ **DONE 2026-09-10.** Now reads `requirements*.txt` and `pyproject.toml` — PEP 621
  *and* Poetry, because both are everywhere and a project using the shape we skipped
  would scan clean for the wrong reason — against PyPI, and `package.json` against the
  npm registry.

  > **Direct manifests, never lockfiles.** A lockfile is a resolved transitive tree,
  > and transitive dependencies are not the ones a language model invents: the
  > hallucination is written into the file a human or an agent edited. `poetry.lock`
  > beside a `pyproject.toml` is a deliberate skip, not a hole — and a lockfile with
  > *no* readable manifest beside it still reports a gap, because then nothing was
  > inspected at all.
  >
  > **Measured end-to-end through the rebuilt image**, not just in unit tests: an npm
  > project with an invented package now reports it, where it previously returned 0
  > findings silently. `express` and `@types/node` were correctly left alone, and so
  > was a `workspace:*` sibling — the false positive most likely to make a real
  > finding ignored is reporting every package in a monorepo as nonexistent.
  >
  > **Cargo, Go, Ruby, PHP and JVM still have no existence check**, and are reported
  > as gaps instead. That is the honest half of this task's own wording — *"or
  > explicitly report unsupported manifest coverage"* — and it is what keeps F3.1
  > true rather than aspirational.
  >
  > **Severity, while here.** Every finding from this Check arrived as `unknown`,
  > including the one the product exists for: a nonexistent dependency ranked below a
  > missing licence file. Now `high` for nonexistent, `medium` for near-miss and
  > newly-registered. `high` rather than `critical` — nobody has registered the name
  > yet, and if they have, the CVE Scanners are what will say so.
  >
  > **The self-scan gate is green again.** 19.D.3 left it deliberately red with one
  > finding — *"Python (PEP 621 / Poetry) dependencies were not checked"* — because
  > this repository uses `pyproject.toml`. Resolved by coverage, as promised, not by a
  > suppression: **0 live findings**, 4 suppressed, 165 excluded from fixtures.

- [x] **19.D.2** Replace remaining user-facing references to the retired `standard`
  Profile with `full`. ✅ **DONE 2026-09-10.** Both output strings fixed:
  `results.py` now says *"Run `valvur scan --profile full` for full coverage"*, and
  `dependency_reality.py` says *"Re-run with `--profile full`"*. The alias still
  resolves; new users are no longer taught the retired name.

  > I first reported this task's premise as **false**, having searched only the
  > documentation. The retired name survived in **output strings**, which is the one
  > place that actually teaches it. Both worked, via the alias, which is exactly why
  > nothing failed. A test now asserts `--profile standard` is *absent* from the
  > Summary as well as `--profile full` being present — the pair, so removing the fix
  > fails rather than merely un-improving.

- [x] **19.D.3** Add coverage-gap reporting for Checks that are intentionally narrow.
  ✅ **DONE 2026-09-10.**

  > `valvur.dependency.ecosystem-not-covered`, **low** severity — it is our missing
  > coverage, not a defect in the user's code, and ranking it alongside a hallucinated
  > dependency would be dishonest in the other direction.
  >
  > **Reported before the early return**, which is the whole point: a repository with
  > no `requirements.txt` used to exit with an empty list, so the one shape that most
  > needed the warning was guaranteed not to get it. One finding per *ecosystem*, not
  > per file — a monorepo has one gap, not forty — and vendored manifests are ignored,
  > since `node_modules` is full of other people's `package.json`.
  >
  > Checks can now state their own severity; previously every Check finding ranked
  > alike, so a coverage note and a hallucinated dependency arrived at the same weight.
  >
  > **valvur now reports its own gap.** The self-scan has **1 active finding** —
  > *"Python (PEP 621 / Poetry) dependencies were not checked for existence"* — because
  > this repository uses `pyproject.toml` and the Check reads `requirements*.txt`. It
  > is true, it is ours, and **19.D.1 resolves it rather than a suppression**. The
  > self-scan gate is red until then, deliberately.
  >
  > **The trap this exposed, now in CONTRIBUTING.md:** Checks and rules ship *inside*
  > the image (ADR-0013), so unit tests passed while a real scan ran the published
  > image's older copy and reported nothing. Second time — the first was an Opengrep
  > rule in 12a.6.

### E — Architecture

- [x] **19.E.1** Make coverage contracts explicit, without breaking the adapter
  boundary. ✅ **DONE 2026-09-10.** `coverage(workspace, exclude)` joins the
  `ScannerAdapter` protocol beside `applies_to`, returning what an adapter reads, what
  it deliberately ignores, and the gaps that bite in *this* Workspace. `run.json`
  carries the declaration under `coverage`.

  > **The default is empty, never "covers everything".** An adapter that has not
  > declared its limits is recorded as having declared nothing. Recording it as
  > unlimited would be the silent-narrowing failure the method exists to remove, and a
  > test pins the distinction: absent and present-but-empty are different claims.
  >
  > **Asked of the whole registry, not the Profile's selection** — a limit does not
  > stop being true because a Profile skipped the Scanner that has it. That is the
  > structural fix for C1 below.

- [x] **19.E.2** Revisit `ScanRun.status` semantics after 19.C.1. ✅ **DONE
  2026-09-10.** `status` answered four questions with one word: did we find problems in
  your code, are there accepted risks, did we look at everything, was our data good
  enough. It now answers only the first, and the other three are reported beside it.

  > `ScanRun` grew `active`, `suppressed` and `coverage_notes`. Only `active` feeds the
  > verdict. **`inconclusive` widened** to cover an uninspected ecosystem — the same
  > claim it already made for a stale database: *we did not look, so `clean` is not
  > ours to claim*.
  >
  > It deliberately does **not** cover a Profile omission. The user chose `offline` and
  > valvur did that job completely; that is different from valvur silently being unable
  > to do a job nobody declined. Including it would have made every default scan
  > `inconclusive`, which destroys the word.
  >
  > **The consequence that decided the coverage-note half:** a release gate keyed on
  > active findings must not go red because valvur has no Rust support. The user cannot
  > fix that, and a gate nobody can turn green is a gate that gets deleted. F7.16
  > amended in `requirements.md`.

- [x] **19.E.3** Add a release-readiness document aimed at GitHub portfolio readers.
  ✅ **DONE 2026-09-10.** [`docs/EVALUATING.md`](../../../docs/EVALUATING.md), linked
  from the README. Install, verify the signed image, prove non-exfiltration on both
  halves, read the three statuses, and a plain list of what valvur does **not** claim.

  > **Written to be read sceptically**, which meant leading with the limits rather than
  > appending them: dependency-reality covers Python and npm only; F1.6 SELinux
  > labelling is unimplemented; there is no reachability analysis and never will be.
  >
  > Its last section points at the repository's own audit trail — the unmet-requirement
  > annotations, the tasks recording premises I asserted and then measured to be false,
  > and the traceability ratchet. For a security tool, the record of being wrong in
  > public is more persuasive than the feature list.

### F — Local corpus validation

Use real projects on this machine as a discovery corpus, not as committed fixtures.
Every scan runs against a temporary copy, and every defect that matters is distilled
into the smallest publishable fixture that reproduces it.

- [x] **19.F.1** Select a small, mixed local corpus before implementing fixes.
  ✅ **DONE 2026-09-10.** Six projects, each chosen for a different claim: a
  Rust + Python + npm + Docker/Compose monorepo (multi-ecosystem, IaC, agent
  artifacts); a `pyproject.toml`-only Python project (the known gap); a Python project
  with **both** `requirements.txt` and `pyproject.toml` (false-positive risk); a
  project with **no manifest at all** (the nothing-to-scan path); a monorepo with one
  `pyproject.toml` and four `package.json` (per-ecosystem deduplication); and a 309MB
  Node project with populated `node_modules` (vendored-path skipping at scale).

  > **Claims the corpus does not exercise, recorded rather than assumed:**
  > suppressions and expiry (no project has a `.security-scan.toml`, so those paths
  > stay synthetic-fixture-only); Go, Ruby, PHP and JVM; and secrets at scale.

- [x] **19.F.2** Scan only disposable copies under `/private/tmp/valvur-corpus/`.
  ✅ **DONE 2026-09-10.** Copies only; no original was scanned and none holds a
  `.security-scan/`. **The register of what was scanned is deliberately not committed**
  — it names six private repositories, and one of them carries a live API key in a
  committed-adjacent `.env`. Only the shapes above and the defects below cross into
  git; the corpus is deleted when Block 4 finishes.

  > **Secret redaction verified on a real credential.** That `.env` holds a live
  > Anthropic API key. Zero valvur-written artifacts contain the literal secret and no
  > `sk-ant` prefix appears anywhere under `.security-scan/`, `raw/` included. The
  > first time this guarantee has been tested against a key that actually works.

  > ### What the baseline measured
  >
  > **No Scanner failed anywhere** — nine scans across six projects, two profiles, all
  > exit 0. No crashes, no timeouts, including 309MB and 421MB trees. Runtime 24–83s.
  >
  > **Six defects, none of which unit tests could have found**, because all six are
  > about what the output does or does not say:
  >
  > | | Defect | Class | Fix in |
  > |---|---|---|---|
  > | **C1** | **Coverage-gap reporting never runs on the default profile.** 19.D.3's `ecosystem-not-covered` lives inside a Check registered `needs_network=True`, which `profiles.py` excludes from `offline`. The gap is a *static filesystem fact* and needs no network — so the message that exists to say "this scan could not help you" is absent from the profile almost everyone runs. | unsupported coverage, silent | Block 2 |
  > | **C2** | `run.json` records `scanners_not_run`; `SUMMARY.md` names only the *conditional* skip (checkov, "nothing to analyse") and stays silent on the two the profile excluded. The §7 rule is honoured for the skip with nothing to find and not for the omission that does. | unclear Provenance | Block 3 |
  > | **C3** | **The one caveat that would say so is gated on finding nothing** — `results.py:213`, `if absent and not findings:`. One missing-licence finding was enough to suppress the notice that dependency-reality never ran. The reader is told least about missing coverage exactly when there is most else on screen. | confusing output | Block 3 |
  > | **C4** | **npm and pnpm counted as two ecosystems.** The monorepo reports `npm`, `npm (pnpm)` and `Python` — three gaps for two ecosystems. 19.D.3 deduped four `package.json` files to one, then split npm on lockfile flavour, because `UNCOVERED` maps filenames to *labels* and dedup is by label. npm + pnpm + yarn would report three. | false positive | Block 2 |
  > | **C5** | `valvur.licence.missing` carries severity `unknown`, which reaches the `SUMMARY.md` counts table as a literal `unknown` row. Every corpus project has one. | confusing output | Block 3 |
  > | **C6** | The representative path for a deduped ecosystem gap is arbitrary — `infra/package.json` over the root `package.json`, by `rglob` order. Cosmetic, but it is the path a reader opens first. | confusing output | Block 2 |
  >
  > **C1 and C3 together are the finding that justifies the block.** Independently each
  > looks minor. Together they mean: on the default profile, valvur omits its most
  > distinctive Check, records that omission only in a file the contract tells agents
  > not to read whole, and suppresses the one human-facing sentence about it as soon as
  > anything else is found. That is the silent-narrowing class this project keeps
  > meeting, and no unit test was ever going to catch it — 19.D.3 shipped with tests
  > passing, four hours before the corpus found this.

- [x] **19.F.3** Classify each corpus failure before fixing it.
  ✅ **DONE 2026-09-10.** Three defects, all the same class — **false positives valvur
  itself produced on ordinary repositories**, which is the worst finding this product
  can emit: a developer told their own code is a supply-chain attack stops reading the
  report, and the real finding in it goes with them.

  > | | Defect | Classification |
  > |---|---|---|
  > | **F1** | Three **high-severity** *"almost certainly hallucinated"* findings against a monorepo's own workspace members. `uv`, Poetry and Hatch all resolve a plain `"demo-core"` from the tree beside it when a member defines that name — nothing in the dependency string says so. The npm side already skipped `workspace:*`, `file:` and `link:`; Python has no equivalent marker. | false positive |
  > | **F2** | *"'discord.py' is one character from the far more popular 'discord-py'"* — **the same package.** PEP 503 folds `.`, `-` and `_` together; verified 2026-09-10 that PyPI returns 200 for all three spellings with canonical name `discord.py`. One edit apart on raw strings, zero apart in fact, so any name containing a dot or underscore could accuse itself. | false positive |
  > | **F3** | **17 of one project's 42 findings were inside `.uv-cache/`** — `eval` and `exec` in pytest, hypothesis, pygments and attrs, every one at high severity. Forty percent of that report was other people's code. | false positive |
  >
  > **F3 is the one worth learning from.** The mechanism was correct and already
  > working; the directory name simply postdated the list. `exclusions.VENDORED` is a
  > denylist, and a denylist ages — uv did not exist when it was written.
  >
  > **Excluding whatever `.gitignore` covers was considered and rejected.** It is the
  > project's own statement about what is not its source, which is exactly the right
  > signal — and it would stop valvur scanning `.env` files, which are gitignored
  > precisely because they hold the credentials this tool exists to find.

- [x] **19.F.4** Distil each defect into a minimal fixture and a failing test.
  ✅ **DONE 2026-09-10.** `tests/fixtures/monorepo/` — a root manifest declaring two
  local Python packages and a scoped npm workspace member, plus one real external
  dependency in each ecosystem so the fix cannot be "stop checking anything".
  `tests/test_corpus_regressions.py` holds all three, each with its pairing test.

  > **Every fix has a pair**, because each of these is a way to make findings
  > disappear: a local package is skipped but a real external one is still asked
  > about; PEP 503 folding must not disarm a genuine transposition like `reqeusts`;
  > and a whole-segment match must leave a developer's own `src/cache/` alone.
  >
  > **A local package is never even asked about**, not merely unreported. A workspace
  > member's name leaving the machine buys nothing, and §3 is about what we transmit
  > as much as what we say.
  >
  > F2 is a property of a pure function and is tested as one. Manufacturing a fixture
  > directory for it would have been ceremony.

- [x] **19.F.5** Re-run the corpus after the fixes.
  ✅ **DONE 2026-09-10.** Ten scans across six projects and two Profiles, against an
  image rebuilt from the fixed tree.

  > | Condition | Result |
  > |---|---|
  > | No Scanner failures | **0**, every run `complete: true` |
  > | No silent skipped coverage | every omission named: Profile gaps, conditional skips, uninspected ecosystems |
  > | No confusing status | `clean: 0 active`, `findings: 70 active, 1 not covered` |
  > | No avoidable false positives from valvur | three classes found and fixed; none remain |
  > | Clear Provenance | `run.json` carries the coverage contract, the skip reasons and what left the machine |
  >
  > **The monorepo went from 45 findings to 23** — 22 dropped as vendored, up from 3.
  > Half its report had been other people's code.
  >
  > **One measurement recorded rather than fixed:** that project's `full` scan went
  > from 87s to 123s, because 19.D.1 now queries a registry for every declared package
  > and the lookups are serial. Real work for real coverage, but the lookups are
  > independent and I/O-bound, so this is the obvious place to parallelise if scan time
  > becomes a complaint. Not done here — it touches the one code path that reaches the
  > network, and that is not a change to make casually at the end of a block.
  >
  > **The corpus was deleted afterwards.** It was disposable by design (19.F.2), and
  > one project carried a live API key.

**Exit:** a fresh contributor can run one documented command for local confidence;
CI and release gates check the same things at the right time; suppressed-only,
stale-data and unsupported-coverage states are unmistakable; and the public GitHub
project reads as reliable rather than merely clever.

**Commit:** `chore: harden build, release and portfolio readiness`

---

## Phase 20 — Close Phase 8 runtime portability debt

**Goal:** resolve the one known gap left by Phase 8 before public release: F1.6,
SELinux mount labelling. Phase 8 found multiple false-clean runtime failures; this
phase exists so an untested native SELinux host does not become the next one.

> **Added 2026-09-10 after reviewing Phase 8.** Phase 8 is correctly marked complete
> for the Docker/rootless-Podman behaviours it tested, but F1.6 was later found
> unimplemented. That cannot remain only a note if valvur is going to claim reliable
> regulated-industry portability.

- [x] **20.1** Test valvur on a native SELinux-enforcing host, Workspace under
  `$HOME`, using Podman. ✅ **DONE 2026-09-10.** Fedora CoreOS 44, `targeted` policy
  **enforcing**, `container-selinux` 2.250, workspace on **xfs on a block device —
  not virtiofs**. Rootful and rootless both tested.

  > **It fails.** Every one of valvur's three mounts is denied: the source
  > (`admin_home_t` as root, `user_home_t` as an ordinary user), the scratch directory
  > and the Trivy cache. `:z` fixes all three.
  >
  > **The 2026-09-05 note guessed virtiofs was hiding it, and was right to be
  > suspicious.** The same Podman VM reproduces the defect immediately on its own
  > native filesystem. *Could not reproduce* was not *does not happen*.
  >
  > **`:Z` is architecturally impossible here**, which no amount of reading would have
  > settled: it stamps a private MCS category, and a second container is then denied.
  > valvur launches its Scanners concurrently against one mount, so `:Z` would break
  > the fleet from the second Scanner onward. Measured, not inferred.
  >
  > **valvur fails loudly rather than falsely clean**, which is what kept this a
  > usability defect rather than a safety one. The probe's `ls -A /workspace | wc -l`
  > returns 0 while the host has entries, so `WorkspaceUnreadable` is raised. Run
  > verbatim on the enforcing host to confirm.

- [x] **20.2** Implement the chosen mount-label behaviour and test the exact runtime
  flags. ✅ **DONE 2026-09-10. Opt-in relabel, refusing by default** — chosen by the
  owner after the measurements above.

  > **valvur's own directories are labelled unconditionally** on an enforcing host: the
  > scratch mount and the Trivy cache are a temporary directory we created and a cache
  > we own, and without the label the container cannot write its results at all.
  >
  > **The Workspace is not**, unless `VALVUR_SELINUX_RELABEL=1`. `:z` rewrites the
  > SELinux context of every file in the scanned tree and it persists after the scan;
  > §10 prohibits writing to the scanned tree without explicit owner approval, and a
  > tool whose first promise is that it cannot touch your code should not quietly
  > rewrite its labels. The accepted cost is that a first run on RHEL fails.
  >
  > **An environment variable, not a CLI flag.** MCP is the primary interface
  > (ADR-0015) and has no command line, so a flag would fix this for the second-choice
  > path only.
  >
  > **The first draft of the remediation shipped a false instruction.** It said
  > *"Undo with: restorecon -R"*, which does **nothing**: `container_file_t` is listed
  > in the policy's `customizable_types` and restorecon skips those unless forced.
  > Measured on the host, corrected to `restorecon -R -F`. A remediation that silently
  > does nothing is worse than none — the reader believes they have undone it.
  >
  > **Exact flags verified on the enforcing host**, generated by valvur and run there:
  > default leaves the label `admin_home_t` untouched and the probe sees 0; with the
  > opt-in the label becomes `container_file_t` and the probe sees every entry. **F1.1
  > survives** — a write to `/workspace` is still refused through a `,z` mount.

- [x] **20.3** ~~If SELinux labelling is not required, cut or amend F1.6.~~
  ✅ **NOT TAKEN 2026-09-10.** This was the branch for *"the defect does not reproduce
  on a native host"*. It does, immediately, so 20.2 was the applicable branch and F1.6
  stands as written — now met rather than cut.

- [x] **20.4** Update the Phase 8 completion note.
  ✅ **DONE 2026-09-10.** [Phase 8](#phase-8--runtime-portability-and-hardening) now
  records that it was complete for what it tested and that F1.6 was not among it —
  the fourth silent failure of that set, found six weeks after the phase that should
  have caught it.

**Exit:** F1.6 is either implemented and tested on the environment it names, or the
requirement is amended with evidence from that environment. No Phase 8 portability
claim remains stronger than the proof behind it.

**Commit:** `test: close SELinux portability gap`

---

## Phase 21 — Everything that remains

**Goal:** one ordered release sequence for the open tasks that should happen only
after hardening and runtime-portability debt are closed.

> **Originally added as Phase 18 on 2026-09-10. Renumbered 2026-09-10.** The phase
> was a useful release checklist, but it ran too early: public-release actions should
> not precede the reliability and portfolio hardening now captured in Phase 19, or
> the F1.6 portability closure in Phase 20. **If an item here disagrees with its own
> task, the task is authoritative.**
>
> **Closed while writing the original phase**, because both were done and neither
> said so: [0.2](#phase-0--preflight) (Podman installed, six weeks after the entry
> still read *"Recon: not installed"*) and [1.12](#phase-1--walking-skeleton) (a
> pointer to work that moved to 10.0 and finished on 2026-08-31). Two tasks that
> looked like remaining work and were not.

```
PREREQUISITES
   Phase 19  reliability, release and portfolio hardening
   Phase 20  F1.6 SELinux/runtime portability closure
        ↓
A. OWNER ACTIONS — nothing downstream can start
   12a.1  push · repo public · package public
   0.14   branch protection (needs the repo public first)
        ↓
   Phase 22 Block A  offline existence check   ← added 2026-09-12; the default
   Phase 22 Block B  prove the release pipeline    Profile must catch a hallucinated
        ↓                                          package before anyone runs it
D1. 12a.7 (second half)  publish 0.2.0  ← needs PyPI trusted publishing + a
                                           `release` environment, also owner actions
        ↓
   Phase 23 Block 2  the published index   ✅ 2026-09-12 — the first ten minutes,
   Phase 23 Block 3  valvur doctor            before a stranger measures them
        ↓
B. NEEDS A PERSON WHO HAS NEVER SEEN VALVUR
   10.1.1 · 10.1.2   the usability gate
        ↓
D2. 12b.1  act on what the gate found
    12b.2  re-run the constraint suite against the release artifact
    12b.3  tag v1.0.0

C. UNBLOCKED, AND NOT WAITING ON THE OWNER ACTIONS  — both done
   10.4.12  what a human sees first in SUMMARY.md          ✅ Block 3
   10.2.5   the CLAUDE.md / AGENTS.md snippet, against a real agent  ✅ 2026-09-11
```

> **Where this stands on 2026-09-12.** PREREQUISITES and C are complete. Everything
> left is A → D1 → B → D2, in that order, and every item in A is an action only the
> repository owner can take at github.com or pypi.org. There is no remaining
> engineering task that does not depend on one of them.
>
> **Amended the same evening.** Phase 23 inserted two engineering blocks before the
> gate. Block 2 (the published index; Ruby, PHP and Rust offline; the image pull
> named) is **done**; Block 3 (`valvur doctor`, timing, cancel, the gate command, the
> Action, the budget) is what remains before B. A gains one item from Block 2: the
> `valvur-index` GHCR package public, beside the image's.
>
> **2026-09-13: A and D1 are done — `0.2.0` is published** (23.1.1 has the account).
> What remains: Phase 23 Block 3, then B (the usability gate — now possible: there
> is something to install), then D2. **Superseded the same day by the one list at
> the head of [Phase 24](#phase-24--the-audit-and-one-list-of-everything-that-remains)**,
> which orders every open task; this diagram is history.

### A — Owner actions

Only the repository owner can do these, and everything else waits behind them.

- ~~**21.A.1**~~ ✅ **Done 2026-09-13.** → [12a.1](#12a--make-it-obtainable-and-trustworthy). Push (45 commits
  ahead), make the **repository** public, then the **packages** — `valvur`, the
  image, and since 23.2.1 `valvur-index`, the daily name index. In that order, or
  the newly-public repo is missing every phase from 10.3b onward. Measured
  2026-09-10: repo API `404`, GHCR anonymous token `401` — and 2026-09-12 for the
  index package, the same `401` from the shim's own client.
- ~~**21.A.2**~~ ✅ **Done 2026-09-13.** → [0.14](#phase-0--preflight). Branch protection on `main`. Deferred
  since 2026-08-30 because GitHub charges for it on private repositories; it becomes
  free the moment 21.A.1 lands, and guards nothing until then.
- ~~**21.A.3**~~ ✅ **Done 2026-09-13** (PyPI and TestPyPI publishers by the owner; private vulnerability reporting enabled by API). → the setup half of [12a.7](#12a--make-it-obtainable-and-trustworthy)
  and [12a.5](#12a--make-it-obtainable-and-trustworthy): PyPI trusted publishing
  against `release.yml`, a `release` GitHub environment, and private vulnerability
  reporting. All three are documented in
  [docs/RELEASING.md](../../../docs/RELEASING.md); the release workflow fails without
  the first two, and `SECURITY.md` links to a 404 without the third.

### B — Needs a person who has never seen valvur

- **21.B.1** → [10.1.1](#101--the-usability-gate) and
  [10.1.2](#101--the-usability-gate). The usability gate. **Cannot be simulated** —
  the entire value is that the participant has no context, and participants cannot be
  reused because first impressions do not reset. Blocked by 21.A.1: there is nothing
  to install until the package is public.

### C — Unblocked

Neither of these waits on the owner actions. They can proceed while the owner actions
are pending, but still come after Phase 19 so the surface being tested is the hardened
one.

- ~~**21.C.1**~~ ✅ **Done 2026-09-10, Block 3.** → [10.4.12](#104--error-messages-as-a-usability-surface). Decide what
  a **human** sees first in `SUMMARY.md`. It is currently written for agents — the
  machine-facing block is first by design (F7.6) — and no one has asked whether that
  is right for the person who opens it in an editor. A genuine design decision, not a
  bug.
- ~~**21.C.2**~~ ✅ **Done 2026-09-11.** → [10.2.5](#102--the-mcp-first-run-the-primary-path). Verify the
  copy-pasteable `CLAUDE.md` / `AGENTS.md` snippet against a real agent in a real
  repository *(P6)*. Partly evidenced already — task 12a.4 confirmed `valvur-mcp`
  starts, reports its version and advertises four read-only tools — but nobody has
  pasted the snippet into Kiro or Claude Code and watched what happens, which is the
  actual claim.

### D — Sequenced after

- ~~**21.D.1**~~ ✅ **Done 2026-09-13, `v0.2.0`.** → [12a.7](#12a--make-it-obtainable-and-trustworthy), publishing half.
  The automation is done and verified; tagging publishes `0.2.0`. Carries two
  corrections that only take effect on release: the **multi-arch build** (13.1 — the
  published image is still `arm64` only) and the **PyPI licence metadata**, which
  still says MIT while the repository is Apache-2.0.
- **21.D.2** → [12b.1](#12b--release). Act on the gate's findings.
- **21.D.3** → [12b.2](#12b--release). Re-run the Phase 11 constraint suite and
  the self-scan gate against the **release artifact** rather than the working tree.
- **21.D.4** → [12b.3](#12b--release). Tag `v1.0.0`.

**Exit:** `v1.0.0` released, having been installed and used by someone who did not
build it, after Phases 19 and 20 removed the known reliability and portability debt.

**Commit:** *(none — this phase only references others)*

---

## Phase 22 — The product move, and what the review found behind it

**Goal:** make the headline feature usable by the market it is for, prove the release
pipeline before it runs for real, and pay down the sediment three days of blocks left
behind — in that order, because the first two decide whether publication goes well and
the rest decide whether the next six months do.

> **Added 2026-09-12 from a critical review of build, deploy, functionality,
> architecture and product.** Phases 19 and 20 are complete and nothing technical
> blocks publication. This phase is what the review said should happen *before*
> `0.2.0` reaches anyone, and what should happen after.
>
> **The finding that shapes the order.** Slopsquat detection — the check this product
> is most distinctive for — needs a registry, so it runs only on `full`. `full` sends
> package names to PyPI and npm. Target market #1, regulated industries, is *defined*
> by not being able to do that. So the tagline and the default profile disagree: "fully
> offline" and "hallucinated-package detection" are both true, and not at the same
> time. The first thing a regulated-industry reviewer will do is run the default
> profile on a Java repository and read `not_covered: 1`. Block A exists so that they
> read something else.

```
Block 6 (Phase 21 A: owner actions)  ─── any time; nothing here waits on it
        ↓
Block A  offline existence check        ─┐  BEFORE 0.2.0 publishes (21.D.1)
Block B  prove the release pipeline     ─┘
        ↓
21.D.1  publish 0.2.0
        ↓
Block C  build guards                   ─┐
Block D  architecture sediment          ─┼─ independent; any order, after publication
Block E  corpus and rules               ─┤
Block F  the first impression           ─┘
        ↓
Phase 23 Blocks 2–3  (index ✅, doctor)  ← added 2026-09-12, from the Kiro run
        ↓
21.B / 21.D2  the usability gate → v1.0.0
```

### A — The offline existence check

The one product move. Existence — *does this package name exist at all?* — is the
hallucination check. Age and near-miss similarity are refinements. Existence can be
answered from a local index of names; the refinements need a registry. Split them.

- [x] **22.A.1** Design and measure the index before building it. Two decisions, each
  with a number behind it, recorded as an ADR:

  > **Done 2026-09-12 — [ADR-0018](../../../docs/adr/0018-offline-package-name-index.md).**
  > Measured against the live registries: PyPI 890,006 names (12.8MB plain, 4.0MB
  > gzip); npm 4,382,736 (90.5MB plain, 25.4MB gzip). **Exact wins**: 29MB on the wire
  > beside the database's 116MB, and a bloom filter at 0.1% would have saved 20MB for
  > one missed hallucination in a thousand. Lookup is a binary search over the
  > memory-mapped plain file — 8µs a name, measured, against 0.3s/1.6s per scan to
  > stream the gzip or a second and ~270MB to build a set — so the index is stored
  > uncompressed and `grep -x` is the audit. **Sources:** PyPI's simple index is one
  > 9.7MB request. npm has no all-names endpoint: `replicate.npmjs.com/_all_docs`
  > caps pages at 10,000 and refuses `skip` (439 requests, 145.6MB, 330s for the full
  > set); `_changes` is ~24,000 entries a day, so a week of drift is ~17 requests.
  > `all-the-package-names` was rejected on **measurement**: diffed the morning it
  > was published, 140,823 of its names do not exist on the registry (deleted spam
  > it never dropped — the direction that turns a hallucination into "exists") and
  > 81,134 registry names are missing from it. Staleness: PyPI adds ~530 projects a
  > day and npm ~1,600; threshold set at 30 days, with the note that an old index
  > *overstates* (a package newer than itself reads as nonexistent) rather than
  > misses, so the threshold keeps the age visible rather than marking a cliff.

  **Exact set or probabilistic?** A bloom filter is small (roughly a byte per name at
  1% false positives), but a false positive here is a *missed hallucination* — the
  headline finding, silently not reported one time in a hundred. An exact sorted list
  compresses well and never lies. Measure both against the real name counts: PyPI is
  in the high hundreds of thousands, npm in the low millions. If the exact form is
  under ~20MB compressed it wins on principle; if not, say what rate was accepted and
  why.

  **Where the names come from, and how they are refreshed.** PyPI's simple index is
  one request. npm has no cheap all-names endpoint; find what is actually maintained
  (the replicate feed, a published dump) and measure how stale it can be before it
  matters. Refresh belongs with `valvur update`, beside the vulnerability database
  (ADR-0012): outside the image, in the host cache, mounted at scan time.

  > **Not in the image.** Names change daily; image releases do not. The exact
  > argument ADR-0012 made for the database, and the same answer.

- [x] **22.A.2** Implement it, and move existence to the default Profile. The
  dependency-reality Check runs on `offline` against the index — existence only, under
  `--network=none`, with `what_left_the_machine` still `nothing`. On `full` it adds
  what needs a registry: first-publish age and the near-miss comparison.

  > **Done 2026-09-12.** `src/valvur/name_index.py` (builder on the host, reader in
  > the container, one file because the format is the contract); `valvur update`
  > fetches it under the cache's exclusive lock and `--if-stale` refreshes the index
  > alone when only it is due; the runner mounts `~/.cache/valvur/names` read-only at
  > `/cache/names` and sets `VALVUR_NETWORK=1` in exactly the case it omits
  > `--network=none`, so the Check reads the decision the kernel enforces and never
  > probes. The network grant moved out of the adapter and into `profiles.select`
  > (`for_profile` on the protocol) — the only place a network is granted. Stale past
  > 30 days is `inconclusive` on every surface the database's staleness reaches:
  > verdict, `run.json` (`name_index` block), `SUMMARY.md`, terminal, MCP.
  >
  > **One correction to the task as written:** the near-miss comparison never needed
  > a registry — it reads the popular list shipped in the image — so it runs offline
  > too. The gap prose says `offline` lacks "package age (newly-registered names)";
  > hallucinated packages moved to the *covered* side of the Summary's sentence.
  >
  > **Proven in a real container**, image `valvur:blockA`, `tests/fixtures/broken-repo`
  > on `offline`: `reqeusts` ("did you mean 'requests'?") and `aws-helper-sdk`, both
  > high, `what_left_the_machine: nothing`, `name_index.present: true`. On `full`
  > the same two plus age lookups for the names the index confirmed. Empty cache:
  > the Check refuses host-side before launching, fix first — the first measurement
  > produced a traceback truncated at 200 characters with `valvur update` cut off.
  > The Phase 11 suite gained six tests (the Check opens no connection ungranted, does
  > when granted, never sends a name the index settled, refuses without an index, the
  > runner tells containers the truth, the mount is `:ro`); `verify-offline.py` runs
  > the Check in-process under the poison as a third half. Eight mutations, six
  > caught, two equivalent-or-fixed. The unit suite now refuses every `urlopen` — a
  > `full` scan against a fake runner would otherwise have reached PyPI from a test.
  > 443 → 524 tests.

  > **This amends ADR-0016**, which says `full` adds *"the two that genuinely need a
  > socket"*. After this, one of the two runs on both Profiles and only its
  > refinements need the socket. `profiles.py`'s gap prose changes with it: `offline`
  > no longer lacks "hallucinated and typosquatted packages", it lacks "package age and
  > typosquat similarity". Every test that pins the Profile split moves; the Phase 11
  > constraint suite must stay green, because the moat claim is what this touches.
  >
  > **A stale index is `inconclusive`, not `clean`.** The same rule as the database:
  > record its age in `run.json`, and past a threshold the verdict carries the doubt.
  > An index that quietly ages into uselessness would be the silent-narrowing class
  > again, inside the fix for it.
  >
  > **The self-scan and the corpus fixtures prove it.** `tests/fixtures/broken-repo`
  > has `reqeusts` and `aws-helper-sdk` in `requirements-ai.txt`; on `offline`, today,
  > neither is reported. After this task both are, with no socket.

- [x] **22.A.3** Parallelise the `full` lookups. Measured: 123s on a monorepo, because
  each registry call is serial and each carries a 10s timeout. The lookups are
  independent and I/O-bound. Bound the concurrency — this is the one code path that
  reaches the network, and a scanner that opens fifty connections to PyPI at once is a
  scanner that gets rate-limited and reports *unreachable* as if nothing was declared.

  > **Done 2026-09-12.** `_verify` is two passes: existence from the index, then one
  > bounded `ThreadPoolExecutor` (`LOOKUP_CONCURRENCY = 8`) for whatever the registry
  > still has to answer — age for the names that exist, and existence too where
  > there is no index — then findings built in declaration order so the output is
  > byte-identical whatever order the answers arrived in. Measured in-process
  > against live PyPI, 60 real names: **9.5s serial → 2.0s** at eight wide. A name
  > the index settled as absent is never in the batch (asserted in Phase 11). One
  > failed lookup is one unverified name, not a failed Check. Four mutations —
  > serial, unbounded, nonexistent names sent, asked without a network — all caught.

- [x] **22.A.4** Extend existence checking to JVM and Go, the two ecosystems the
  stated market actually runs on. Maven Central is one registry with a name index;
  Go's proxy has a feed but no all-modules list, so Go may be `full`-only and should
  say so in its coverage contract rather than be promised. Whatever the answer, the
  coverage note for these two must change from *no existence check* to what is true.

  > **Done 2026-09-12 — both `full`-only, and the task's premise about Maven was
  > wrong.** Measured: Central's "name index" is the 3.24GB Lucene index; its search
  > API has 661,801 coordinates at 200 a page. Go's `index.golang.org` is a version
  > feed — 2,000 entries covered seventeen minutes of 2026-09-11 — with no module
  > list. Neither becomes a file a user downloads. So: one request per name on
  > `full` (`repo1.maven.org/.../maven-metadata.xml`, `proxy.golang.org/.../@v/list`,
  > 410 treated as absent), verified live both ways. Parsed: `pom.xml`
  > (`<dependencies>` and `<dependencyManagement>`, `${project.groupId}` resolved,
  > other properties skipped, namespace-agnostic, reactor modules never asked
  > about), `build.gradle`/`.kts` (every quoted `group:artifact`, comments stripped,
  > `project(":x")` excluded), `gradle/libs.versions.toml` (all three shapes),
  > `go.mod` (direct `require`s; `// indirect` and locally `replace`d modules never
  > asked about; the proxy's `!` case escaping). On `offline` these are dropped
  > before anything else and the Coverage contract says *"existence checked on
  > `full` only (no offline index exists for this registry)"* — a Profile omission
  > under F7.16's rule, so a JVM repository now reads `clean` with the omission named
  > rather than `inconclusive` with a gap Finding. That is a deliberate trade and the
  > public corpus (Block E) is where it gets re-examined. Proven in a real container
  > on a pom + go.mod fixture with one invented coordinate each: both reported on
  > `full`, neither failed on `offline`. Nine mutations, nine caught. No age for
  > either — neither registry states first publication — and the contract says so.

### B — Prove the release pipeline before it runs for real

`release.yml` has never executed. Cosign, the SLSA attestation, PyPI trusted
publishing, the `release` environment — all of it is theory until a tag pushes, and
the first tag was going to be `0.2.0` in front of everyone.

- [x] **22.B.1** Dry-run the release workflow end to end on a throwaway tag against
  TestPyPI and a scratch GHCR namespace, before `0.2.0`. Every step must succeed or
  fail *for a reason the log names*. Record what broke — something will.

  > **Done 2026-09-12, four rehearsals, four things broke.** `release.yml` gained a
  > `workflow_dispatch` rehearsal mode: same steps, same permissions, same OIDC
  > identity, throwaway targets (`ghcr.io/maverickhq/valvur-rehearsal`, TestPyPI, a
  > draft pre-release deleted on the way out) under `<version>.dev<run>`. But first:
  > **the push itself found that CI had not run for twelve days and 68 commits**,
  > and its last run had failed. Two tests were wrong on Linux — a macOS-only hint
  > test that never said which platform it meant, and a runtime-detection test that
  > looked only in macOS locations, whose skip the parity guard read as "dual-runtime
  > unverified". Fixed; CI green for the first time since 2026-08-31. The e2e job
  > and the self-scan gate had never fetched the database or the index; they do now,
  > with the index cached between runs (restored: the update step took 21s instead
  > of five minutes). Then the rehearsals:
  >
  > 1. **Attestation refused** — GitHub does not persist attestations for a
  >    user-owned *private* repository. Skipped in rehearsals on a private repository,
  >    with a warning; never skipped on a real release. **The one step still
  >    unrehearsed**, until 12a.1 makes the repository public.
  > 2. **SBOM `unauthorized`** — syft through the Docker socket had no credentials
  >    for a fresh (private) GHCR package. Now the registry source with syft's own
  >    auth variables, no socket, pinned to one platform. 2,227 components.
  > 3. **TestPyPI `invalid-publisher`** — no trusted publisher exists there yet; an
  >    owner action (`docs/RELEASING.md` §one-time setup, item 4), and the token's
  >    claims to configure it against are in the run log. Allowed to fail without
  >    stopping the rehearsal, so the release step after it runs; the report at the
  >    end turns the run red until it passes.
  > 4. **The cleanup step lied** — "no release to remove" for a draft it had just
  >    removed, because a draft has no tag for `--cleanup-tag` to clean. Split;
  >    the fourth rehearsal reported "removed draft release rehearsal-4" and "no
  >    tag to remove (a draft never creates one)", and left nothing behind.
  >
  > **Proven:** verify job end to end (6m30s: `verify.sh`, image build, DB + index,
  > the whole suite including e2e, F10.4, the self-scan gate — clean); the
  > multi-architecture push (4m36s, both platforms asserted on the published index);
  > keyless signing — verified from this machine with the README's exact `cosign
  > verify` command, identity `release.yml@refs/heads/main`, Rekor entry present;
  > SBOMs in both formats; `uv build`; the GitHub release with all assets attached
  > (as a draft, then deleted, no tag left behind). Multi-arch build 4.5 minutes,
  > whole rehearsal ~12. Four scratch image tags remain in
  > `ghcr.io/maverickhq/valvur-rehearsal` as evidence.

- [x] **22.B.2** Write the partial-failure runbook into `docs/RELEASING.md`. The
  workflow pushes the image, then publishes to PyPI. State what to do when the image
  is pushed and PyPI fails, when PyPI succeeds and the GitHub release fails, and when
  a tag has to be re-run. There is currently no rollback story of any kind.

  > **Done 2026-09-12.** A table by the step it stopped in: what exists, what to do.
  > Fix forward throughout; the one case where moving the tag is right (nothing
  > left the runner); the dangerous state named (an unsigned image under a real
  > tag) with the order of operations to leave it; `gh run rerun --failed` as the
  > re-run path and why a whole re-run of a tag that reached PyPI fails correctly;
  > the `release` environment as the manual brake. Written before the rehearsals and
  > checked against what they showed: the states in the table are the ones the
  > workflow can actually stop in.

- [x] **22.B.3** Stand up a real mirror and run air-gapped. `VALVUR_DB_REPOSITORY` is
  documented in two places and has never been exercised. Point it at a local OCI
  registry, cut the network, and confirm `valvur update` and a `full`-equivalent scan
  complete. After 22.A.2, the name index needs the same treatment.

  > **Done 2026-09-12 — and the documented setting did not work on its own.** A
  > `registry:2` on a Docker `--internal` network (no route out: structural, not a
  > firewall rule), the Trivy DB copied in with `oras`, and `VALVUR_DB_REPOSITORY`
  > pointed at it: *"server gave HTTP response to HTTPS client"*. Trivy assumes TLS
  > for anything that is not `localhost` or a private-range IP literal. Three
  > settings that did not exist that morning: `VALVUR_DB_INSECURE=1` (Trivy's
  > `--insecure`), `VALVUR_CONTAINER_NETWORK` (the update container joins the
  > mirror's network; never applied to a `--network=none` container, asserted), and
  > `VALVUR_KEV_URL` — KEV was the one fetch with no mirror at all, so an air-gapped
  > `valvur update` always tried cisa.gov. The index mirror is `VALVUR_NAME_INDEX_URL`:
  > the three files served verbatim by any static server, `built_at` preserved so the
  > reported age is the data's (F6.11); truncated or non-index mirrors refused.
  > `scripts/verify-mirror.py` runs update + offline scan with every connection
  > outside the mirrors refused as an air gap would refuse it, and judges the
  > attempts. Result from a fresh cache: update complete (DB via the internal
  > registry — 8 GETs in its log — index and KEV via loopback), offline scan complete
  > with 76 findings, `what_left_the_machine: nothing`, no attempt beyond loopback.
  > "`full`-equivalent" is the wrong phrase: `full` reaches api.osv.dev and FIRST by
  > definition; what an air-gapped site runs is `offline`, which since 22.A.2
  > includes the hallucination check. Recipe in `docs/RELEASING.md`; settings in the
  > README's air-gap section (moved to `docs/AIR-GAPPED.md` in 22.F.1).

- [x] **22.B.4** Measure the true first run and publish the least flattering number.
  From a clean machine: bytes downloaded (image, database, index), wall-clock to the
  first result, and what the user is staring at while it happens. Put it in
  `EVALUATING.md`. The honesty document should carry the number a competitor would
  quote, before they do.

  > **Done 2026-09-12.** From an empty cache on this Mac: image 321MB compressed as
  > published (`0.1.0rc1`, and single-arch — the known defect) or ~240MB from the
  > current tree; `valvur update` **6m27s** and **276MB** (Trivy DB 118,357,868
  > bytes by its manifest, npm names 146MB in 439 requests, PyPI 10MB, KEV 2MB);
  > first scan **45s** on `broken-repo` (Checkov runs — Terraform is present;
  > measured identical with the pre-Block-A image, so not a Block A cost). **About
  > eight minutes to a first result on 100 Mbit, most of it npm.** In `EVALUATING.md`
  > §1 as a table with the "what you are staring at" column the task asked for, and
  > the one sentence that matters: a valvur-published index is what moves this
  > number next, and it waits on Block B.

### C — Build guards

- [x] **22.C.1** A local image-staleness guard. The rebuild trap bit four times in
  three days: Checks and rules ship *inside* the image (ADR-0013), so unit tests pass
  while a real scan runs yesterday's code. CONTRIBUTING documents it; documentation
  is not a guard. `scripts/verify.sh image` hashes `src/valvur/checks/`, `rules/` and
  the `Dockerfile`, compares against a label baked into the local image at build
  time, and fails with the rebuild command.

  > **Done 2026-09-12 — a fifth bite first.** During Block B the previous image,
  > run with the new shim, crashed its Check in-container; F1.9 saw two identical
  > versions. Two deviations from the task as written, both for the same reason:
  > **one module computes the digest on both sides.** `src/valvur/tree_hash.py` runs
  > inside the Dockerfile (`python -m valvur.tree_hash --image`, stored at
  > `/etc/valvur/inputs.sha256`) and on the host over the tree, so the two can only
  > disagree because the inputs do — a label cannot be computed during a build, and a
  > `--build-arg` at every call site is the 19.A.3 drift again. And the digest covers
  > all of `src/valvur/`, not only `checks/`: the Check imports `name_index`,
  > `exclusions`, `ecosystems`, all of which ship in the image. Keyed by label, not
  > path, so `src/valvur/x.py` and its site-packages copy hash alike; `__pycache__`
  > and `.pyc` excluded on both sides (the image strips them, the host has them
  > everywhere). Verified: in-image and tree digests identical on a fresh build; a
  > one-line edit to a rule fails with the rebuild command; an image predating the
  > guard fails as such. Two consumers: `scripts/verify.sh image` (opt-in, needs a
  > runtime; the script says when it was not run) and the first e2e test, which is
  > where the trap bites — CI's e2e job passes it because it builds what it tests.
  > A test pins the input set to exactly the Dockerfile's `COPY` lines, so a new
  > `COPY` widens the guard or fails the suite. Two things found on the way: the
  > checkov layer sat *after* our `COPY`s, so every Check edit re-ran a 60-second pip
  > install (reordered); and there was no `.dockerignore` — the build context was
  > 124MB, of which the Dockerfile copies under 1MB (added).

- [x] **22.C.2** Cite the 24 tolerated requirements and take the ratchet to zero. They
  are mostly *core* — F2.1 (orchestrate the Scanners), F7.1 (write the Results
  Folder), F8.1 (read Suppressions), F10.2 (non-root) — uncited because nobody wrote
  `# F7.1` beside obvious code, not because they are unmet. A tolerated count that
  never shrinks is a number nobody reads.

  > **Done 2026-09-12 — 0 uncited, 0 orphan ADRs, and the premise was wrong for
  > three of the 24.** Twenty-one were exactly as described: obvious code nobody had
  > annotated, now cited where the behaviour lives (the Finding model, the
  > fingerprint classes, the status diff, the enrichment provider, the machine
  > header, the results writer, the runner's container flags, the parity tests, the
  > Dockerfile pin test). Three were not:
  >
  > - **F7.3 was uncited because it is unimplemented** — valvur does not add
  >   `.security-scan/` to the scanned project's root `.gitignore`, and CLAUDE.md
  >   section 7 said it did. It must not: that is a write to a tracked file in the
  >   scanned tree (section 10, moat item 2). **Retired** in `requirements.md` with
  >   the reason, the ID kept; CLAUDE.md corrected; ADR-0011's scope clarified (its
  >   root-`.gitignore` layer is this repository's own hygiene, not something valvur
  >   does to a Workspace).
  > - **F3.3 is half met** — age yes, adoption no; PyPI has no download counts
  >   without a third-party service (F1.7, ADR-0008). **F3.4 is met by proxy** —
  >   top-3,000 membership, not a 100× download ratio, and PyPI only. Both cited by
  >   the code implementing the half it implements, and both carry a note in
  >   `requirements.md` saying which half, because the ratchet cannot tell.
  >
  > The eight orphan ADRs each gained a **Requirements** line naming what they
  > decided about. Baseline re-recorded empty, so the ratchet is now a hard check:
  > mutating one citation away fails it (`::error::new requirement cited nowhere:
  > F8.1`). Rebuilt the image afterwards — the citations changed `src/valvur/`, and
  > 22.C.1's guard said so before anything else did.

  > **What the ratchet cannot do, stated so nobody expects it to.** 19.D.1 proved that
  > citation is not satisfaction: F3.1 was cited by code implementing a tenth of it. The
  > ratchet catches a requirement losing its last citation. It will never catch one
  > that is cited and unmet. The corpus (Block E) is the tool for that.

### D — Architecture sediment

Three days of blocks added stages by inserting them. It works. It is also where the
next ordering bug lives — Block 2 already had one, when exclusions were loaded after
the coverage gap that needed them.

- [x] **22.D.1** Name the pipeline. `api.py::_scan_locked` is 120 lines of
  coverage → licence → vendored → configured → merge → gitcontext → enrich →
  suppress → rank → write, inline. Make it a list of named stages, and pin their
  order with a test that fails when one moves.

  > **Done 2026-09-12.** `src/valvur/pipeline.py`: ten `Stage`s in a tuple, each a
  > pure function of the Findings and a `Context`, each carrying `why_here` — the
  > constraint its position encodes, kept beside the code because a constraint in a
  > commit message is one the next insertion does not see. `write` is not a stage;
  > `diff` is the last one, so Status is computed over the final set. Behaviour
  > unchanged: the suite passed as-is after the switch. `tests/test_pipeline.py`
  > pins the order outright, and pins the reasons: swapping `coverage`/`configured`
  > fails the exclusions test Block 2's bug would have failed; swapping
  > `vendored`/`merged` fails a duplicate that survives by merging. Five swaps
  > mutated, five caught; two by the order test alone, which is what it is for.

- [x] **22.D.2** `results.py` accepts a `ScanRun` and nothing else. `_summary` is
  190 lines with **34 `getattr(run, …, default)` calls**, defending against a
  dataclass whose fields are always populated — the tests pass duck-typed stubs, and
  the production code grew defensive against a case that cannot occur. Give the tests
  a real `ScanRun` and delete every `getattr`.

  > **Done 2026-09-12.** 38, not 34, plus two in `cli.py`; all deleted, every entry
  > point typed `run: ScanRun` (annotation-only import — `api` imports `results`).
  > The premise was nearly right: 51 of 52 test call sites already built a real
  > `ScanRun`; the one duck-typed `Run` was the ten-thousand-findings cap test, and
  > it is the reason the defaults could never be removed before. The two `getattr`s
  > on `runner` stay — fake runners are a real duck-typed boundary.

- [x] **22.D.3** Coverage belongs to the Check. `CheckAdapter.coverage()` special-cases
  `if self.name != "dependency-reality"` — the adapter knows a Check's name, which is
  the boundary ADR-0013 drew being crossed in the wrong direction. Put `coverage()` on
  the Check protocol; the adapter forwards.

  > **Done 2026-09-12.** `Check.coverage(workspace, exclude, *, network)` with the
  > empty default, inherited by the two Checks that declare nothing; dependency-
  > reality's contract moved onto the Check; the adapter looks the Check up in the
  > registry and forwards, network grant included. A test asserts the adapter's
  > source names no Check. Host-side, like before: coverage is a static statement
  > about files, and needs no container.

- [x] **22.D.4** `status_reason`. `inconclusive` now has two causes — a stale
  database, an uninspected ecosystem — and after 22.A.2 a third, a stale index. An
  agent that wants to say *why* has to reconstruct it from `database.stale` and
  `findings.not_covered`. One field, one line, and the MCP `scan_status` message
  stops guessing.

  > **Done 2026-09-12.** `ScanRun.doubts` — every reason a nil result is not
  > evidence, as a list; `status` derives from it — and `ScanRun.status_reason`,
  > one line for all three statuses. Carried in `run.json` and `findings.json`,
  > used verbatim by the `SUMMARY.md` verdict sentence and the MCP `scan_status`
  > and `start_scan` replies. The guessing it replaced was wrong in a case nobody
  > had hit: a run with a stale database, a stale index *and* an uninspected
  > ecosystem named only the first. A `run.json` from before this says "reason not
  > recorded; rescan" rather than being guessed at. Verified on real scans: a
  > Rust-only project reads the identical sentence in all three places. Three
  > mutations, three caught.

### E — Corpus and rules

- [x] **22.E.1** A public, committed corpus. The local corpus found three false
  positives in an hour — two of them introduced by the block before, with every test
  passing — and was then deleted because it held private repositories and a live
  credential. There is nothing between a future change and a user except seven small
  fixture directories. Assemble ten real-shaped, permissively-licensed repositories
  under `tests/corpus/`, and run them weekly in CI with the 19.F.5 success conditions:
  no Scanner failures, every omission named, no confusing status, no false positives
  from valvur itself.

  > **Done 2026-09-12 — and it found a defect on its first run, like the private one
  > did.** Eleven repositories, not ten: requests, flask, llm (AGENTS.md), express,
  > fastify, cobra, gson, ripgrep, terraform-aws-vpc, sinatra, and awesome-cursorrules
  > (hundreds of real `.cursorrules`, the AI Artifact Check's false-positive test).
  > **Pinned by commit in `tests/corpus/corpus.toml`; the bytes are fetched, not
  > committed** — `scripts/corpus.py fetch` does a depth-1 fetch of the SHA into an
  > ignored, self-scan-excluded directory (38MB). Ten real projects in our history
  > forever, and in every self-scan, is the wrong trade; the pins and the expectations
  > are the corpus and the bytes follow from them. `scripts/corpus.py run` scans and
  > judges the four conditions, names every failure, writes `report.json`;
  > `.github/workflows/corpus.yml` runs it weekly on both Profiles and on dispatch.
  >
  > **The finding: Express read `clean` with thirty dependencies never checked.** It
  > commits no lockfile, and Trivy produces no result — not zero, none — for
  > `package.json` alone. Measured the same for `pyproject.toml`, `Gemfile` and
  > `Cargo.toml`; `requirements.txt`, `go.mod` and `pom.xml` scan on their own.
  > Now `ecosystems.VULNERABILITY_MANIFESTS` records what was measured, the Trivy
  > adapter declares it through the coverage contract, and a manifest with nothing
  > Trivy reads beside it is a coverage note (`valvur.dependency.vulnerabilities-
  > unchecked`) that makes a nil result `inconclusive` — Express and fastify both
  > read that way now, with the reason. The judge checks that condition too, and
  > learned on the second run that an *empty* lockfile is not silence (awesome-
  > cursorrules' `pnpm-lock.yaml`). Both Profiles pass: eleven of eleven, no
  > suspect finding from any of valvur's own Checks on any real project, on `full`
  > included — every Go module and Maven coordinate verified to exist.

- [x] **22.E.2** Measure the eleven rules. `rules/` holds 4 LLM-output-to-sink, 5
  Python and 2 pinning rules — the whole of *"targeted checks for AI-specific risks"*
  in SAST form. Run them over the corpus and count hits, false positives and misses
  against what a reviewer would expect. Then decide, with numbers: which to keep,
  which to fix, and whether the positioning is carried by these or by the
  agent-config and hidden-Unicode Checks, which are the genuinely novel ones.

  > **Done 2026-09-12. The numbers, on eleven real projects:**
  >
  > | rule | hits | a reviewer would accept | verdict |
  > |---|---|---|---|
  > | `pinning.mutable-action-ref` | 64 | 64 — every one a tag-pinned action | true, and the majority of ALL findings on four repos (cobra 10/11, ripgrep 15/17); **WARNING → INFO** so it ranks last |
  > | `python.weak-hash` | 7 | 0 — cache keys, content ids, HMAC-SHA1; **3 carried `usedforsecurity=False`** | **fixed** (pattern-not on the flag) and INFO; 7 → 4 |
  > | `python.dangerous-eval` / `-exec` | 3 | 0 — Flask's PYTHONSTARTUP and config loader, `llm` loading user-written tools: the feature | **kept as a sink inventory at INFO**, reworded: the `valvur.llm.*` rules report the flow, this names the sink |
  > | `python.subprocess-shell-true` | 1 | 0 — `Popen("git describe", shell=True)`, a constant | **fixed** (pattern-not on a literal command); 1 → 0 |
  > | `python.insecure-yaml-load`, `pinning.mutable-git-ref`, `js.output-to-innerhtml`, the four `llm.output-to-*` | 0 | — | unmeasurable here: no true positive exists in the corpus, including in `simonw/llm`, which does not execute model output. Unchanged; the fixture proves they fire. |
  >
  > 75 rule findings became 71, every one of them now `low`, and the corpus produced
  > **zero high- or medium-severity findings from our own rules** — because the only
  > rules that stayed at ERROR are the ones that never fired on real code. The
  > canary floor holds (broken-repo still yields 14).
  >
  > **The positioning is not carried by these rules.** Eleven repositories, and the
  > SAST half produced no finding a reviewer would act on. What did carry it: the
  > dependency-reality Check verified every declared dependency of every project,
  > on both Profiles, and was right every time — silently, which is the point — and
  > its coverage machinery found the Express lockfile gap (22.E.1); the AI Artifact
  > Check read hundreds of real `.cursorrules` and one real `AGENTS.md` and reported
  > nothing false. The rules are a small honest supplement — the sink half of a
  > taint story whose flow half has no corpus evidence yet. `CLAUDE.md` §1 and the
  > README say so now; the "eleven rules" are not the product.

### F — The first impression

- [x] **22.F.1** Halve the README. It is 408 lines. The record of being wrong in
  public is persuasive to exactly the right reader and a wall to everyone else.
  `EVALUATING.md` is the audit; the README should be the introduction, and point
  there. Keep the three claims, the two snippets, the platform table and the
  what-it-is-not list. Move the rest.

  > **Done 2026-09-12: 464 → 190 lines.** It had grown to 464 since the task was
  > written — Blocks A, B and E each added a blockquote. Kept: the three claims,
  > each with the one command that verifies it; the MCP config and the agent
  > snippet; the results tree; the scanner credit table (P4); what-it-is-not; the
  > platform table. The five coverage blockquotes under claim 2 became one
  > three-row table — *exists? / known CVEs?* per ecosystem — which says the same
  > thing in a tenth of the space and leads with the Checks, as 22.E.2 concluded it
  > should. Moved: the air-gap recipe and its five settings to a new
  > `docs/AIR-GAPPED.md`; the comparison table, the corrected coverage detail
  > (existence offline / JVM-Go on full / the lockfile gap), the SELinux commands,
  > the Fargate non-claim and the agent-snippet lesson into `EVALUATING.md`, whose
  > §5 had gone stale on all of them. The first-run table was already there.
  > Nothing was deleted; every sentence that left the README has a home the README
  > points at.

### G — Environment-gated

- [x] **22.G.1** Kiro. Named as a primary client in every document; never run. Task
  10.2's claim 1. Needs Kiro installed; the harness from 10.2.5 is reusable as-is.

  > **Done 2026-09-12 — claim 1 holds, and the run found a defect in the published
  > rc.** Kiro 0.12.333 was installed after all. A scratch copy of `broken-repo` with
  > the README's exact block in `.kiro/settings/mcp.json`; the harness was not
  > reusable (Kiro has no `-p`), so the owner sent one prompt and the record was read
  > from Kiro's logs and session store. **Before sign-in nothing happens**: the agent,
  > and with it every MCP server, does not initialise (`No valid token found`); the
  > user setting `kiroAgent.configureMCP: Disabled` would also have stopped it, and a
  > workspace `.vscode/settings.json` overrides that — both now in `EVALUATING.md`.
  > **1.6s after sign-in:** `uvx --from valvur valvur-mcp` spawned (PyPI `0.1.0rc1`,
  > resolved through Kiro's login-shell PATH), *"Connected to server with transport:
  > stdio … Successfully connected and synced tools"*. Then: `scan` (consent asked,
  > then auto-approved) → `scan_status` ×10 → `list_findings` → a correct answer that
  > led with **"Status: INCOMPLETE (one scanner failed)"**, named the injection, the
  > hidden Unicode and the KEV-listed Pillow CVE, and asked before doing more. 58s
  > scan, 13 model calls, 1.00 credit.
  >
  > **What it found.** The rc's shim has `IMAGE = "valvur:dev"` hard-coded — it never
  > pulls the published image, so a fresh install's first scan fails "not found";
  > here it picked up today's dev build, a shim/image mismatch F1.9 could not see
  > (both say `0.1.0rc1`), and dependency-reality failed with the new `IndexMissing`
  > message inside the old shim. 12a.2 fixed the derivation without ever naming the
  > published consequence; the CHANGELOG does now. And the ten polls: 0.65 of the
  > 1.00 credit — two thirds of the scan's cost was `scan_status` returning
  > instantly, the same defect 10.2.5 measured in Claude Code (14 polls), now
  > measured in a second client and priced. The agent also chose `profile:
  > "standard"` — the retired name, which is what the rc's schema offers; it
  > resolves (ADR-0016). Cosmetic: uvx's *"Installed 1 package"* on stderr shows as
  > a warning in Kiro's MCP log. Claim 4 (the image-pull message) stays untested —
  > the image was local. Claim 3 gains evidence: Kiro surfaces a server's stderr, so
  > a server that died at startup would be visible there.

- [x] **22.G.2** Confirm Dependabot's `uv` ecosystem actually opens a pull request.
  Switched from `pip` in Block 1 on the strength of documentation; cannot run until
  the repository is public.

  > **Done 2026-09-12, and the premise was wrong: it did not need a public
  > repository.** The first push in twelve days (22.B.1) triggered all three
  > Dependabot ecosystems on the private repository. The `uv` job parsed `uv.lock`,
  > checked pytest, ruff, mypy, jsonschema and hatchling against PyPI and reported
  > "No update needed" for each — every pin was current, so no pull request, which
  > is the correct outcome rather than a missing one. The `github_actions` and
  > `docker` ecosystems opened three PRs the same minute, so the mechanism as a
  > whole is proven; the `uv` half is proven up to the point of needing an update.

**Exit:** the default Profile reports a hallucinated package with no socket; the
release workflow has run once somewhere that does not matter; a stranger's first
minute is measured and published; and the next silent regression is caught by a
corpus, not a user.

**Commit:** *(one per block, as before)*

---

## Phase 23 — What the second client showed

**Goal:** turn the record of one real agent driving the published rc — and the
measurements taken around it — into the five moves that change what a stranger meets
in their first ten minutes, in the order that each unblocks the next.

> **Added 2026-09-12 from a review of build, deploy, operations, architecture and
> functionality, grounded in the Kiro run (22.G.1).** The evidence, so the order is
> auditable: 13 model calls, **1.00 credit, 0.65 of it polling**; 58s on a 12-file
> fixture (28s with the current shim — Checkov 27.9s, Opengrep 18.4s, everything else
> done by 11s); the failure reason truncated at 80 characters in `scan_status`; no
> timing anywhere in provenance; no way for the agent to stop a scan; the image pulled
> on the first *scan* rather than on `update` (claim 4, still untested); the Check
> that exists for agent files unable to see `.kiro/` in a Kiro workspace; and a shim
> on PyPI that looks for a local `valvur:dev` and can never have worked for anyone.
> Measured the same evening: 191MB of the 576MB image is Checkov's site-packages,
> installed unpinned into valvur's own interpreter; `rubygems.org/names` is 196,830
> names in 2.8MB and Packagist's `list.json` 461,636 in 12MB, each one request —
> two of the three "no existence check" ecosystems are an afternoon from offline.
>
> **Nothing here contradicts a locked decision.** Blocks 2 and 3 are the two that
> change the first ten minutes, which is what 10.1 is about to measure — so they
> come before the gate, and Block 1 comes before everything because until it lands
> the only version anyone can install does not work.

```
Block 1  0.2.0                          ─── owner actions; unblocks everything
        ↓                                    (✅ 2026-09-13 — published)
Block 2  the published index            ─┐  BEFORE the usability gate (10.1):
Block 3  valvur doctor                  ─┘  these two are the first ten minutes
        ↓                                    (Block 2 ✅ 2026-09-12)
10.1.1 · 10.1.2  the usability gate
        ↓
Block 4  build and architecture         ─┬─ independent; any order
Block 5  the primary client's own files ─┘
        ↓
12b.1–3  → v1.0.0
```

> **Order superseded 2026-09-13.** The one list at the head of
> [Phase 24](#phase-24--the-audit-and-one-list-of-everything-that-remains) now orders
> every open task, this phase's included, and moved 23.4.1 ahead of the gate; the
> diagram above is history.
>
> **Where this stands on 2026-09-12, evening.** Block 2 is complete — the four
> tasks below carry their notes — and was run out of order with Block 1 because it
> needs nothing from the owner to *build*, only to *reach users*. It kept the
> pattern of every block before it: the real environment found what the unit suite
> could not. The first real pull of the 34MB artifact found a chunk-boundary write
> defect in the streaming reader (`cmp` caught it; a 300,000-name fixture now pins
> it); the Rust task's premise — *"impossible per user"* — was wrong by a factor of
> five, because nobody had measured where `crates.csv` sits in the dump; and the
> first workflow run showed the shim's anonymous pull refused by the private
> package, which added one line to Block 1's list. **Next is Block 3** (`valvur
> doctor` first — 23.3.1), the last engineering before the usability gate; Block 1
> remains the owner's, and now has four items rather than three.

### 1 — `0.2.0`

The published `0.1.0rc1` shim has `IMAGE = "valvur:dev"` hard-coded (found 22.G.1).
It never pulls the published image; a fresh install's first scan fails "not found".
Every day it is the only version on PyPI is a day the product is a broken link.

- [x] **23.1.1** The owner actions, in order: repository public, package public
  (12a.1); PyPI and TestPyPI trusted publishers for `release.yml` / environment
  `release` (12a.7); branch protection (0.14). Then one more rehearsal — the TestPyPI
  and attestation steps go green the moment the repository is public — and the tag.
  *This is 21.A and 21.D.1 restated with the reason the review added; nothing new to
  build.*

  > **Done 2026-09-13 — `0.2.0` is published.** In the order it happened: a
  > pre-public sweep found the AWS identifiers and led to the history rewrite
  > (12a.1); the repository went public by API, the two packages by the owner's
  > click; PyPI's publisher was configured by the owner and checked against the
  > workflow's claims; branch protection and private vulnerability reporting by
  > API. **Rehearsal #5**, the first on a public repository: SLSA attestation passed
  > for the first time, TestPyPI said `invalid-publisher` — step 4 not yet done.
  > **Rehearsal #6**, with the TestPyPI pending publisher in place: the OIDC
  > exchange succeeded and the upload failed one line later — `InvalidDistribution:
  > '2.5' is not a valid metadata version`. `uv build` writes core metadata 2.5 and
  > the twine inside `pypa/gh-action-pypi-publish` v1.14.0 predates it; **the real
  > release would have failed at its last step, after the image was pushed and
  > signed.** The only step that runs twine's check is the TestPyPI upload, so the
  > rehearsal that "was not really required" is the one that caught it. Fixed by
  > pinning v1.14.2 (twine 7), folded into the release-prep PR because the required
  > amd64 check cannot pass on a branch still declaring the arm64-only `0.1.0rc1`.
  > GitHub then had a partial outage — dropped PR events, refused merges, a
  > rehearsal stuck "queued" for 83 minutes and later reported as both queued and
  > completed — so the prep landed by fast-forward and the rehearsal was
  > re-dispatched once Actions recovered. **Rehearsal #7**: every step green,
  > `valvur 0.2.0.dev11` on TestPyPI (which created the project and claimed the
  > name), the image's signature and attestation re-verified from this machine,
  > both architectures. Then the tag, on the owner's word: **`v0.2.0` on that same
  > commit**, and the real run published in six minutes.
  >
  > **The stranger's first run, measured against the published release** (clean
  > venv, empty cache, image removed, Apple silicon, Docker Desktop):
  > `pip install valvur==0.2.0` **1.7s** · `valvur update` **53s** — the image
  > (320MB, said and streamed), the database, KEV, and the published index pulled
  > anonymously with `signature: verified` · first `valvur scan` of the broken
  > fixture **33s**, 76 active findings, complete, `what_left_the_machine:
  > nothing`. **About a minute and a half from nothing to a first result**, against
  > eight minutes the day before Block 2. One thing the measurement found: on a
  > Python without a CA bundle (python.org's macOS build before *Install
  > Certificates.command*) every host-side fetch fails `CERTIFICATE_VERIFY_FAILED`
  > — the image and database still arrive, because the runtime and Trivy fetch
  > those, but KEV and the index do not, and the fallback walk fails the same way.
  > The message names the cause; `valvur doctor` (23.3.1) gains the check.

  > **One item added 2026-09-12, by Block 2:** the **`valvur-index` package must be
  > made public too** — it was created private by the first run of `index.yml`. Until
  > it is, every `valvur update` on every machine is refused anonymously and walks
  > the five registries itself (the CI log on commit `051bdc7` shows it happening),
  > so the "first run 8 min → about 1" that Block 2 built is not yet what anyone
  > gets. Package settings → Danger Zone → Change visibility, as for the image.

### 2 — The published index

Eight minutes to a first result, five and a half of them walking npm, because the
index is built on every user's machine. The walk exists because we have not published
the index. The release pipeline exists now; this is the `trivy-db` pattern ADR-0018
already named as the eventual answer.

- [x] **23.2.1** A daily workflow builds the index (PyPI simple, npm `_all_docs` once
  then `_changes`, and the three below) and pushes it as an OCI artifact —
  `ghcr.io/maverickhq/valvur-index:latest` plus a dated tag — cosign-signed, with the
  `built_at` per ecosystem in its metadata. `valvur update` pulls it (30–50MB, seconds)
  and verifies the signature; the direct walk stays as the fallback and as what the
  workflow itself runs. `VALVUR_INDEX_REPOSITORY` mirrors it the way
  `VALVUR_DB_REPOSITORY` mirrors the database, and `docs/AIR-GAPPED.md` gains the row.
  **First run 8 min → about 1.**

  > **Done 2026-09-12.** `index.yml` (daily 03:23 UTC, and on dispatch): `python -m
  > valvur.name_index build` — the same code as `valvur update --build-index` — then
  > `oras push` with `metadata.json` as the config blob and one gzip layer per
  > ecosystem, `cosign sign` under the workflow identity, then the artifact is pulled
  > back with the shim's own client and `cmp`'d file by file against what was built,
  > with cosign on the runner so the identity regexp is proven daily. **The shim's
  > client is `valvur/oci.py`**, zero dependencies: resolve, manifest, blob, the
  > anonymous bearer challenge and the CDN redirect — both measured against GHCR
  > with `trivy-db:2` before writing a line, and both reproduced by a real
  > `http.server` on loopback in the tests rather than a monkeypatch. Every byte is
  > digest-checked; every file is checked for the sorted-list invariant the reader
  > bisects on, as it streams. **Measured**: the real index is 34MB compressed
  > (npm 25MB); pulled from a local `registry:2` in **1.7s**; pushed with the exact
  > `oras` command the workflow uses. That first real pull found a defect the unit
  > fixtures could not: every name fragment straddling a 1MB chunk boundary was
  > written twice — `cmp` caught it, and a 300,000-name fixture now pins it.
  > **Signature**: verified with `cosign` when installed, stated on one line when
  > not, and a cosign that refuses is `SignatureInvalid` — never a fallback; the
  > same run against the unsigned local artifact was refused with the message that
  > names `cosign copy`/`oras cp --recursive`. Why not verify keylessly in the shim
  > itself, and why not a pinned key, is in ADR-0018's amendment. Anonymous only,
  > pinned by a test: no credential store, no `GITHUB_TOKEN`. `VALVUR_INDEX_
  > REPOSITORY` set explicitly is the only source tried; unset, an unreachable
  > registry falls back to the walk, loudly — and the walk, being 400MB now, skips
  > any registry it walked within twenty hours unless `--build-index` forces it,
  > which is what keeps four CI jobs a push from re-streaming the crates dump.
  > **Until the owner makes the package
  > public (23.1.1), every user's update takes the fallback** — the workflow warns
  > about exactly that and checks the round trip with authenticated tools instead.
  > **First run, dispatched the same evening** (run 34714322697): built in 4m28s
  > (npm walked in full, no cache yet), pushed `ghcr.io/maverickhq/valvur-index:
  > 2026-09-12` = `latest` @ `sha256:2788b2a6…`, signed; the shim's anonymous
  > pull was refused as predicted (*"the registry demands credentials and valvur
  > pulls anonymously (is the package public?)"*), the authenticated `oras pull`
  > matched all five files byte for byte, and `cosign verify` bound the digest to
  > `…/.github/workflows/index.yml@refs/heads/main` at commit `6b372ae` — the
  > Rekor entry names that SHA, which the history rewrite of 2026-09-13 (below,
  > under 12a.1) replaced with `051bdc7`; the signature stays valid, the artifact
  > digest is unchanged, and the old SHA is what the log will always say. The CI
  > run on the same push shows the other side: `update` refused anonymously, fell
  > back, and skipped every registry as walked within the day.

- [x] **23.2.2** Ruby and PHP offline. `rubygems.org/names` (196,830 names, 2.8MB) and
  `packagist.org/packages/list.json` (461,636, 12MB) are each one request and drop
  straight into `name_index.FILES`; a `Gemfile`/`*.gemspec` parser and a
  `composer.json` parser join `dependency_reality.py`. The coverage table goes from two
  ecosystems offline to four, and the corpus's sinatra note changes from "no existence
  check" to a checked project.

  > **Done 2026-09-12.** Measured before deciding the stored form: RubyGems is
  > **case-sensitive** (`rails.json` 200, `Rails.json` 404), so gem names are stored
  > and looked up as spelled and `gem "Rails"` is reported nonexistent, which is what
  > `bundle install` would say; Packagist is case-insensitive and lowercase by rule.
  > The Gemfile parser reads lines, not Ruby: `gem` with its options (`git:`,
  > `github:`, `path:`, `source:` and the `:git =>` spellings skip), and a block
  > stack so gems inside `source "…" do` (a private server), `path … do` and
  > `git … do` are skipped while `group`/`platforms` blocks are transparent;
  > gemspecs contribute `add_dependency`/`add_runtime_dependency`/
  > `add_development_dependency` and define their own gem. The composer parser
  > reads `require`/`require-dev`, skips platform packages (no vendor), and treats
  > the `repositories` a manifest points at — `vcs`/`git` by URL, `path`, `package`
  > by name — as defined locally, because a private library required that way is
  > not a hallucination. On `full`, age from every gem version's `created_at` and
  > from Composer 2's minified `p2` metadata, expanded (a missing `time` means
  > "same as before"). **Proven in the real image**: sinatra (git: and github:
  > sources, groups, gemspecs) and monolog — added to the corpus as its first PHP
  > project — scan offline with no false nonexistent; a workspace with
  > `rails-ai-helper-sdk` and `acme/llm-composer-bridge` reports both, `what_left_
  > the_machine: nothing`. Every assertion mutation-tested (nine killed).

- [x] **23.2.3** Rust, through the published index only. crates.io's daily dump is
  1.86GB — fine for the workflow, impossible per user — and `crates.csv` inside it is
  the name list. `Cargo.toml` parser; `FILES["cargo"]`; the coverage contract says
  "offline, from the published index" and `valvur update` without the published index
  says Rust is unavailable rather than walking anything.

  > **Done 2026-09-12 — and the premise was wrong, which measuring found.**
  > `data/crates.csv` is the archive's *third* member, after 2MB of README and SQL,
  > so a streaming reader reaches it at once and stops when it ends: **381MB read of
  > the 1.86GB, 17.5 seconds, 91MB of memory, 332,494 names** (the CSV carries every
  > crate's README — fields past the `csv` module's limit — and only the `name`
  > column is kept). That is 2.6× npm's walk in bytes and a tenth of it in time, so
  > Rust is walked like the other four: `valvur update --build-index` builds all
  > five, there is no "published only" ecosystem, and the "unavailable" message this
  > task specified was never needed. crates.io folds case and `-`/`_` (`Serde` and
  > `serde-json` both answer with the underscore form) and the dump has no two
  > names that collide under the fold, so `serde-json` in a manifest and
  > `serde_json` in the index are the same crate. The parser reads `[dependencies]`,
  > `[dev-dependencies]`, `[build-dependencies]`, the same under any `[target.…]`,
  > and `[workspace.dependencies]`; `path`/`git`/`registry` entries and
  > `workspace = true` skip; `package = "real"` names the crate that has to exist;
  > every `[package].name` in the tree is local. **Proven in the real image**:
  > ripgrep — a workspace of many members and path dependencies — scans offline with
  > no false nonexistent, and `tokio-ai-agent-runtime` is reported. On `full`, age
  > from `crate.created_at`.

- [x] **23.2.4** `valvur update` pulls the image too, and `scan_status` says *"pulling
  ghcr.io/…:0.2.0 (240MB)"* when the image is not local — checked with
  `image inspect` before the first launch. Claim 4 of 10.2 becomes testable, and is
  tested: remove the local image, run the harness, read the status line.

  > **Done 2026-09-12.** `ContainerRunner.image_present()` (`image inspect`, ms),
  > `pull_size_mb()` (the registry's manifest through the same `oci.py` client —
  > the platform's layers summed from the image index; measured against
  > `ghcr.io/aquasecurity/trivy:0.65.0`, a real multi-platform image: 53MB for
  > arm64 in 0.9s, anonymously; None rather than a guess when the registry cannot
  > say, which a private package cannot) and `pull_image()` (`<runtime> pull`,
  > streamed line by line to the terminal for `update`, captured for a scan).
  > `api._scan_locked` asks first — *before* `compat.check`, which reads no label
  > from a missing image and passes — and a scan over MCP reports `pulling <image>
  > (<n>MB) — the first run only` as its own `Now:` line on `scan_status`, then
  > `image pulled (Ns)` among the completed stages; the CLI prints the same two
  > lines to stderr. `valvur update` pulls before the database, because the
  > database update runs Trivy inside the image and was pulling it silently under
  > Trivy's name. A failed pull is `ImagePullFailed` with the runtime's own words
  > and the `pull` command to run by hand. **Measured as the task asked**: the
  > image deleted (`docker rmi` + prune, 1.6GB reclaimed), `valvur-mcp` driven over
  > stdio with `VALVUR_IMAGE` pointed at a registry on the Docker VM's own network
  > — `image inspect` said absent, the pull ran, and the first `scan_status` (after
  > its 15s wait) read `Completed so far: image pulled (2s), checkov: ok, …`. The
  > pull took two seconds because the registry was VM-local; from GHCR at 100 Mbit
  > it is ~26s, so the first poll would still be inside it and read `Now: pulling
  > …` — that rendering is pinned by a unit test with a slow fake pull. The size
  > was absent on that line, honestly: the shim on the Mac could not reach the
  > VM-local registry's manifest, and the private GHCR package answers 401, so the
  > sized form of the line is measured against trivy's public image and will show
  > for valvur's the day the package is public.

### 3 — `valvur doctor`

Every first-run failure this session was a precondition: rc1's missing image, no
database, no index, Kiro's MCP disabled, Kiro not signed in, SELinux. Each surfaced
as a failed scan, or as silence. A command that checks them in two seconds and names
the fix for each is the difference between a stranger's first ten minutes and their
last.

- [x] **23.3.1** `valvur doctor`: container runtime found and version; image present
  and its build digest against the shim's (see 23.4.4); database present and age;
  index present, age, ecosystems; SELinux enforcing and whether the tree is labelled;
  which Profile can reach what (a DNS probe per registry, only when asked); MCP client
  configuration detected — Claude Code (`.mcp.json`, `~/.claude.json`) and Kiro
  (`.kiro/settings/mcp.json`, `kiroAgent.configureMCP`) — with the server named and
  enabled or not; and, added by the `0.2.0` first-run measurement (23.1.1), **whether
  this interpreter can verify TLS at all** — python.org's macOS build has no CA
  bundle until *Install Certificates.command* is run, and every host-side fetch
  fails `CERTIFICATE_VERIFY_FAILED` while `pip` (which bundles certifi) works. One
  line per check, the fix on the failing ones, exit non-zero if
  any would fail a scan. Also an MCP tool, so an agent runs it *before* `scan` — and
  the `scan_status` failure branch says so.

  **STATUS 2026-09-13:** ✅ `src/valvur/doctor.py`: nine checks in the order a scan
  meets them, each a probe small enough to test against the real thing once and a
  report tested against a healthy machine with one thing broken at a time. **The
  TLS check is a count, not a request:** `ssl.create_default_context()
  .cert_store_stats()["x509_ca"]` — measured 0 on python.org's 3.10 and 3.12, 128 on
  every interpreter that could fetch — so it needs no socket; it is `fail` when the
  database or the index is absent (the first scan's fetch is next) and `warn` when
  the cache is filled (this scan runs; `valvur update` will not). **The runtime
  check runs `info`**, because `image inspect` fails the same way for a stopped
  daemon as for a missing image, and a doctor that said "the first scan pulls it"
  to someone whose Docker Desktop is closed would be wrong. **The image check
  starts a container** (`--network=none`, `cat` of the build-digest file, 2–5s):
  presence, the F1.9 version label against the shim's, and that the runtime, the
  image and this architecture actually work together — the digest itself is
  reported for information until 23.4.4 gives the shim one to compare. Database
  and index: absent is `info` since 24.1 (the first scan fetches them), stale is
  `warn` with the threshold that makes a scan `inconclusive`, and an index missing
  an ecosystem's list names which. SELinux: on an enforcing host the tree's
  context via `os.getxattr`, `fail` with 20.1's measured `chcon` line unless it is
  `container_file_t` or `VALVUR_SELINUX_RELABEL=1`. MCP clients: `.mcp.json`,
  `~/.claude.json` (top level and `projects[<this path>]`), `.claude/settings*.json`'s
  `disabledMcpjsonServers`, `.kiro/settings/mcp.json` (workspace and user) with its
  `disabled` flag, and `kiroAgent.configureMCP` in `.vscode/settings.json` and Kiro's
  user settings — on this project's own machine it found the latter set to
  *Disabled*, which no scan would ever have said. `--network` (MCP: `network: true`)
  is one bounded 3s TCP connect per host, in two groups — what a first run and
  `valvur update` reach (the image's registry, Trivy's first default `mirror.gcr.io`,
  the index's `ghcr.io`, `www.cisa.gov`), each replaced by the operator's mirror
  when `VALVUR_IMAGE`, `VALVUR_DB_REPOSITORY`, `VALVUR_INDEX_REPOSITORY` /
  `VALVUR_NAME_INDEX_URL` or `VALVUR_KEV_URL` names one, and the nine hosts `full`
  reaches — `fail` only when a first-run host is unreachable and a fetch is due.
  `valvur doctor [path] [--network]` exits 1 on any `fail`; the `doctor` MCP tool
  is the same `doctor.run`/`render` through `operations.doctor` (F9.3, the parity
  tests extended); `scan_status`'s FAILED branch now says *"Run `doctor` (the tool;
  `valvur doctor` on a shell) before scanning again"*. Read-only, no socket unless
  asked — pinned by a test whose healthy fixture fails on any probe. **Measured:**
  3.4s on the CLI, 1.7s over stdio, 8.8s with `--network` (all reachable); the
  python.org interpreter with an empty `VALVUR_CACHE` reads `FAIL python: … 0
  trusted roots` and `not ready`, with the cache filled `warn`. 34 tests in
  `tests/test_doctor.py`; 26 mutations, two survived the first round (the `fix:`
  line and the root count were unpinned) and were pinned. Not done: the build-digest
  *comparison* (23.4.4) and the DNS-only probe the task text imagined — a TCP
  connect is what a fetch does first, and proves more.

- [x] **23.3.2** `duration_s` on every `ScannerRun`, in `run.json` and in
  `scan_status`, and *"slowest: checkov 27.9s"* in `SUMMARY.md`. The corpus report
  gains a column. This is how users find the Checkov cost themselves, and how we
  measure 23.4.2.

  **STATUS 2026-09-13:** ✅ `ScannerRun.duration_s`, stamped by `api._run_one`
  around the whole attempt (`applies_to` through report read, so a skipped Scanner
  shows the cost of deciding to skip). On every surface: `run.json` (`duration_s`,
  to a tenth), `scan_status` (*"checkov: ok (40.9s)"* per line plus *"slowest:
  checkov 40.9s — the fleet runs concurrently, so that is about what the scan
  cost"*; a run.json from before this has no key and gets no invented number),
  the progress line while a scan runs (*"Completed so far: gitleaks: ok (7.9s),
  …"*, the surface an agent watches), and one line at the foot of `SUMMARY.md`
  (skipped Scanners never win; an untimed run says nothing). `scripts/corpus.py`
  records `scan_s` (the scan's wall-clock — N1.1's number, for 24.3) and
  `duration_s` per Scanner per repository, prints `scan` and `slowest` columns.
  **Measured, and the reason the task existed:** on the ten-file fixture with the
  published `0.2.0` image, checkov 40.9s, opengrep 26.0s, syft 20.9s,
  dependency-reality 15.8s, trivy 14.3s, licence-file 12.5s, ai-artifact 12.4s,
  gitleaks 7.9s — scan 44s; the same scan against the freshly built `valvur:dev`
  minutes earlier read checkov 59.1s, opengrep 46.7s, scan 60s, and the machine's
  load average was 13.7 both times. The morning's 33s was a quiet machine. Three
  things fall out: Checkov is the scan's length (23.4.6's case, now with numbers);
  Opengrep's 26–47s on ten files is the second cost and worth a look; and the
  three Checks cost 10–16s *each* for work that is milliseconds — three container
  starts of a 576MB image — which is 23.4.2's whole argument, now measurable
  before and after. **And the instrument's first reading on N1.1's own test
  workspace** (this repository minus the venv: 3,404 files) on the same loaded
  laptop: scan 91s — checkov 84.8s, opengrep 69.4s, dependency-reality 57.9s, syft
  53.2s, gitleaks 43.5s, trivy 43.5s, ai-artifact 40.2s, licence-file 9.2s. Gitleaks
  at 43s on 3,404 files is not Gitleaks; it is eight containers reading one
  virtiofs bind mount at once on Docker Desktop while the host sat at load 8–10
  (the constraint test read 60.6s, 94s and 75s over the day on this machine, and
  passed under 60s on Linux CI for every PR). That is 24.3's question — N1.1 as
  written names a line count and no machine — and it now has numbers per Scanner
  per run rather than one wall-clock and a guess. 11 tests in
  `tests/test_timing.py`, 9 mutations killed; the image rebuilt for e2e, 24 of 25
  passing locally with N1.1's budget the one over, on that load.

- [x] **23.3.3** `scan_cancel` as an MCP tool over the `kill_running` that already
  exists; `scan_status` on a cancelled job says so. `--jobs N` on the CLI, honoured by
  the fleet's executor, with a note in the platform docs about Docker Desktop's
  default memory.

  **STATUS 2026-09-13:** ✅ Not over `kill_running` as written — that stops every
  container this *process* started, right for Ctrl-C and wrong for an MCP server
  scanning two workspaces at once — but over a per-runner `ContainerRunner.kill()`:
  `_launch` records each container on the runner as well as in the process-wide
  set, `kill` signals its own live ones in **one** `<runtime> kill a b c…` (per
  container it cost an agent's cancel 6s for seven; one call is 2.7s for eight,
  measured) and sets `runner.cancelled`. `api.scan` reads that flag at three
  points — before the fleet, after it, and once more before anything is written —
  and raises `ScanCancelled`, deliberately not a `ScannerFailed` ("every Scanner
  failed" is what killing them looks like), so a cancelled scan has F1.11's three
  properties over MCP as over the CLI: containers stopped, no Results Folder (the
  lock's `.gitignore` and `.lock` are all that exist), not a failure. `jobs.cancel`
  marks the job *cancelling* and calls the canceller `_run_scan` registered
  (`runner.kill`); whatever the fleet raises on its way down, a job in that state
  ends *cancelled*; a cancel that arrives after the work finished is told "no scan
  is running" and the result stands. `scan_status` waits on a cancelling job as on
  a running one (10.2.5) and reads *CANCELLING — …* then *CANCELLED after Ns —
  cancelled: 4 of 8 Scanner(s) had finished; the rest were stopped and nothing was
  written*. **Measured over stdio against the real image:** 7 containers running,
  `scan_cancel`, 0 running two seconds later, `.security-scan/` holding only
  `.gitignore` and `.lock`. `--jobs N` (`_positive`, refuses 0) bounds the
  `ThreadPoolExecutor`; `VALVUR_JOBS` is the default for every surface, because the
  MCP server takes no flags, and a nonsense value is ignored rather than fatal;
  the README's Platforms section says why (Docker Desktop's VM memory; exit 137
  reported as a failed Scanner). No CLI `cancel` command: Ctrl-C is the CLI's, and
  the parity test is one-directional. 19 tests in `tests/test_cancel_jobs.py`; 18
  mutations, four survived the first round (the pre-fleet check, the post-fleet
  count, the canceller registration, the cancelling wait) and were pinned. The
  loop ran with `PYTHONDONTWRITEBYTECODE=1` after 23.3.5's lesson.

- [x] **23.3.4** No truncation of a failure reason on the MCP surface. `scan_status`
  cut *"…no package-name index for PyPI, so"* at 80 characters; bound the number of
  lines, never the sentence. And the `DONE` response names the next two moves:
  `explain_finding <fingerprint>` for the top item, and `REMEDIATION.md`'s first
  action — the agent never called `explain_finding` because nothing pointed at it.

  **STATUS 2026-09-13:** ✅ `operations._whole_reason`: every line of a failure
  reason, the continuation lines indented under the tool's name, and only the
  count bounded — `REASON_LINES = 6`, then *"… N more line(s) in run.json"*.
  Reproduced the 22.G.1 case for real (an index that cannot be fetched, via
  `VALVUR_INDEX_REPOSITORY=registry.invalid/…`): the three-line reason, 24.1's
  "could not be fetched" prefix included, reads whole on `valvur status`, which is
  the same operation the MCP tool calls. `operations._next_moves`: after the
  counts and before the Scanner list, a `Next:` block with `explain_finding
  <fingerprint> — #rank path:line title` for the highest-ranked **active** Finding
  (not a suppressed one, not a coverage note — 19.C.1's rule for what makes a
  status `findings`) and *"REMEDIATION.md, action 1 of N: <heading>"* read from the
  file's own `## 1.` line so the agent is pointed at exactly what it will find
  there. Nothing when nothing is active; nothing invented for results an older
  valvur wrote (no findings.json, no REMEDIATION.md, or one without numbered
  actions — the second pinned after a mutation survived). The README's agent
  snippet says *"then follow its `Next:` lines"*. 11 tests in `tests/test_mcp_done.py`;
  10 mutations, two survived the first round and were pinned. Not changed: the
  CLI's own *"! tool did not complete:"* line still prints a multi-line reason
  unindented — the terminal is the second surface, and it was never truncated.

- [x] **23.3.5** `valvur gate --fail-on high --no-inconclusive`: one exit code from
  `run.json`, replacing the Python heredoc that `ci.yml` and `release.yml` each carry
  a copy of. `valvur cache` beside it: what is cached, how old, how large, `--clear`.

  **STATUS 2026-09-13:** ✅ `src/valvur/gate.py`: `evaluate(workspace, fail_on,
  no_inconclusive) -> Verdict(failures, summary, exit_code)` with the heredocs'
  three conditions and the threshold they never had — an incomplete run fails at
  every threshold naming the Scanner and its reason; an active Finding (19.C.1's
  word: not suppressed, not a coverage note) at or above `--fail-on`, `any` being
  every one; a lapsed suppression (`valvur.suppression.expired`/`.stale`) at every
  threshold, because if nothing fails the build then mandatory expiry is decoration
  — plus `--no-inconclusive`, which the heredocs never asked. Exit 0/1, and 2 for
  no results. Under `GITHUB_ACTIONS` each reason is a `::error::` annotation; the
  summary counts what was let through (*"0 at or above any; 0 below; 4 suppressed;
  194 excluded by .security-scan.toml"* on this repository's own self-scan, which
  passes the exact command CI now runs). `ci.yml`'s selfscan job and
  `release.yml`'s verify job each lost their heredoc for `valvur gate . --fail-on
  any --no-inconclusive`, and a test pins that neither carries a `json.loads` gate
  again. `valvur cache`: `cache.inventory()` — database, index (each ecosystem's
  count), KEV — with size, age and detail, `human_size`, a total, and `--clear`,
  which removes the three under the **exclusive** cache lock (a scan reading the
  database finishes first, 16.3) and never the directory or the lock file. On this
  machine: database 1.38 GB 1.5 days, index 121.9 MB 1.0 days, kev 78 kB, total
  1.50 GB. 18 tests in `tests/test_gate_cache.py`; 16 mutations, all killed — and
  one lesson for the mutation loop itself: a same-length mutation restored within
  the same second leaves Python's `.pyc` (mtime+size) believing the mutated
  bytecode is current, which showed up as `human_size` returning `2.9 MB` from a
  source that said `3.0`; run mutation loops with `PYTHONDONTWRITEBYTECODE=1`, or
  clear `__pycache__` after. No MCP tool: a gate is CI's question, not an agent's,
  and the CLI-parity test is one-directional by design.

- [x] **23.3.6** `MaverickHQ/valvur-action`: a composite action that installs the
  shim, restores the database and index from the Actions cache (the pattern
  `ci.yml` uses), runs `valvur scan` and `valvur gate`, and uploads `results.sarif`
  to code scanning. CI adoption becomes one `uses:` line, and it is the first thing a
  team evaluating valvur will ask for. Dogfooded by this repository's own self-scan
  job, which replaces its heredoc with it.

  **STATUS 2026-09-13:** ✅ [github.com/MaverickHQ/valvur-action](https://github.com/MaverickHQ/valvur-action),
  public, `action.yml` composite: install (`version` — a PyPI pin, defaulting to
  `0.3.0` because `gate`, `--budget` and `--jobs` are unreleased; a `git+https://…`
  source; or `""` for the `valvur` on PATH), cosign via `sigstore/cosign-installer`
  so the index signature verifies (`verify`, default on — the first run on a real
  runner read *"not verified: cosign is not installed"*, which is the one thing
  the action must not let stand), the index restored from the Actions cache
  (`ci.yml`'s pattern; the 1.3GB database is refetched each run, ~30s), `valvur
  update`, `valvur scan` with `profile`/`budget`/`jobs`, `run.json` read into
  outputs (`status`, `complete`, `active`, `results`), `results.sarif` uploaded
  through `github/codeql-action/upload-sarif` (`sarif`, needs `security-events:
  write`), and `valvur gate` with `fail-on`/`no-inconclusive` (`gate`). Every input
  reaches the shell through `env:`, never interpolated. Its own CI runs it against
  a two-line fixture (PyYAML 5.1, urllib3 1.24.1): once where the gate must fail at
  `critical` and the outputs say `findings`/`true`/≥5, once with the gate off and a
  budget and jobs set, asserting `what_left_the_machine: nothing` — both green,
  ~50s each (install 7s, update 24–28s, scan 7s). **Dogfooded:** `ci.yml`'s
  self-scan job builds the image, puts the tree's venv on PATH, and `uses:
  MaverickHQ/valvur-action@<sha>` with `version: ""`, `profile: full`, `fail-on:
  any`, `no-inconclusive: "true"` — the job gains `security-events: write` for the
  SARIF upload, so valvur's own findings (none, gated) would appear in code
  scanning; `release.yml` keeps the direct commands so a release never depends on
  the second repository, and the workflow test pins both shapes. Not done, by
  design: the `v0` tag, which waits for valvur 0.3.0 on PyPI (the README example
  uses `@v0`; until then the self-test installs from `git+…@main`); and the
  database in the Actions cache — 1.3GB uncompressed is the wrong shape for it.

- [x] **23.3.7** A scan budget. Each Scanner has a 600s timeout and the run has none;
  an agent session with a runaway Checkov waits ten minutes for one Scanner. `--budget`
  (default: none on the CLI, 300s over MCP — F2.6's figure) stops launching new
  Scanners past it, cancels the rest, and reports the run incomplete with the ones it
  cut named. Pairs with `scan_cancel`.

  **STATUS 2026-09-13:** ✅ `api.scan(budget_s=)`: the fleet's `as_completed` gets
  the budget as its timeout; on `TimeoutError` the queued futures are cancelled
  (*"not started: the 20s budget was spent before its turn"*), the running ones
  are stopped through `runner.stop_containers()` — 23.3.3's per-runner kill
  **without** the cancelled flag, because a cut is not a cancel: the Scanners that
  finished are a result and the run is written, incomplete — and each stopped one
  is recorded *"cut by the 20s budget after 20s (exited 137 with no report …)"*.
  A Scanner that finishes on its own between the timeout and the kill is a
  result, not a casualty (pinned after a mutation survived). A runner that cannot
  stop containers (the suite's fakes) still refuses what has not started. The
  budget counts from the fleet's start, not the first run's fetches, which
  announce themselves and have their own timeouts. `ScanRun.budget_s` /
  `budget_cut`; `run.json` gains `budget: {seconds, cut}`; SUMMARY, `scan_status`
  and `gate` report the cut through the failure paths they already had. Over MCP
  `MCP_BUDGET_S = 300` unless the `scan` tool's `budget_s` says otherwise (0 for
  none), bound into the job by `operations._scan_with_budget`; on the CLI none
  unless `--budget SECONDS` (Ctrl-C is the CLI's), refusing 0. **Measured over
  stdio against the real image with `budget_s: 20`:** six Scanners ok in 12–18s,
  Opengrep and Checkov cut at 20s with exit 137, DONE in 26s, `complete: False`,
  zero containers left. 12 tests in `tests/test_budget.py`; 12 mutations, one
  survived and was pinned. F2.7 extended.

### 4 — Build and architecture

- [x] **23.4.1** Checkov in its own virtual environment (`/opt/checkov`), installed
  from a `requirements-checkov.txt` generated with `pip-compile --generate-hashes`.
  Today it shares valvur's interpreter with 300+ transitive packages nobody pins, so
  the image is not reproducible and the SBOM is mostly Checkov. Dependabot watches the
  lock. Measure the image before and after.

  **STATUS 2026-09-13:** ✅ `requirements-checkov.in` (`checkov==3.2.517`) →
  `requirements-checkov.txt` by `scripts/lock-checkov.sh` (`uv pip compile
  --universal --generate-hashes`, uv being the project's tool; the task said
  pip-compile): **96 packages, 1,866 sha256 hashes** — every published wheel and
  sdist of each pin, so one lock serves amd64 and arm64 and musl. The Dockerfile
  copies it before our own files, creates `/opt/checkov` with `--without-pip`,
  installs through the system pip's `--python` with `--require-hashes`, asserts
  the binary exists, symlinks `/usr/local/bin/checkov` so the runner's invocation
  is unchanged, and drops the compiler as before. **Measured:** the image is the
  same 576MB (the bytes moved, 191MB from the system site-packages to 185.5MB in
  `/opt/checkov`); the system site-packages hold pip and valvur and nothing else,
  where before they held 96 packages; the build layer takes 48s; Checkov 3.2.517
  answers from the venv and finds 13 things on the fixture; the F10.4 licence
  check reads 1,261 components added over the base and no GPL; the tree-hash guard
  covers the lock (`tree_parts`/`image_parts` gain `checkov-lock`), so a changed
  hash is a changed image. Dependabot gains a `pip` entry for the lock, grouped.
  **The task's "300+ transitive packages" was 96**, counted. **Found on the way,
  and worse than the task:** the Dockerfile's `RUN … && find … || true` put
  `|| true` over the whole `&&` chain, so the first build of this layer — whose
  `pip install` failed on a misplaced `--python` — produced an image *without
  Checkov* and reported success; the same shape had covered the old `pip install
  checkov` for as long as it existed. The `find` is scoped in a subshell, and
  `test_no_run_chain_in_the_dockerfile_can_swallow_its_own_failure` refuses the
  shape. Three constraint tests; four mutations, one survivor (a by-name install
  hidden behind `--python`) pinned. F2.2 extended. **And the lock's first day paid
  for itself:** the PR's self-scan gate — valvur scanning its own tree — failed on
  the new `requirements-checkov.txt`, because Checkov 3.2.517 pins `asteval==1.0.6`,
  which carries two sandbox-escape advisories (CVE-2026-55244 / GHSA-89v8-rhwq-hf77,
  GHSA-9w56-46f6-3qhx; fixed in 1.0.9), and every Checkov release through 3.2.533
  pins the same. Until the lock existed that dependency was installed at build
  time and appeared in no manifest valvur reads. Now `requirements-checkov.overrides`
  forces `asteval==1.0.10` at lock time (`uv pip compile --override`, each
  override with its reason and the condition for dropping it), the image installs
  the lock with `--no-deps` because the lock *is* the resolution and pip would
  refuse the pair, Checkov 3.2.517 runs on asteval 1.0.10 with the same 13
  findings on the fixture, the self-scan gate reads `0 at or above any`, and the
  constraint test requires every override to name its reason and the lock to
  carry it. A Checkov user who installs it the ordinary way runs the vulnerable
  asteval; ours does not.

- [x] **23.4.2** The three Checks in one container: `python -m valvur.checks all`,
  nine container starts per scan become seven, and one 1.7s interpreter start instead
  of three. Same isolation the Checks have today — they are our code, and they never
  had a network to lose except dependency-reality's, which the batch keeps by running
  it last with the grant the Profile gave. Measure with 23.3.2: expect ~4s off every
  scan on a small repository.

  **STATUS 2026-09-14:** ✅ `python -m valvur.checks batch <workspace> <name>…`
  (named for what it does rather than `all`, since it runs the Checks the Profile
  selected): each Check isolated inside the container — its own findings, its own
  error, its own seconds — and dependency-reality last whatever order was asked.
  `ContainerRunner.run_checks(names, workspace, network)` launches it once, carries
  the grant, keeps the host-side index refusal for dependency-reality (the
  container is launched for the other two), and turns a container that fails or
  answers nonsense into a failure for every Check with the runtime's words. The
  orchestrator gained one internal notion, `api._plan`: a task may answer for
  several adapters, so the fleet's futures map to index lists and the budget's cut
  names every Check in the batch; `_run_checks` gives each Check the outcome
  `_run_one` would have — skipped when it does not apply, failed with the reason
  when the runner raises — timed as the batch, and the widest grant any of them
  was given. `CheckAdapter` is unchanged, so ADR-0013's "no new adapter protocol"
  holds (the ADR is amended to say what did change). A runner without the ability
  — an older one, or a fake — gets the Checks one by one; the suite's fakes gained
  `run_checks` so 806 tests run the production path, with `run_checks_in_process`
  isolating per Check the way the container does. **Measured**, old shim + old
  image against new shim + new image on the ten-file fixture, three runs each on a
  Mac at load 5–7: scan **35.1–46.0s → 31.2–34.6s**; the Checks 7.4–8.4s each in
  three containers → one batch of 7.6–8.1s; Checkov 33.4–43.6 → 29.8–32.7s and
  Opengrep 20.8–24.2 → 17.7–20.3s, which is the two container starts they no
  longer contend with; same 76 findings, `complete: True`. The local e2e suite
  took 6m12s where it had taken 12–13 minutes all day. The task's ~4s held. 21
  tests in `tests/test_checks_batch.py`; 12 mutations, two survivors (a per-Check
  error in the report reported ok; a runner raising on the batch losing the whole
  scan) pinned. One trap on the way: the new shim against the OLD image ran the
  batch entry point that did not exist there and reported the three Checks failed
  — exactly what the tree-hash guard (22.C.1) exists for, and the before/after
  measurement had to pair each shim with its own image. **Then CI's published-image
  job failed the same way** — the tree's shim against the published `0.2.0` image,
  the one job pointed at what users get — and that is not a CI artefact: a
  `VALVUR_IMAGE` pinned to an older image, or a newer shim on an older image within
  the same 0.x minor, would have lost all three Checks while F1.9 called the pair
  compatible. So the runner tells that image apart — its entry point answers
  `usage:` and exit 2 — raises `BatchUnsupported`, and the fleet runs the Checks
  one by one as before; measured against the published `0.2.0` image, `complete:
  True`, all three Checks ok, three starts instead of one. Two more tests.

- [x] **23.4.3** `docker buildx bake` with the version, labels and platforms in one
  file. `CONTRIBUTING.md`, `ci.yml`, `release.yml` and `corpus.yml` carry four copies
  of the build command today, and 19.A.3 already showed what copies do. The arm64 half
  of the release build moves to a native arm64 runner and `imagetools create` merges;
  4m36s under QEMU becomes a fraction.

  **STATUS 2026-09-14:** ✅ `docker-bake.hcl`: `dev` (this machine's architecture,
  loaded, `VALVUR_VERSION` from the caller so the F1.9 label is the tree's — the
  file cannot read pyproject and must not guess) and `release` (this runner's
  architecture, pushed to `BAKE_IMAGE` by digest, untagged). The five copies —
  `CONTRIBUTING.md`, `ci.yml` twice, `corpus.yml`, `release.yml`'s verify job —
  all run `docker buildx bake` with the GHA cache passed as `--set` overrides so
  the file itself works anywhere; the rebuild hints in `check_image.py`, the
  tree-hash guard and RELEASING point at it; a constraint test refuses a workflow
  that builds any other way, a release that installs QEMU, or one without the
  arm64 runner. **The release:** a `build` matrix — `ubuntu-latest` and
  `ubuntu-24.04-arm`, each `bake release` natively with a per-architecture cache
  scope, the digest handed on as an artifact — then `release` writes one index
  over the two with `docker buildx imagetools create`, and the platform assertion,
  the signature, the attestation and the SBOM see that index's digest exactly as
  before. **Measured by rehearsal from the branch** (run 34862131855): amd64 46s
  and arm64 54s, side by side, **1m14s wall against 4m50s under QEMU on v0.2.0**;
  the index 7s; sign 6s, attest 5s, SBOM 34s, TestPyPI 18s; the index carries
  `linux/amd64` and `linux/arm64` (plus BuildKit's two `unknown/unknown`
  attestation manifests, as v0.2.0's does), and `cosign verify` on the index
  digest passes with the README's own command. **The first rehearsal failed**, and
  it was the bake file's fault: bake reads its variables from the environment, so
  the release workflow's own top-level `IMAGE` turned the verify job's test image
  into `ghcr.io/…/valvur-rehearsal:dev`, a name nothing then found. The variables
  are `BAKE_IMAGE`/`BAKE_TAG` now, and the release build job sets `BAKE_IMAGE`
  from `IMAGE` explicitly. One more copy that could not drift: the `verify` job
  used to spell the version into the build by hand; it is the same env now.

- [x] **23.4.4** The shim carries the tree hash it was built beside. `release.yml`
  builds the wheel and the image from one tree; put `tree_hash` of the inputs into the
  wheel (a generated `_build.py`, never committed) and compare it to the image's
  `/etc/valvur/inputs.sha256` at scan time, as `doctor` does. This closes the hole rc1
  fell through — same version string, different code, and F1.9 content — as a warning
  in `run.json` and `SUMMARY.md`, never a refusal: a mismatch is a diagnosis, not a
  reason to hide results.

  **STATUS 2026-09-14:** ✅ `hatch_build.py`, a hatchling build hook
  (`[tool.hatch.build.hooks.custom]`): at every `uv build` it computes
  `tree_hash.digest(tree_parts(root))` — the same module, the same inputs the
  image hashes — writes `src/valvur/_build.py` with `INPUTS_SHA256`, force-includes
  it into the wheel, and removes it in `finalize`; never committed (`.gitignore`),
  never copied into the image (`.dockerignore`, where a host value would only be
  stale), and never an input to the digest it holds (`tree_hash` skips the name —
  it sits inside `src/valvur`, which is hashed). The sdist carries the inputs, so
  a wheel built from one computes the same value; an editable install has no
  file and `compat.shim_inputs()` hashes the checkout live, as the e2e guard does;
  a wheel from before the hook answers None. **The image side**,
  `compat.image_inputs(runtime, image)`: `image inspect --format {{.Id}}`
  (milliseconds), then a memo under `~/.cache/valvur/image-inputs/<id>` — first
  read by `cat` of `/etc/valvur/inputs.sha256` in a `--network=none` container
  (2–5s on Docker Desktop, once per image), an image without the file remembered
  as such, a container that did not start (exit 125) not remembered at all. The
  runner's `build_provenance()` hands the pair to the scan; `ScanRun` carries
  `shim_built_from`/`image_built_from`/`build_match` (None when either side is
  unrecorded — nothing invented from nothing); `run.json` gains `build: {shim,
  image, match}`; `SUMMARY.md` and `scan_status` warn on a mismatch with both
  digests and the two fixes; `doctor`'s image line says *built from 958d10ca, the
  tree this shim was built from* or warns with both. **Measured with a real wheel
  in a clean venv:** `_build.py` = `shim_inputs()` = the tree = the image built
  from it (958d10ca…); against the published `0.2.0` image, `match: False`, the
  warning on all three surfaces, and the scan still complete — the diagnosis rc1
  never had. 14 tests in `tests/test_build_hash.py`, one of them a real `uv build`
  that opens the wheel; 13 mutations, two survivors pinned (a `cat` that printed
  noise while failing; a container that did not start being remembered as an
  answer). F1.9 extended. Not done: a *refusal* — deliberately, per the task; and
  `doctor` still starts a container to read the digest rather than using the memo,
  because that start is the point of its image check.

- [x] **23.4.5** Measure osv-scanner's marginal value on the corpus: findings on `full`
  that Trivy did not report, per ecosystem, from the report `corpus.yml` already
  writes. cobra went 11 → 132 on `full`; the fixture went 36 merged of 38. Keep it
  with the number in the README's scanner table, or drop it from `full` — either is
  fine; "a second advisory source" without a number is not.

  **STATUS 2026-09-14:** ✅ Measured from the two reports of run 34764187516 (twelve
  repositories, `ubuntu-latest`, 2026-09-13), by rule, `full` minus `offline`:
  **cobra +121** — every one a Go standard-library advisory (`CVE-2022-1705` is
  `GO-2022-0525`, net/http Transfer-Encoding; OSV lists 132 for `stdlib` 1.15.0,
  osv-scanner reported 121), keyed on `go 1.15` in `go.mod`, which Trivy reports
  only from compiled binaries and which describes the toolchain rather than the
  repository's code; **flask +1** — `CVE-2026-7246`, a *disputed* Click advisory
  Trivy's database does not carry; **the other ten +0**, across npm (express,
  fastify), Ruby (sinatra), PHP (monolog), Rust (ripgrep), Java (gson), Python
  (requests, llm), Terraform and the cursorrules corpus. So per ecosystem: Go is the
  whole of it, Python one disputed entry, everything else nothing. **Kept, with the
  number**: the Go toolchain gap is real for a Go application, it costs about a
  second (0.9–1.9s per repository, 23.3.2), and OSV is the second primary source §3
  names — but the README's scanner table now says exactly what it adds, and
  EVALUATING says that a project with no Go will get nothing from it Trivy did not
  give, at the price of its lockfile's names and versions leaving the machine
  (`full` only). The measurement repeats with every corpus run: `scripts/corpus.py
  compare report-offline.json report-full.json` prints per-repository advisories
  added and the rest, and `corpus.yml` runs it and uploads `corpus-compare.txt`;
  one test on the arithmetic, one mutation (a rule that shrank counted as added)
  survived and was pinned. The task's own numbers held: cobra 11 → 132.

- [ ] **23.4.6** Checkov on demand. It is 191MB of the image, the slowest Scanner by
  ten seconds, and `applies_to` already knows when there is nothing for it to read —
  yet every user pulls it and every scan of application code pays its startup. Two
  shapes to measure: a second image (`valvur-checkov`) pulled the first time
  `applies_to` says yes, or a `slim` tag of the main image without it. Either way the
  README's first-run table gets a smaller number for the common case, and 23.3.2's
  timing says exactly how much smaller. Decide with the measurement, not before.

### 5 — The primary client's own files

- [x] **23.5.1** `.kiro/` into the AI Artifact Check: `steering/*.md` are agent
  instructions; `settings/mcp.json` carries `autoApprove` (the key is already checked
  under `.mcp.json`); **`hooks/` run shell commands on file events**, which is an
  autonomous-execution surface and exactly §4's concern — a new rule,
  `valvur.ai-artifact.hook-runs-command`, at high. With it the other clients the Check
  does not know: `.clinerules`, `.roo/`, `.continue/`, `.aider.conf.yml`. A Kiro
  workspace was scanned today by the Check that exists for it, and it could not have
  seen a poisoned steering file.

  **STATUS 2026-09-18:** ✅ **Block A, A1.** `.kiro/steering/`, `.kiro/settings/mcp.json`
  and `.kiro/hooks/` are read (`KIRO_DIRS`; a `.kiro` below the root counts too), and
  `.kiro/specs/` deliberately is not: the project's own documents — and this
  repository's own `tasks.md` contains *"ignore previous instructions"* in the
  sentence that specifies the injection rule, so reading `specs/` would have failed
  our own gate with our own words, found by asking what the self-scan would do
  before writing the code. **The new rule**, `valvur.ai-artifact.hook-runs-command`
  (high, ranked with `permission-bypass`), fires on a hook whose *type* runs a shell
  — a Kiro hook of action type `command`, in **both** formats Kiro has shipped (a
  `hooks` list with `trigger`/`action`, and the older one-per-file `when`/`then`
  with `runCommand`); a Claude Code `type: command` handler under `hooks` in
  `.claude/settings.json` or `settings.local.json`, the other primary client's
  identical surface; aider's `lint-cmd`/`test-cmd`, which run after every edit —
  never on an agent/prompt-type hook, even one carrying a stray `command` key, since
  the type decides what executes. Title names the event and the hook; the command
  is the evidence, fenced (F3.13); identity is the file and the hook's name, so a
  line shift does not move it. **The clients the Check did not know:** `.clinerules`
  (file *and* directory form), `.roo/` (its `mcp.json` says `alwaysAllow` for what
  Kiro calls `autoApprove` — one list of keys now), `.roomodes`, `.continue/`,
  `.windsurf/`, `.aider.conf.yml` (`yes-always: true` is a permission bypass; read
  by line, no YAML parser — the shim stays dependency-free). F3.6 amended, README
  bullet rewritten. **Measured:** the real container on a Kiro workspace as Kiro
  leaves it (steering with a directive, MCP settings with `autoApprove`, one command
  hook, a spec carrying the directive) — three Findings, the spec silent, 0.9s in
  the Check. The corpus has none of the new files, so its answer is "still zero on
  hundreds of real `.cursorrules`"; Block A's dispatch confirms it. 27 tests in
  `tests/test_ai_artifact_clients.py`, one of them e2e; twelve mutations, two of
  which survived on the first pass — the hook-type gate was redundant with the
  command-key gate until the tests planted a stray `command` on an agent-type hook,
  which is now the case that makes it load-bearing. Not on `corpus.py`'s suspect
  list: a committed hook on a real project is what the rule is for.

- [ ] **23.5.2** Snapshot the MCP `tools/list` in a test — the JSON both clients see —
  so a schema change is a deliberate diff. The rc offered `standard`, and nothing
  would have shown the change from the profile rename until an agent chose it.

- [ ] **23.5.3** Taint-mode LLM rules, or retire the word. The four `valvur.llm.*`
  rules fired zero times on eleven real projects including an LLM tool; they are
  pattern rules with no sources. *Corrected 2026-09-13 (24.2): three of the four
  ARE taint rules and have been since 2026-08-30 — their sources are the three SDK
  call shapes below and nothing else; the fourth (`output-to-sql`) has no model
  source. The task stands with its premise fixed: widen the sources, then measure.*
  Opengrep taint mode with real sources —
  `openai.chat.completions.create(…).choices[0].message.content`,
  `anthropic.messages.create`, LangChain `.invoke()`, `litellm`, `ollama` — into the
  sinks the INFO rules now inventory. A planted fixture proves they fire; the corpus
  measures whether they ever fire on real code. If after that they still do not, the
  README says "sink inventory" and stops saying taint.

- [ ] **23.5.4** npm adoption on `full`: `api.npmjs.org/downloads/point/last-month/`
  is public and unauthenticated, so *newly registered AND under N downloads* — the
  slopsquat signal design.md specified for F3.3 — is real for half the ecosystems.
  PyPI stays stated as impossible without a third party.

- [x] **23.5.5** Coverage statements that still count as active. The rc run showed
  fifteen `valvur.licence.dependency-unknown` findings — one fact, since collapsed to
  one Finding — and the corpus shows `valvur.licence.dependencies-unreadable` on six
  of eleven real projects: *"licences could not be determined"* is a statement about
  what valvur could read, not a defect in the code, yet it is an active, low Finding
  that makes a project read `findings` with nothing wrong in it. Decide the class:
  either these join `coverage.NOTE_RULES` (never active; but a licence gap must NOT
  make a security verdict `inconclusive`, so the note machinery needs a "does not
  cast doubt" flag), or they stay active with the rule that a gate keyed on
  high/critical never sees them, and the README says so. The REMEDIATION wording that
  put two versions in one sentence — *"so `json5` reaches 2.2.2, 1.0.2"* — is fixed in
  passing: one target per action, the minimal one, as the CHANGELOG already promises.

  **STATUS 2026-09-17:** ✅ **The first shape, with the flag.** Three rules —
  `dependencies-unreadable`, `dependency-unknown`, `unidentified` — are
  `coverage.LICENCE_STATEMENT_RULES`, in `NOTE_RULES` (never active, `not covered`
  on every surface, invisible to `valvur gate` at every threshold) and *not* in the
  new `coverage.DOUBT_RULES` (the two gaps, which alone make a nil result
  `inconclusive`); `ScanRun.doubts` reads the second set, `SUMMARY.md` renders the
  two kinds as two blocks — *"Part of this repository was not inspected at all"*
  stays the gap's sentence, *"What valvur could not read"* is the statement's, ending
  *not counted in the verdict*. The sets are pinned apart by test so a new note has
  to choose. Missing licence file, contradiction, copyleft-in-permissive stay
  Findings: facts about the project. F4.6 annotated. **Measured on the corpus
  before the change** (`tests/corpus/report.json`, `full`): a licence statement
  active on eight of twelve repositories; awesome-cursorrules — a CC0 `LICENSE`, no
  signature — reading `findings` on it and nothing else. **Measured after, through a
  rebuilt image, on the two repositories the change touches differently:**
  awesome-cursorrules `findings` → **`clean: 0 active, 1 not covered`**, the
  terminal line *`· could not read: Licence file present but its licence could not
  be identified`*, `SUMMARY.md` listing it under *What valvur could not read*;
  express unchanged at `inconclusive` — the lockfile gap still casts its doubt —
  and its `REMEDIATION.md` no longer opens with *"Remove the hallucinated
  dependencies"*. **The full corpus after landing** (run 35269487234, both
  Profiles `CORPUS PASSED`): awesome-cursorrules `findings` → `clean`, and the
  active count fell by exactly one on each of the seven repositories that
  carried a licence statement — cobra 132 → 131, fastify 5 → 4, flask 22 → 21,
  gson 3 → 2, llm 16 → 15, requests 6 → 5, ripgrep 17 → 16 (its `licence.mismatch`
  stays active, as it should) — with `not_covered` up by one on each; no other
  verdict moved, no Scanner failed. `tests/corpus/report.json` is gitignored, so
  the numbers live here.

  **Two defects found on the way, both older than the task.** (1) `REMEDIATION.md`
  was rendered from *every* Finding, so each coverage note went through `_key` —
  and the lockfile gap, *"npm dependencies were not checked for known
  vulnerabilities"*, came out as **"Remove the hallucinated dependencies"** on every
  repository without a lockfile (express, on the corpus), and from there into
  `scan_status`'s *"REMEDIATION.md, action 1 of N"* since 23.3.4. Notes are now
  counted aside in one line and left to `SUMMARY.md`; the partition test counts
  actions against Findings-about-the-code. (2) The sentence the task quotes was
  worse than quoted — the golden fixture rendered *"so `json5` reaches 2.2.2,
  2.2.2, 1.0.2"* — and had two causes: Trivy's `FixedVersion` is a comma-joined fix
  per release line and the adapter copied it (now the smallest fix above the
  installed version, OSV's rule, from the shared `versions.version_key`; Trivy's own
  words kept when nothing is above), and `_retarget` wrote the highest fix *across
  the whole root group* after whichever package the first finding named — with the
  first cause fixed alone it read *"so `json5` reaches 1.4.2"*, loader-utils'
  version on json5's name. Now per package: *"Upgrade `webpack` so `json5` reaches
  1.0.2 and `loader-utils` reaches 1.4.2"*. 30 tests in
  `tests/test_licence_statements.py`; fourteen mutations, all caught — including
  the first loop, which reverted uncommitted work with `git checkout` and had to
  be re-run from a baseline commit.

**Exit:** a stranger installs the published version, `valvur doctor` passes or tells
them exactly why not, the first scan lands in about a minute, and the Check that
exists for agent files can see the primary client's own.

**Commit:** *(one per block, as before)*

---

## Phase 24 — The audit, and one list of everything that remains

**Goal:** close the gap between what the requirements say and what the published
`0.2.0` does, found by auditing the one against the other the morning it shipped —
and replace the sequencing notes scattered across Phases 21 and 23 with **one ordered
list of every open task**, so "what is next" has exactly one answer.

> **Added 2026-09-13, from an audit of the requirements against the published
> release.** Three measurements were taken against `valvur==0.2.0` from PyPI and the
> image from GHCR, not the tree. **(1)** A stranger's MCP first run — `scan` over stdio
> with an empty cache, as the README's snippet instructs — finished `complete: False`
> with Trivy and dependency-reality both failed, each saying *"Fetch it once with:
> `valvur update`"*: a shell command the agent has no tool for, and one the snippet
> never mentions. P1 says *one command*; the primary path needs two and hides the
> second. **(2)** `uvx --from valvur valvur-mcp` — the README's primary install —
> answers `serverInfo.version: 0.2.0`; that path is real for the first time.
> **(3)** The CLI first run: `pip install` 1.7s, `valvur update` 53s, first scan 33s.
> The requirements audit found three claims the traceability ratchet cannot see
> through, because it proves an ID is *cited*, not *met*: F3.10 (four Opengrep rules
> that fired zero times on twelve real repositories, still listed as a feature in
> the README), F1.10 (never run on AWS), and N1.1/N1.4 (evidence thin: no timing on
> a 50k-line repository, memory measured once by hand). And `0.1.0rc1`, the shim
> that looks for `valvur:dev`, is still installable by pin.

### The list — every open task, in the order it should be done

**This list is authoritative for order** — *until 2026-09-18, when
[Phase 25](#phase-25--one-block-to-the-release-then-the-three-checkpoints) took
that over; every row and number here stands, and Phase 25 says when.* Each task's own text remains authoritative
for what it means. The diagrams in Phases 21 and 23 are history; where they disagree
with this list, this list wins. Items marked *owner* need a person; everything else
is engineering and proceeds in this order. The usability gate (13–14) needs a
stranger and a calendar, so it is arranged while 1–12 are built and its findings
(15) are acted on before Blocks 4 and 5.

> **Amended 2026-09-17.** Block 4's engineering (16–19) ran on 2026-09-14, ahead of
> the gate: the stranger was not yet arranged, and none of the four changes what a
> first run meets. 23.4.6 (20) stays behind the gate. **What the gate now depends
> on that this list does not name:** 10.1.2 has the stranger install *the way the
> README says*, and the README installs from PyPI — which is `0.2.0`, without
> `doctor`, the first-run fetch, the budget or `scan_cancel`. Seventeen tasks have
> closed since `0.2.0` shipped (2–12, 16–19, 25 and, on 2026-09-18, 21) and none is
> released; run against
> `0.2.0`, the gate re-finds 24.1. A `0.3.0` release — a rehearsal, then the tag,
> as `RELEASING.md` describes — is an owner action no row carries; it is **Batch 2**
> below, and `valvur-action`'s `v0` tag waits on the same release (23.3.6).

| # | task | what | who | batch |
|---|---|---|---|---|
| 1 | [24.4](#phase-24--the-audit-and-one-list-of-everything-that-remains) | yank `0.1.0rc1` on PyPI | **owner**, one click | 2 |
| 2 | 24.1 | `scan` fetches what is *absent* on a first run, and says so — the primary path's one command | ✅ 2026-09-13 | ✅ |
| 3 | 24.2 | the README stops claiming the LLM-output-to-sink rules as a feature | ✅ 2026-09-13 | ✅ |
| 4 | [23.3.1](#3--valvur-doctor) | `valvur doctor`, with the CA-bundle check | ✅ 2026-09-13 | ✅ |
| 5 | 23.3.2 | `duration_s` per Scanner; the corpus gains timings | ✅ 2026-09-13 | ✅ |
| 6 | 24.3 | requirements: F1.10 retired; N1.1 and N1.4 given evidence or amended | ✅ 2026-09-13 | ✅ |
| 7 | 23.3.4 | no truncation over MCP; `DONE` names the next two moves | ✅ 2026-09-13 | ✅ |
| 8 | 23.3.5 | `valvur gate`, `valvur cache` | ✅ 2026-09-13 | ✅ |
| 9 | 23.3.3 | `scan_cancel`, `--jobs` | ✅ 2026-09-13 | ✅ |
| 10 | 23.3.7 | a scan budget | ✅ 2026-09-13 | ✅ |
| 11 | 23.3.6 | `MaverickHQ/valvur-action`, dogfooded | ✅ 2026-09-13 | ✅ |
| 12 | [23.4.1](#4--build-and-architecture) | Checkov hash-locked in its own venv — moved ahead of the rest of Block 4: the one image input signed with our identity that is not pinned by hash | ✅ 2026-09-13 | ✅ |
| 13 | [10.1.1](#101--the-usability-gate) | the usability gate: protocol, participant, recording | **owner** + a stranger | 3 |
| 14 | 10.1.2 | they install it the way the README says | with 13 | 3 |
| 15 | [12b.1](#12b--release) | act on what the gate found | | 3 |
| 16 | 23.4.2 | the three Checks in one container | ✅ 2026-09-14 | ✅ |
| 17 | 23.4.3 | `buildx bake`, native arm64 | ✅ 2026-09-14 | ✅ |
| 18 | 23.4.4 | the shim carries its build hash | ✅ 2026-09-14 | ✅ |
| 19 | 23.4.5 | measure osv-scanner's marginal value | ✅ 2026-09-14 | ✅ |
| 20 | 23.4.6 | Checkov on demand, or a slim image | decided by 5 | 5 |
| 21 | [23.5.1](#5--the-primary-clients-own-files) | `.kiro/` into the AI Artifact Check | ✅ 2026-09-18 | ✅ |
| 22 | 23.5.2 | `tools/list` snapshot | | 1 |
| 23 | 23.5.3 | taint-mode LLM rules, or retire the word | resolves 24.2 for good | 4 |
| 24 | 23.5.4 | npm adoption on `full` | | 4 |
| 25 | 23.5.5 | coverage statements counted active | ✅ 2026-09-17 | ✅ |
| 26 | 12b.2 | the constraint suite against the release artifact | | 2 |
| 27 | 12b.3 | `v1.0.0` | **owner** | 6 |

### Run in batches — the 12 open tasks grouped, and the order re-cut

> **Superseded 2026-09-18 by [Phase 25](#phase-25--one-block-to-the-release-then-the-three-checkpoints).**
> Batches 1, 4 and 5 and 12b.2 are its Block A, run as one block with one corpus
> dispatch and one rehearsal; Batches 2, 3 and 6 are its three checkpoints. The
> reasoning below stands; the order there wins.
>
> **Added 2026-09-17.** Twelve boxes remain, three of them the owner's. Run one at
> a time they are twelve review cycles and — the expensive part — an image rebuild
> and a corpus dispatch for most of the nine engineering ones. Grouped by what they
> share, the nine collapse into **three batches with one corpus dispatch each**, and
> the three owner-bound items become the checkpoints between them. As for Phases
> 19–21: **a reading order, not a renumbering** — every task keeps its ID, and its
> own text stays authoritative for what it means.
>
> **It re-cuts the table's order in three places, and from row 13 down this section
> wins where the two disagree.** **(1)** Block 5's three that change what a first
> run *reads* — 25, 21, 22 — move ahead of the gate: the stranger measures them or
> finds them. **(2)** 12b.2 (26) moves from the tail into the release: it is a
> `release.yml` job, and the rehearsal `0.3.0` needs anyway is the run that proves
> it. **(3)** The `0.3.0` release itself, which no row carried, is Batch 2 — the
> gate measures the published version, and today that is `0.2.0`.

```
Batch 1  what the stranger's project reads   23.5.5 · 23.5.1 · 23.5.2     one corpus dispatch
              ↓
Batch 2  release 0.3.0                        12b.2 · rehearsal · v0.3.0     owner + pipeline
                                              · valvur-action v0 · 24.4
              ↓
Batch 3  the usability gate                   10.1.1 · 10.1.2 → 12b.1    ─┬─ owner + a stranger; a calendar
Batch 4  claims measured on the corpus        23.5.3 · 23.5.4             ─┘  engineering, while 3 waits
              ↓
Batch 5  image shape                          23.4.6                        its own rehearsal; decided by 3
              ↓
Batch 6  v1.0.0                               12b.3                         owner
```

#### Batch 1 — What the stranger's project reads · 23.5.5, 23.5.1, 23.5.2

Touches `src/valvur/checks/`, `coverage.py`, the AI Artifact rules, the REMEDIATION
wording in `results.py`, and a snapshot test over `mcp/tools.py`. Each PR rebuilds
the image — the tree-hash guard demands it — and **one corpus dispatch at the end
judges all three**: the verdict shift and the new rule's hits arrive in one report.

Together because all three decide what a first-time user *sees*, and the gate's
stranger is the first person who will see it:

- **23.5.5 first**, because it changes the verdict semantics the other two are
  measured under. On the committed corpus report (`tests/corpus/report.json`, run
  34764187516, `full`): `valvur.licence.dependencies-unreadable` is an active
  Finding on **six of twelve** repositories, a licence *statement* of some kind is
  active on eight, and one — awesome-cursorrules — reads `findings` on a
  `licence.unidentified` note and nothing else. A stranger whose project reads
  `findings` with nothing wrong in it is a gate finding already held; the gate's
  ten minutes are for the ones that are not.
- **23.5.1**: a Kiro workspace scanned by the Check that exists for it cannot see
  `.kiro/steering` or `.kiro/hooks` — Block 5's exit criterion in so many words.
  Needs a planted fixture; the corpus has no `.kiro/` and will report zero, which
  is expected and is not evidence.
- **23.5.2 last**: the `tools/list` snapshot is taken after the last change to the
  MCP schema before `0.3.0` — and with `scan`'s `budget_s`, `scan_cancel` and
  `doctor` this week, the schema has moved more than at any point since the rc.

**Commits:** one per task, each with its CHANGELOG line under Unreleased.

#### Batch 2 — Release `0.3.0` · 12b.2, then the owner's clicks

Fifteen tasks closed since `0.2.0` and none released (rows 2–12 and 16–19), plus
Batch 1. **12b.2 goes in first**: a job in `release.yml` after `release`, which
installs the wheel from `dist/` into a clean venv, pulls the image **by the digest
just pushed**, and runs the e2e suite and `valvur gate` against those two. The
`verify` job runs the same suite and gate against `valvur:dev` *before* the push —
that proves the tree, and N2.5 asks for the artifact. `ci.yml`'s `published` job
already does half of this (the tree's shim against the published tag); 12b.2 is
the other half, inside the release that produced the artifact.

Then, in order, as `RELEASING.md` describes: one `workflow_dispatch` rehearsal —
12b.2's job runs for the first time there, which is the point; the version bump
and CHANGELOG date; tag `v0.3.0`; `valvur-action`'s `v0` tag on the commit whose
`version` default is `0.3.0` (23.3.6); and **24.4**, the yank of `0.1.0rc1`, in the
same sitting. Then the README's first-run numbers re-measured against the release,
as 23.1.1 did for `0.2.0`.

#### Batch 3 — The usability gate · 10.1.1, 10.1.2, then 12b.1

Owner and a stranger, on `0.3.0`, installed the way the README says, MCP first.
Nothing engineering waits on it except 12b.1 and Batch 5's decision. The reason in
[the 6 that do not group](#the-6-that-do-not-group) still holds: first impressions
do not reset, so this is the one batch that cannot be re-run.

#### Batch 4 — Claims measured on the corpus · 23.5.3, 23.5.4 — while Batch 3 waits

Together because both are *change it, dispatch the corpus, then decide what the
README may say*: 23.5.3 is rules (`rules/`) plus a planted fixture that proves the
widened sources fire; 23.5.4 is the dependency-reality Check on `full` — one more
public, unauthenticated endpoint, `full` only, §10 untouched. Neither changes the
first run or the MCP shape, so they land *behind* `0.3.0` without changing what
the stranger installs. **One corpus dispatch judges both**, and the two steps that
answer them already exist: `corpus.py rules` (22.E.2) prints per-rule hits,
`corpus.py compare` (23.4.5) prints what `full` added. Each ends in a
`POSITIONING.md`/README claim edit — *taint* kept or retired; *newly registered
and under N downloads* held for npm or not.

#### Batch 5 — Image shape · 23.4.6, alone, after the gate

Alone because it is the one open task that changes the release pipeline again — a
second image or a `slim` tag means the bake file, the `build` matrix,
`_ensure_image` pulling mid-scan and the action's inputs — so it needs its own
rehearsal cycle and should not ride on `0.3.0`'s. And 24.3's measurement already
leans: every corpus repository carries a workflow file, so Checkov runs on all
twelve; an on-demand `valvur-checkov` would be pulled by everyone on their first
scan, and the smaller first-run number *for the common case* mostly disappears.
What the numbers leave is a `slim` tag for people who opt out, or the decision that
nothing here is worth an image — and whether the 223MB pull registered with the
stranger at all is the input to decide with, which is why it waits for Batch 3.

#### Batch 6 — `v1.0.0` · 12b.3

Owner. After 12b.1's fixes land and 12b.2's job has gone green on a real release —
which, by then, it has.

### The audit's tasks

- [x] **24.1** **`scan` fetches what is absent on a first run, and says so.** Measured
  2026-09-13 against the published `0.2.0`: over MCP, with an empty cache, the first
  `scan` finishes incomplete — Trivy and the dependency-reality Check fail, each
  naming `valvur update`, which the agent cannot run and the README's snippet never
  mentions. Task 14.2 decided valvur does not update by itself, and its three
  reasons were about **staleness**: a hostile download inside a scan the user asked
  to be fast, the Profiles diverging, and refreshing on the user's behalf being the
  same move as fixing on their behalf. **Absence is a different case** — without the
  database and the index there is no scan at all, and 23.2.4 already crossed this
  line for the image, with the pull announced on `scan_status`. So: when the
  database or the index is *absent*, `scan` fetches it first and reports it the same
  way (*"fetching the vulnerability database (118MB) — the first run only"*), on the
  CLI and over MCP; when either is *stale*, nothing changes — the warning stands and
  the user decides. The README's agent snippet then needs no `update` line, and
  `valvur update` remains the way to refresh. Tested the way 23.2.4 was: empty
  cache, `valvur-mcp` over stdio, read `scan_status`. **P1 becomes true on the
  primary path.**

  **STATUS 2026-09-13:** ✅ **Measured the way 23.2.4 was, from a stranger's state —
  the image removed, an empty `VALVUR_CACHE`, `valvur-mcp` over stdio, one `scan`
  call: `complete: True` in 110s**, 76 findings, `left this machine: nothing`.
  `scan_status` read, in turn, *"Now: pulling ghcr.io/maverickhq/valvur:0.2.0
  (223MB) — the first run only"*, *"Now: fetching the vulnerability database (119MB)
  — the first run only"* (`Completed so far: image pulled (22s)`), *"Now: fetching
  the package-name index (35MB)"* (`… database fetched (30s)`), then the eight
  Scanners (`… index fetched (7s), gitleaks: ok, …`). The CLI with the image present:
  four lines on stderr, 91s. **How:** `api._ensure_data` runs in `scan` after
  `_ensure_image` and **before the shared cache lock** — both fetches take it
  exclusively, and a shared lock already held on another descriptor of the same
  file in this process would deadlock them (the image pull moved out of
  `_scan_locked` for the same reason; the order test now goes through `scan`). The
  database is `runner.update_db()`, the same call `valvur update` makes; the index
  is `name_index.refresh(…, fallback=False)` — a new flag, because the seven-minute
  registry walk is exactly the download 14.2 called hostile inside a scan, so a scan
  pulls the published index or fails naming `valvur update`, which walks. Sizes come
  from the registries' manifests through `oci.image_size` (which gained `insecure=`
  for an operator's mirror): `ContainerRunner.db_size_mb()` against
  `DEFAULT_DB_REPOSITORY` (`mirror.gcr.io/aquasec/trivy-db:2`, the first of Trivy's own two defaults; 118.5MB measured, 0.7s) and
  `name_index.published_size_mb()` (35MB; None for a static mirror). The vocabulary
  is two tuples in `api` — `FETCH_STARTED = ("pulling ", "fetching ")`,
  `FETCH_ENDED` — that `operations.scan_status` uses for its `Now:` line (the latest
  message, if it is a fetch, until anything follows it) and `cli` for what it
  prints. **What a failure does:** a fetch that fails costs only the Scanner that
  needed it (F2.5): the run is incomplete, `scan_status` records *"database not
  fetched: <Trivy's words>"*, and `_say_why_unfetched` prefixes that Scanner's
  failure with the reason, ahead of the runner's own refusal that names `valvur
  update` — still the right fix for a person, but not the whole story once a fetch
  has been tried. `oci.SignatureInvalid` is deliberately not caught: a refused index
  signature stops the scan (23.2.1's rule). KEV is not fetched — the image carries
  a snapshot as its floor (ADR-0007), so its absence costs nothing. **The stale case
  is untouched**, and 14.2's pin changed shape: it inspected `scan`'s source for the
  word `update_db`, which the new structure would have passed vacuously; it is now a
  scan against a 45-day-old database with an `update_db` that fails the test if
  called. 16 new tests in `tests/test_first_run.py` (the exclusive lock is proven by
  asking for the shared one during the fetch and getting `Busy`); 16 mutations,
  each killed; 678 unit tests; e2e unchanged (CI runs `valvur update` before it).
  The image was rebuilt for the e2e suite because the tree-hash guard (22.C.1)
  demanded it, as it does for any change under `src/valvur` — though nothing under
  `checks/` or the index's reader half changed — and the measurement above used the
  published `0.2.0` image, pulled by the scan itself. F10.8 amended and P1 annotated in `requirements.md`; README, EVALUATING
  (a new first-run row) and CHANGELOG say what changed.

- [x] **24.2** **The README stops claiming the LLM-output-to-sink rules as a
  feature.** Claim 2's third bullet lists *"model output reaching `eval`, `exec`, a
  shell, SQL or `innerHTML`"*; measured on the corpus (22.E.2) those four rules fired
  zero times on twelve real repositories, one of them an LLM tool. That is a
  coverage claim we do not hold (§10). Until 23.5.3 either makes them real with
  taint mode or retires them, the README and `docs/EVALUATING.md` say what is true:
  the rules exist, they are pattern rules, and on real code they have not fired.
  Ten minutes, and it should not wait for the gate.

  **STATUS 2026-09-13:** ✅ Done, and the task's own text was wrong twice, which is
  worth recording in a task about overclaiming. **(1) "twelve"**: the last corpus
  run (34706225304, 2026-09-12 16:45) scanned *eleven* repositories — its job name
  says so — and monolog, the twelfth, was added later that day; the twelve-repo
  corpus has not run yet. Every sentence written today says eleven. **(2) "pattern
  rules … made real with taint mode"**: `rules/llm-output-sinks.yaml` has used
  `mode: taint` since 2026-08-30 for three of the four (sources: `messages.create`,
  `chat.completions.create`, `generate_content`; sinks: `eval`/`exec`/`compile`,
  `os.system`/`popen`/`subprocess(shell=True)`, `innerHTML`); the fourth,
  `output-to-sql`, is a plain string-built-SQL pattern with no model source at all.
  So 23.5.3's question is not "add taint mode" but "why do taint rules with these
  sources never fire on real code" — the sources are three SDK call shapes, and a
  helper that unwraps `.choices[0].message.content`, LangChain, litellm and ollama
  are all outside them; its text is annotated below. **What changed:** the README
  bullet now says what the rules are, that they fire on the fixture, that on eleven
  real repositories including `simonw/llm` they have never fired, and that the
  Checks carry the section; `docs/EVALUATING.md` says the zero is *unmeasured*
  rather than a pass or a fail, since no corpus repository executes model output;
  `docs/POSITIONING.md` gains *"A measured limit on Claim 2"* in the shape Claim 3
  already had, with the rule that the rules may be listed but not sold; F3.10 is
  annotated as cited and exercised, met-on-real-code unmeasured. Nothing in the
  rules, the Scanners or the tests changed: this was a documentation defect, and
  the constraint suite has no test for prose.

- [x] **24.3** **Requirements the ratchet cannot see through.** `check_traceability`
  proves every ID is *cited*; F3.1's own note records that a requirement was cited
  by code implementing a tenth of it. Three need the same explicit treatment F7.3
  got: **F1.10** (identical image on AWS) has never been run there and CLAUDE.md
  already says so — retire it, or defer it with the condition that would revive it;
  **N1.1** (`offline` under 60s on ≤50k lines) has 33s on a twelve-file fixture and
  7–24s on small real projects, and no measurement on a repository of that size —
  23.3.2's `duration_s` on the corpus (ripgrep is the candidate) supplies it, and the
  requirement is then either met with the number or amended; **N1.4** (2GB) was
  measured once by hand at 344MiB and never asserted — record the measurement in
  the requirement and assert it in the e2e suite on Linux, where `docker stats` can.

  **STATUS 2026-09-13:** ✅ **F1.10** split into the half that holds and the half
  that was never exercised: *no cloud-specific code path* is the requirement now,
  asserted on every commit by `test_there_is_no_cloud_specific_code_path`; the
  *targets AWS* clause is struck through and **deferred**, revived only by a
  measured run on a host with a Docker socket (ECS-on-EC2, EC2 — not Fargate,
  ADR-0001), and no document may say valvur runs on AWS until then. **N1.1**:
  the corpus was dispatched on `main` with 23.3.2's timing (run 34764187516,
  `ubuntu-latest`) — every application repository from 22k to 100k lines completes
  `offline` in **14–18s, flat with size** (cobra 44k 14.4s, flask 47.5k 16.1s, llm
  53k 15.2s, gson 64k 16.7s, ripgrep 80k 17.6s, fastify 100k 16.1s), because the
  scan is Checkov's ~15s start-up and every other Scanner is 1–4s; and the one
  infrastructure repository, `terraform-aws-vpc`, took **88.2s, Checkov 87.8s** —
  so the 60s claim is *met with three times to spare on application code* and *not
  held on IaC-heavy repositories*, and the requirement now says both, names the
  machine class (this laptop through Docker Desktop read 60–94s on the same
  workspace under load, a container start being 10–16s there against 2–3s on
  Linux), and states that the data is present. **N1.2** annotated beside it: `full`
  is `offline` plus 0–1s everywhere. **N1.4**: the self-skipping test is replaced
  by a real one — `_FleetMemory` samples `<runtime> stats` in a thread throughout
  a `full` scan of this repository, keeps the highest sum over every `valvur-*`
  container, adds the shim's `ru_maxrss`, and fails above 2 GiB; Linux-only, where
  the accounting is the kernel's (through Docker Desktop's VM the sampler works —
  151 samples, fleet peak 493 MiB, shim 38 MiB on the ten-file fixture — but
  describes the VM's view, so macOS keeps the hand measurement); `ci.yml` runs e2e
  with `-rP` so the passing test's one printed number is in every CI log, and
  `_parse_mem_usage` reads docker's `MiB` and podman's `MB` alike. The committed
  `tests/corpus/report.json` is the run's `full` report, twelve repositories with
  `scan_s` and `duration_s` per Scanner — and the four LLM rules are now zero on
  twelve, so 24.2's "eleven" became "twelve" where it was written. Two findings
  worth more than the task: **Checkov runs on every real repository** (they all
  carry a workflow file, so applicability says yes) and is 85–95% of every scan on
  Linux — 23.4.6's decision has its numbers; and **a container start on Docker
  Desktop costs five times what it does on Linux**, which is most of what a Mac
  user waits for and the whole of 23.4.2's case.

- [ ] **24.4** **Yank `0.1.0rc1` on PyPI.** *Owner action.* The published rc shim has
  `IMAGE = "valvur:dev"` hard-coded (22.G.1) and can never have worked for anyone;
  it is still installable by anyone who pins it. A yanked release stays for people
  who already pinned and stops resolvers choosing it. pypi.org → `valvur` → Manage →
  release `0.1.0rc1` → *Yank*, with the reason *"looks for a local development
  image; use 0.2.0"*.

## Phase 25 — One block to the release, then the three checkpoints

**Goal:** run everything engineering that stands between here and `0.3.0` as **one
block** — one stretch of work, one corpus dispatch, one release rehearsal — and leave
the rest of the plan as three checkpoints that each need a person: the release, the
gate, `v1.0.0`. Written 2026-09-18 from a review of the eleven open tasks.

> **What the review found.** Every open task falls into one of two kinds. Six are
> engineering that no person is waited on for — 23.5.1, 23.5.2, 23.5.3, 23.5.4,
> 23.4.6 and 12b.2 — and each was scheduled apart from the others only because the
> batches of 2026-09-17 sequenced them around a gate that has no date yet. Five need
> a person: 24.4 and the `0.3.0` cut (the owner), 10.1.1–10.1.2 (the owner and a
> stranger), 12b.1 (whatever they found), 12b.3 (the owner). The six share one
> validation apparatus — a corpus dispatch judges 23.5.1, 23.5.3 and 23.5.4 in one
> report; a release rehearsal proves 12b.2 and everything `0.3.0` will carry — so
> running them as one block costs one dispatch and one rehearsal instead of three
> and two, and puts every engineering change into the release the stranger measures.
>
> **This phase is now the one answer to "what is next".** The ordered list at the
> head of Phase 24 keeps every row and every number; its batches of 2026-09-17 are
> re-cut here into Block A and three checkpoints, and where the two disagree, this
> phase wins. Task IDs and task text stay where they are and stay authoritative for
> *what* each task means; this phase says *when*.

```
Block A   the pre-release block          23.5.1 → 23.5.2 → 23.5.3 → 23.5.4 → 23.4.6 → 12b.2
          engineering, no person          one corpus dispatch · one release rehearsal
               ↓
Checkpoint B   release 0.3.0             25.1 rehearsal + tag · 25.2 valvur-action v0 · 24.4 yank
               owner, one sitting
               ↓
Checkpoint C   the usability gate         10.1.1 · 10.1.2  →  12b.1 (engineering, on what they found)
               owner + a stranger; a calendar
               ↓
Checkpoint D   v1.0.0                     12b.3
               owner
```

### Block A — The pre-release block

Six tasks, in this order, each landing by its own pull request; nothing in the block
waits on a person. Every PR rebuilds the image (the tree-hash guard demands it) and
runs the unit suite; the two real-world checks run **once, at the end**.

| # | task | what | why here |
|---|---|---|---|
| A1 ✅ | [23.5.1](#5--the-primary-clients-own-files) | `.kiro/` into the AI Artifact Check — `steering/*.md`, `settings/mcp.json` `autoApprove`, **`hooks/` running shell commands on file events** (`valvur.ai-artifact.hook-runs-command`, high); with it `.clinerules`, `.roo/`, `.continue/`, `.aider.conf.yml` | Block 5's exit criterion in so many words; a Kiro workspace is what the stranger is likeliest to bring. Planted fixture proves it fires; the corpus (awesome-cursorrules' hundreds of real instruction files) proves it does not fire on real ones |
| A2 | 23.5.2 | Snapshot the MCP `tools/list` in a test, so a schema change is a deliberate diff | After A1 and before anything else: no task below changes the MCP schema, so this pins `0.3.0`'s shape |
| A3 | 23.5.3 | Taint-mode LLM rules with real sources — `openai.chat.completions.create(…).choices[0].message.content`, `anthropic.messages.create`, LangChain `.invoke()`, `litellm`, `ollama` — into the sinks the INFO rules inventory; a planted fixture proves they fire | Rules only (`rules/`); the corpus's `rules` step already prints the answer. If the twelve still say zero, the README says *sink inventory* and stops saying *taint* — which resolves 24.2 for good |
| A4 | 23.5.4 | npm adoption on `full`: `api.npmjs.org/downloads/point/last-month/<name>` — public, unauthenticated, `full` only — so *newly registered **and** under N downloads* is the slopsquat signal design.md specified. PyPI stays stated as impossible without a third party | The dependency-reality Check on `full`; §10 untouched (no call on `offline`, no token). The corpus's `compare OFF FULL` step already prints what `full` added |
| A5 | 23.4.6 | Checkov on demand, or a `slim` tag — **decide from the numbers in hand**, then either build the `slim` bake target or close it as declined with the numbers recorded | The measurement the task waited for exists: Checkov is 191MB of the image and 85–95% of every scan (23.3.2); every corpus repository carries a workflow file, so Checkov runs on all twelve (24.3) — an on-demand image would be pulled by everyone on their first scan, and `applies_to` already skips its startup where there is nothing to read. Expected outcome: declined, with the condition that reopens it (a measured user for whom the 191MB is the cost that matters) |
| A6 | [12b.2](#12b--release) | The constraint suite and `valvur gate` against the *release artifact*: a `release.yml` job after `release` that installs the wheel from `dist/` into a clean venv, pulls the image by the digest just pushed, and runs the e2e suite and the gate against those two (N2.5) | Last, because it is the job the rehearsal proves — and the rehearsal that closes the block is the one `0.3.0` needs anyway |

**Validation, once, at the end of the block:**

1. **One corpus dispatch** (`corpus.yml`), read for three things in one report:
   A1's new rule against awesome-cursorrules (zero expected — hundreds of real
   `.cursorrules` are the false-positive test), A3's per-rule hits (`corpus.py
   rules`), A4's `full`-over-`offline` delta (`corpus.py compare`). Both Profiles
   must say `CORPUS PASSED`.
2. **One release rehearsal** (`release.yml`, `workflow_dispatch`): every step against
   throwaway targets, A6's job running for the first time. Green here is the block's
   exit and Checkpoint B's entry.

**Exit (Block A):** six tasks closed with their notes; the corpus and the rehearsal
both green on the tree that will be tagged; `CHANGELOG.md`'s Unreleased section
complete for everything since `0.2.0`.

**Commits:** one per task, Conventional Commits, each PR fast-forwarded onto `main`.

### Checkpoint B — Release `0.3.0` *(owner, one sitting)*

Everything since `0.2.0` — sixteen tasks at the time of writing, twenty-two after
Block A — and nothing of it released. The gate measures the published version, so
this comes before Checkpoint C, not after.

- [ ] **25.1** **Cut `0.3.0`.** In order, as `RELEASING.md` describes: confirm Block
  A's rehearsal is the latest run of `release.yml` and green; bump `pyproject.toml`;
  date the CHANGELOG section; tag `v0.3.0`; watch the tag's run to the end, and read
  A6's job — the first time the constraint suite runs against a real release
  artifact. Then re-measure the README's first-run numbers against the release, as
  23.1.1 did for `0.2.0`, from a stranger's state.
- [ ] **25.2** **Tag `valvur-action` `v0`** on the commit whose `version` default is
  `0.3.0` (23.3.6 left `v0` waiting on exactly this), and switch `ci.yml`'s self-scan
  job from `version: ""` to the tag. The action's README example then works for
  anyone.
- [ ] [**24.4**](#phase-24--the-audit-and-one-list-of-everything-that-remains) — yank
  `0.1.0rc1`, in the same sitting.

### Checkpoint C — The usability gate *(owner and a stranger; a calendar)*

- [**10.1.1**](#101--the-usability-gate) · **10.1.2** — on `0.3.0`, installed the way
  the README says, MCP first, protocol in `docs/usability-gate.md`. First
  impressions do not reset; this is the one checkpoint that cannot be re-run.
- [**12b.1**](#12b--release) — act on what they found. Phase 10's provisional items
  (10.2–10.5) close here or are deferred with a reason. Engineering, sized by the
  findings; may be a `0.3.1`.

### Checkpoint D — `v1.0.0` *(owner)*

- [**12b.3**](#12b--release) — after 12b.1's fixes land and A6's job has gone green on
  a real release, which by then it has. Phase 17's precondition is met.

**Exit (Phase 25):** `v1.0.0` released; someone who had never seen valvur installed
it from the README and got a useful answer; every open task in the plan closed or
deferred with a reason.

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
