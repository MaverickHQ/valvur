# valvur — Open Items (20 items, 5 tiers)

> Generated: 2026-09-21  
> Source: Level 400 codebase analysis (fresh, post-v0.3.0 unreleased work)  
> See also: `.council/20260920-161505/` for the full structured review findings.
> **Reviewed 2026-09-21 against `main` at `ca13795`:** every claim below was checked
> against the code, the workflows and, where a claim was about behaviour, by running
> it — the same treatment the second review's four gaps got at the head of Phase 26.
> Each item carries a **Verdict** line with what was measured.

## The measured tally

| | items | which |
|---|---|---|
| ✅ Already closed before the analysis ran | 1 | T0.1 (26.0.1, 2026-09-20) |
| ✅ Mostly done; one line to fix | 2 | T4.3 (the versions table), T4.4 (cite ADR-0020) |
| ❌ Wrong, measured — not an item | 2 | T1.5 (root `__pycache__` is excluded; 1.30MB context), T2.4 (`scan_status` has shown progress since 24.1) |
| ❌ Premises wrong; a small residue | 1 | T2.1 (an on-failure issue step; the freshness rule stated) |
| ⚠️ Real, narrowed | 4 | T0.2 (order + ref guard; not forks), T1.2 (the README row, not a lane), T1.4 (diagram, §5.1, §8 — not the default), T2.2 (bounded, not permanent) |
| ⚠️ Real as stated | 10 | T0.3, T1.1, T1.3, T2.3, T3.1, T3.2, T3.3, T3.4, T4.1 (tracked *and* in the sdist), T4.2 |

**Open: 17**, of which 7 are under an hour each (T0.3, T4.2, T4.3, T4.4, T3.3, T2.3, T4.1),
7 are an afternoon each (T0.2, T1.1, T1.3, T1.2, T1.4, T2.2, T2.1's residue), and 3 are
refactors for after the usability gate (T3.1, T3.2, T3.4). None of the 17 is a
correctness defect in a scan's result; the two that touch what a user receives are
T0.2 (the daily index can be tagged before it is verified) and T1.1 (the release SBOM's
generator is pinned by tag). What the analysis did not find, and this pass did: the
review's own artefacts are committed and ship in the sdist (T4.1), and `design.md`'s
MCP table is two tools short (under T1.4).

**In `tasks.md` as Phase 27 since 2026-09-21** — sixteen tasks for the seventeen,
ordered by consequence rather than by the tiers above; the task list is the
authoritative record (CLAUDE.md §1) and each task cites its item here.

| item | task | | item | task |
|---|---|---|---|---|
| T0.2 | 27.0.1 | | T4.1 | 27.2.3 |
| T1.1 | 27.0.2 | | T4.3 | 27.2.4 |
| T1.3 | 27.1.1 | | T4.4 | 27.2.5 |
| T2.3 | 27.1.2 | | T0.3, T4.2 | 27.2.6 |
| T2.2 | 27.1.3 | | T2.1 (residue) | 27.2.7 |
| T1.2 | 27.2.1 | | T3.3 | 27.3.1 |
| T1.4 | 27.2.2 | | T3.1 · T3.2 · T3.4 | 27.3.2 · 27.3.3 · 27.3.4 |
| T0.1 · T1.5 · T2.4 | none — closed, wrong, wrong | | | |

---

## Tier 0 — Fix before the next release tag
*3 items. These affect correctness or supply-chain integrity of the next published artifact.*

---

### T0.1 — Parser exceptions escape the fleet failure boundary
**Lens:** Functionality  
**Severity:** High — live correctness gap, violates F2.5

**What is wrong:**  
In `src/valvur/api.py`, `_attempt()` wraps `adapter.run()` in a try/except to catch invocation failures (timeouts, container crashes, etc.) and convert them into a failed `ScannerRun`. However, `adapter.parse(output)` is called *after* the future result is collected, outside that boundary. If any adapter's parser raises — a `json.JSONDecodeError` on malformed output, a `KeyError` on a missing schema field, a `TypeError` on an unexpected null — the exception propagates out of the `ThreadPoolExecutor` as an unhandled error and aborts the entire scan orchestration loop. The result: a single scanner returning malformed output causes the whole scan to fail rather than yielding an INCOMPLETE result with the other scanners' findings intact.

**What should change:**  
Move the `adapter.parse(output)` call inside the same failure boundary as `adapter.run()`. Any exception from parsing should be caught and converted to a `ScannerRun(ok=False, reason=f"parse error: {exc}")` with the raw output retained for `raw/`. The scan continues collecting all other adapters.

**Test to add:**  
A `test_failures.py` case where one adapter's `parse()` raises `json.JSONDecodeError`, and another adapter returns a valid finding. Assert: result is `INCOMPLETE`, the failing adapter is named in `run.json.scanners`, and the valid finding is present in `findings.json`.

**Files:** `src/valvur/api.py` (the `_attempt`/`_scan_locked` boundary), `tests/test_failures.py`

**Verdict (2026-09-21, measured):** ✅ **Already closed — task 26.0.1, 2026-09-20, PR #49.** `api._outcome` (api.py:441) wraps `adapter.parse` and turns a raised parser into `ScannerRun(ok=False, reason="report unreadable: <Exc>: …")` with the raw text kept; `tests/test_failures.py` has the JSONDecodeError case, the AttributeError case, and the report named at the top of `SUMMARY.md` and kept under `raw/`. The analysis read a tree from before that evening.

---

### T0.2 — `index.yml` has no main-ref guard or protected environment
**Lens:** Deploy / Operations  
**Severity:** High — supply-chain exposure on a daily production workflow

**What is wrong:**  
`index.yml` accepts `workflow_dispatch` with no `refs/heads/main` guard. The `publish` job holds `packages: write` and `id-token: write`. Anyone with repository write access can dispatch this workflow from any branch or fork, pushing a signed name-index artifact under the `date` and `latest` tags from non-main code. The workflow's own comment on the round-trip verification step acknowledges that if that step fails, "the tag has already moved." The sign step at line 98 and client verification at lines 100–139 both execute *after* `latest` is assigned at lines 72–93.

**What should change:**  
1. Add a job-level condition: `if: github.ref == 'refs/heads/main'` on the `publish` job.  
2. Create a protected GitHub environment named `index-production` and add `environment: index-production` to the publish job. This gives the option of adding a required reviewer and, at minimum, restricts the deployment to trusted refs.  
3. Restructure the publish step to: push by digest (untagged) → sign → round-trip verify → *then* tag `date` and `latest`. This mirrors the ADR-0020 pattern for the image release.

**Files:** `.github/workflows/index.yml`

**Verdict (2026-09-21, measured):** ⚠️ **Real, narrowed — open.** Confirmed in `index.yml`: `workflow_dispatch` with no ref condition (the only `if:` is `always()` on the report step), no `environment:`, and the order is `oras push "$REPOSITORY:$DATE,latest"` (line 79) → `cosign sign` (98) → round-trip verify (104–139) — the workflow's own comment admits "the tag has already moved". Two corrections: a fork cannot dispatch this — a fork's run has the fork's `GITHUB_TOKEN`, which cannot write `ghcr.io/maverickhq/valvur-index` — so the exposure is a collaborator dispatching from a non-main branch, and this repository has one; and the environment is optional. **What to do:** push untagged (`oras push "$REPOSITORY"`, digest out) → sign → verify → `oras tag "$REPOSITORY@$DIGEST" "$DATE" latest`, the ADR-0020 order; plus `if: github.ref == 'refs/heads/main'` on `publish`. Tests first: the workflow-shape test in `tests/test_constraints.py` asserts the `if:` and that no `oras push` names a tag.

---

### T0.3 — Stale rc1 artifacts in `dist/`
**Lens:** Build / Structure  
**Severity:** Medium — a developer could install the wrong version

**What is wrong:**  
`dist/valvur-0.1.0rc1-py3-none-any.whl` and `dist/valvur-0.1.0rc1.tar.gz` are present in the working tree (dated Sep 5). These are artifacts from the known-bad rc1 release — the one that triggered the entire `TreeHashHook` / `_build.py` mechanism because the version strings agreed while the code did not. `dist/.gitignore` contains `*`, which correctly prevents them from being committed, but they are fully visible on the local filesystem. Running `pip install dist/*.whl` in the repo root installs rc1, not the current tree.

**What should change:**  
Delete both files. The `dist/.gitignore` is correct and will prevent future build artifacts from being committed; the issue is these specific leftover files. Optionally add a `make clean` or `scripts/verify.sh clean` target that removes `dist/*.whl dist/*.tar.gz`.

**Files:** `dist/valvur-0.1.0rc1-py3-none-any.whl`, `dist/valvur-0.1.0rc1.tar.gz`

**Verdict (2026-09-21, measured):** ⚠️ **Real, trivial — open.** `dist/valvur-0.1.0rc1-py3-none-any.whl` and `.tar.gz`, 2026-09-05, present and gitignored. Severity lower than stated: the release builds `dist/` on a clean CI checkout, so nothing published can pick these up; the risk is a developer's `pip install dist/*.whl`. `rm dist/*.whl dist/*.tar.gz`.

---

## Tier 1 — Before the v0.4.0 release tag
*5 items. These are correctness, trust, or documentation gaps that should be closed before the next versioned release.*

---

### T1.1 — Syft in `release.yml` uses a mutable tag; SBOM is single-platform
**Lens:** Deploy  
**Severity:** Medium

**What is wrong:**  
The `stage` job in `release.yml` generates the release SBOM using `anchore/syft:v1.51.1` — a tag, not a digest. The Dockerfile pins every image by index digest with the tag in a comment for Dependabot. The SBOM generator in the release pipeline should be held to the same standard, especially since valvur's own `ai-artifact` rules detect this class of defect (`mcp-mutable-ref`). Additionally, `--platform linux/amd64` means the SBOM describes only one platform of a multi-arch image.

**What should change:**  
1. Pin `anchore/syft` by digest (run `docker buildx imagetools inspect anchore/syft:v1.51.1 --format '{{json .Manifest.Digest}}'` and use the result).  
2. Generate one SBOM per platform and attach both to the GitHub release, or generate from both child digests and merge.

**Files:** `.github/workflows/release.yml` (the SBOM generation step in `stage`)

**Verdict (2026-09-21, measured):** ⚠️ **Real — open.** `release.yml:309` runs `anchore/syft:v1.51.1` by tag with `--platform linux/amd64`; the `Dockerfile:65` already pins the same syft by digest (`sha256:95fe0835…`), so the release SBOM is generated by an image held to a lower standard than the image it describes. Use the Dockerfile's digest, and generate one SBOM per child digest (`stage` has both from the `build` matrix) — two files on the release, each naming its platform. Tests first: the workflow-shape test refuses `anchore/syft:` followed by a tag, and requires both platforms in the SBOM step.

---

### T1.2 — No macOS CI lane; README claim is false
**Lens:** Functionality  
**Severity:** High — a documented feature guarantee with no CI coverage

**What is wrong:**  
`README.md` states that macOS and Linux with Docker or Podman are supported and tested on every commit against both runtimes. The only real-container CI jobs run on `ubuntu-24.04` and `ubuntu-24.04-arm`. The macOS-facing tests in `test_portability.py` monkeypatch `platform.system()` — they cannot exercise Docker Desktop mount sharing, Podman VM path sharing, runtime detection outside PATH, UID translation in containers, or the specific macOS branch in `runner._unreadable_hint()`.

**What should change:**  
Add a `macos-14` runner job covering: install wheel into clean venv, detect runtime, run `valvur scan tests/fixtures/broken-repo --profile offline`, assert complete with ≥20 findings, test a path with a space, assert `valvur doctor` exits 0. If per-commit cost is prohibitive, run on a schedule and on `push: tags`. Update the README claim to match actual CI coverage.

**Files:** `.github/workflows/ci.yml` (new job), `README.md`

**Verdict (2026-09-21, measured):** ⚠️ **Real as a README claim — open; the lane is the wrong fix.** `README.md:227` puts macOS and Linux in one row: *"tested on every commit against both runtimes"*. CI tests Linux on every commit against Docker *and* Podman (`ci.yml:62–108`, the parity job), on amd64 and arm64 — that half is true. macOS is tested by hand: `0.3.0`'s first-run numbers were measured on a Mac through Docker Desktop, and the usability gate (10.1.1) runs there. A macOS CI lane needs a container runtime inside GitHub's macOS runner, which is a VM inside a VM — nested virtualisation, which the standard Apple-silicon runners do not offer; the Intel runner with QEMU-backed Colima is slow and being retired. **What to do:** split the row — Linux, both runtimes, every commit; macOS, Docker Desktop and Podman, verified by hand on each release with the date and the machine — and keep the lane as a measured option, not a claim.

---

### T1.3 — MCP server does not cancel active jobs on exit
**Lens:** Operations  
**Severity:** Medium — resource leak in normal use

**What is wrong:**  
In `src/valvur/mcp/server.py`, `main()` catches `KeyboardInterrupt` and `BrokenPipeError` and returns. Background scan jobs run on daemon threads. Docker/Podman containers launched by those jobs are child processes of the container runtime, not of the Python process — they outlive it. When the MCP server exits (client disconnect, SIGTERM, Ctrl-C), any running scanner containers continue consuming CPU and memory with no owning client. The workspace lock (`.security-scan/.lock`) may also remain held.

**What should change:**  
Wrap `protocol.serve(...)` in a `try/finally` and call `jobs.cancel_all_and_wait(deadline_seconds=10)` in the finally block. `cancel_all_and_wait` should enumerate all active jobs, call each canceller, and wait for settlement up to the deadline, with all output to stderr.

**Test to add:**  
A subprocess-level test: spawn `valvur-mcp`, send `initialize` + `tools/call scan`, close stdin (simulating client EOF), assert within a bounded timeout that no child containers are running.

**Files:** `src/valvur/mcp/server.py`, `src/valvur/mcp/jobs.py` (add `cancel_all_and_wait`), `tests/test_mcp.py` or new `tests/test_mcp_shutdown.py`

**Verdict (2026-09-21, measured):** ⚠️ **Real — open.** `server.main()` (server.py:154–159) catches `KeyboardInterrupt` and `BrokenPipeError` and returns; scan jobs are daemon threads (jobs.py:176); the runner's own comment (runner.py:185) records that the daemon owns a container's lifecycle, so the client dying changes nothing — which is exactly why `kill_running` and the `--name valvur-<id>` registry exist (23.3.3). Nothing calls them on the server's way out. **What to do:** `try/finally` around `protocol.serve`, cancelling every active job through its canceller (26.0.2 made that safe under the lock) and waiting a bounded time; the workspace lock is released by the job's `finally` (jobs.py:172) once the thread returns. Test first: over stdio, `initialize` → `scan` → close stdin, then assert no `valvur-*` container is running within 10s — the shape `tests/test_cancel_jobs.py` already uses.

---

### T1.4 — `.kiro/specs/valvur/design.md` is materially stale
**Lens:** Architecture  
**Severity:** Medium — misdirects anyone using the Kiro IDE on this project

**What is wrong:**  
The design spec contains a diagram placing the orchestrator and normaliser inside the OCI image. The actual orchestration is fully host-side: `api.py` plans and runs the fleet, `pipeline.py` runs the post-fleet stages, `results.py` writes artifacts. The spec also records `full` as the default profile (it's `offline`) and documents dependency-reality coverage that predates the multi-ecosystem offline index from ADR-0018.

**What should change:**  
Replace the stale diagram with an as-built architecture section covering the host orchestration path, the per-scanner `Invocation`/`ContainerRunner` contract, the post-fleet pipeline stages, the MCP background-job path, and the release topology. Link each boundary to its ADR. Mark the current content as historical or replace it outright.

**Files:** `.kiro/specs/valvur/design.md`

**Verdict (2026-09-21, measured):** ⚠️ **Two of three claims real — open, narrowed.** The architecture diagram (design.md:14–36) still draws **Orchestrator** and **Normaliser** inside the OCI image; both are host-side (`api.py`, `pipeline.py`, `normaliser`), and 26.5.2 rewrote §1.1, §1.3, §2, §2a, §6c and §6d that morning without touching the diagram. §5.1 Dependency Reality still says *"`requirements*.txt` against PyPI, and nothing else … widening is task 19.D.1"* and describes offline as "edit-distance and pinning heuristics" — two ADRs stale (ADR-0018, 23.2.2–3). One more the analysis missed: §8's MCP table lists four tools; the registry has six (`scan_cancel`, `doctor`). **Wrong:** §2 records `offline` as the default (line 103), not `full`. **What to do:** redraw the diagram as built (the `Invocation`/`ContainerRunner` seam is already prose in §1.1), rewrite §5.1 from `dependency_reality.py` and ADR-0018, add the two tools to §8.

---

### T1.5 — Root-level `__pycache__/` may not be excluded from Docker build context
**Lens:** Build  
**Severity:** Low

**What is wrong:**  
`.dockerignore` excludes `**/__pycache__` but the root-level `__pycache__/` (containing `hatch_build.cpython-312.pyc`) sits at `./__pycache__` not in a subdirectory. Docker's handling of `**/__pycache__` for a top-level directory varies between BuildKit versions — some match it, some require an explicit `__pycache__/` entry.

**What should change:**  
Add `__pycache__/` as an explicit top-level entry in `.dockerignore`. Verify by running:
```bash
docker buildx bake dev --progress=plain 2>&1 | grep "transferring context"
```
and confirming the context size is approximately ~1MB.

**Files:** `.dockerignore`

**Verdict (2026-09-21, measured):** ❌ **Not an item.** Measured on this machine (buildx v0.31.1): with a root-level `__pycache__/probe.cpython-312.pyc` planted, a `COPY . /ctx` build under the tree's `.dockerignore` transferred **1.30MB** and the exported context held **no `__pycache__` at any level** — `**/__pycache__` matches the root, as Docker's own reference says it does. Nothing to change.

---

## Tier 2 — Operational ownership and observability
*4 items. These do not affect correctness today but represent missing operational infrastructure.*

---

### T2.1 — No operational owner or escalation path for `index.yml` and `corpus.yml`
**Lens:** Operations  
**Severity:** Medium — silent user-facing regressions

**What is wrong:**  
Both `index.yml` (daily) and `corpus.yml` (weekly) document that their failures are "ours to read" but the tree has no CODEOWNERS, no freshness SLA, no automatic notification path, and no runbook for recovery operations. A red `index.yml` means every user's `valvur update` falls back to the full 8-minute registry walk. A red `corpus.yml` means a false positive introduced by a rule change ships undetected. Neither failure surfaces to anyone unless a maintainer checks the Actions tab.

**What should change:**  
1. Create `CODEOWNERS` with named owners for the two workflows.  
2. Add a step to both workflows that opens a GitHub issue on failure (`if: failure()`) with the run link and the recovery command.  
3. Define the freshness SLA in a comment in each workflow file.  
4. Add or update a `docs/OPERATIONS.md` with recovery procedures.

**Files:** `CODEOWNERS` (new), `.github/workflows/index.yml`, `.github/workflows/corpus.yml`, `docs/RELEASING.md`

**Verdict (2026-09-21, measured):** ❌ **Premises wrong; a small residue.** No `CODEOWNERS`, no `docs/OPERATIONS.md`, no `if: failure()` step — those facts hold. The consequences do not: a red `index.yml` that fails *before* its push leaves yesterday's `latest` in place and every `valvur update` keeps pulling it in seconds — the case where a user is hurt is a push *before* verification, which is T0.2, not this; and a scan never walks the registries (24.1). GitHub also mails scheduled-workflow failures to the workflow file's last committer, who is the one maintainer. A `CODEOWNERS` naming one person on a one-person repository records nothing. **Residue worth doing:** an `if: failure()` step on both scheduled workflows that opens an issue with the run link and the recovery command, so a failure is a tracked thing rather than an email; and the freshness rule that already exists (ADR-0018: an index over 30 days makes a scan `inconclusive`) stated in `index.yml`'s header.

---

### T2.2 — Index re-verification skipped after cosign becomes available
**Lens:** Operations  
**Severity:** Low-Medium — trust-state can be permanently unverified

**What is wrong:**  
When cosign is absent at pull time, the index is cached with `"signature": "not verified: cosign is not installed"` in `metadata.json`. On a subsequent `valvur update`, the code checks `built_at` and returns early if current — but `oci.verify_signature` is only called on a fresh pull. An index cached while cosign was absent stays in the unverified state forever, even after the developer installs cosign.

**What should change:**  
After loading cached metadata: if `signature == "not verified: cosign is not installed"` and `shutil.which("cosign")` now returns a path, re-run `oci.verify_signature` against the cached digest. If it passes, update metadata to `"verified"`. If it fails, clear cache and re-fetch.

**Test to add:**  
Seed the cache with unverified metadata. Make cosign available (mock). Assert `valvur update` re-verifies and updates metadata without re-downloading name layers.

**Files:** `src/valvur/name_index.py`, `src/valvur/cli.py`, `tests/test_published_index.py`

**Verdict (2026-09-21, measured):** ⚠️ **Real, bounded — open, low.** `name_index.fetch_published` (name_index.py:337–346) returns before `oci.verify_signature` when every wanted ecosystem's `built_at` matches and the file exists, so an index cached as `"not verified: cosign is not installed"` stays so after cosign is installed. Not permanent: the index is published daily, so the next `valvur update` after the next build re-fetches and re-verifies; the window is until the user next updates, at most the 30 days after which the scan is `inconclusive` anyway. The fix is as described — re-verify the cached digest when cosign has appeared, no layers re-downloaded — and the test seeds the metadata and mocks `shutil.which`.

---

### T2.3 — MCP tool annotations are uniform and incorrect for side-effecting tools
**Lens:** Functionality  
**Severity:** Low — affects MCP client approval flows

**What is wrong:**  
`src/valvur/mcp/server.py` `Tool.describe()` unconditionally returns `readOnlyHint: true` and `destructiveHint: false` for every tool. `scan` writes `.security-scan/`, may pull Docker images, and starts containers. `scan_cancel` changes job state and kills containers. MCP clients can use these annotations for automated approval policies.

**What should change:**  
Give `Tool` per-tool annotation fields (`read_only: bool`, `destructive: bool`). Mark `list_findings`, `explain_finding`, `scan_status`, `doctor` as read-only. Mark `scan` and `scan_cancel` accurately. Update the test that asserts the current global annotation.

**Files:** `src/valvur/mcp/server.py`, `src/valvur/mcp/tools.py`, `tests/test_mcp_snapshot.py` or `tests/test_constraints.py`

**Verdict (2026-09-21, measured):** ⚠️ **Real — open, low.** `Tool.describe()` (server.py:38) returns `{"readOnlyHint": True, "destructiveHint": False}` for all six tools. Per the MCP spec `readOnlyHint` means the tool does not modify its environment; `scan` writes `.security-scan/`, pulls an image and starts containers, and `scan_cancel` stops them — neither is read-only. Both are additive rather than destructive (a cancel writes nothing, F1.11), so `destructiveHint: false` stands. `list_findings`, `explain_finding`, `scan_status`, `doctor` are read-only. The `tools/list` snapshot (23.5.2) will show the diff in review, as it was built to.

---

### T2.4 — `scan_status` shows no partial progress during a long scan
**Lens:** Functionality  
**Severity:** Low-Medium — agent turn consumption

**What is wrong:**  
`mcp/jobs.py` maintains a `job.progress` list that adapters can append to during execution, but `operations.scan_status()` does not surface it. On a real project where a scan takes 2–5 minutes, every poll returns only "running." The progress list exists precisely for this — it is just not surfaced.

**What should change:**  
In `operations.scan_status()`, when the job is in `RUNNING` state, append the last N progress messages (e.g. last 5) to the status text, capped to avoid overflowing a short-context client. The polling contract shape does not change.

**Files:** `src/valvur/operations.py`, `tests/test_mcp_done.py` or `tests/test_mcp.py`

**Verdict (2026-09-21, measured):** ❌ **Wrong — already the behaviour since 24.1 (2026-09-13).** `operations.scan_status` (operations.py:406–423) reads `job.progress` while the job is RUNNING and answers `Now: <fetch in progress>` and `Completed so far: <Scanners>`, and 23.3.2 put each Scanner's duration on it. Measured on a stranger's first run over stdio: the image, the database and the index each announced as they fetched. Nothing to change.

---

## Tier 3 — Architecture refactoring
*4 items. None are bugs today, but each will cause a defect on the next change in its area.*

---

### T3.1 — `dependency_reality.py` is a 1,206-line god module with a circular import
**Lens:** Architecture  
**Severity:** High (as a refactoring target)

**What is wrong:**  
`src/valvur/checks/dependency_reality.py` combines check orchestration, seven ecosystem manifest parsers, registry transport, registry-specific age decoding, and typosquat matching. It has a **bidirectional import** with `name_index.py`: `dependency_reality` imports `name_index` for existence lookups; `name_index` imports `dependency_reality.canonical` for name normalisation. The ecosystem truth is split across `ecosystems.py`, `name_index.py`, and `dependency_reality.py`. Adding a new ecosystem requires coordinated edits in all three files.

**What should change:**  
1. Create `src/valvur/ecosystems/` package with a registry owning: ecosystem name, manifests, index filename, registry URL, age-decoding strategy.  
2. Move each ecosystem's manifest parser behind an interface: `EcosystemParser.parse(path) -> list[DeclaredPackage]`.  
3. `dependency_reality.py` becomes a check orchestrator only. It no longer imports `name_index`.  
4. `name_index.py`'s `FILES` dict moves into the ecosystem registry. `name_index` no longer imports `dependency_reality`.

**Files:** `src/valvur/checks/dependency_reality.py`, `src/valvur/name_index.py`, `src/valvur/ecosystems.py` → `src/valvur/ecosystems/`

**Verdict (2026-09-21, measured):** ⚠️ **Real — open, a refactor.** 1,206 lines; the import is bidirectional and lazy on both sides, which is why it runs: `name_index.py:468` imports `dependency_reality.canonical` inside a function, `dependency_reality.py:101,151,373` import `name_index` inside functions. `ecosystems.py` (130 lines) already exists as the third home. The split proposed is the right shape; it is the largest item on this list and belongs after the gate, in Tier 3 as placed. Tests first: the existing Check tests and `test_published_index.py` are the net; add one that imports each module alone.

---

### T3.2 — `results.py` mixes write orchestration with `SUMMARY.md` rendering
**Lens:** Architecture  
**Severity:** Medium

**What is wrong:**  
`src/valvur/results.py` at 642 lines is both the write authority for the Results Folder AND contains all of `SUMMARY.md`'s rendering logic: `_summary()`, `_verdict()`, `_one_line()`, `_counts_table()`, `_enforce_cap()`, `_slowest()`, all staleness prose, the agent machine header, the profile gap description, the coverage note sections, and the suppression block. The write path and presentation logic share the same module with no boundary between them.

**What should change:**  
Extract the rendering into `src/valvur/summary.py` with a `summary.render(run: ScanRun) -> str` entry point. `results.write()` calls `summary.render(run)` as one of its document generators. `summary.py` becomes independently importable and testable.

**Files:** `src/valvur/results.py` → extract `src/valvur/summary.py`

**Verdict (2026-09-21, measured):** ⚠️ **Real — open, a refactor.** 642 lines; `_summary` runs from line 304 to 563 with `_verdict`, `_slowest`, `_counts_table`, `_one_line` and `_enforce_cap` beside it — about 300 lines of `SUMMARY.md` prose in the module whose job is the atomic write (26.0.3). `summary.render(run) -> str` is the right seam; the write loop calls it like any other document. Behaviour-preserving: the existing summary tests hold the text.

---

### T3.3 — `doctor.py` imports upward from `cli.py`
**Lens:** Architecture  
**Severity:** Medium

**What is wrong:**  
`src/valvur/doctor.py` imports `KEV_URL` and `KEV_URL_ENV` from `src/valvur/cli.py`. This inverts the dependency direction: `doctor` is a pre-flight diagnostic module; `cli.py` is a presentation and entry-point layer. The correct direction is `cli` imports `doctor`, not the reverse. The practical consequence: `doctor.py` cannot be imported in isolation for testing without loading the entire CLI module tree.

**What should change:**  
Move `KEV_URL` and `KEV_URL_ENV` into `src/valvur/enrichment.py` or a new `src/valvur/config.py`. Both `doctor.py` and `cli.py` import from the source-owned module.

**Files:** `src/valvur/doctor.py`, `src/valvur/cli.py`, `src/valvur/enrichment.py` (or new `config.py`)

**Verdict (2026-09-21, measured):** ⚠️ **Real, small — open.** `doctor.py:507` imports `KEV_URL, KEV_URL_ENV` from `cli.py` (defined at cli.py:270–271), lazily, inside the KEV check. The constants belong with the fetch, in `enrichment.py`; `cli` and `doctor` both import from there. Half an hour, and a test that `doctor` imports with `cli` absent from `sys.modules`.

---

### T3.4 — Pipeline stages communicate via mutations to a shared `Context` bag
**Lens:** Architecture  
**Severity:** Low-Medium

**What is wrong:**  
`src/valvur/pipeline.py` defines `Context` with 11 mutable output fields. Stages declare only `list[Finding]` as their return type but communicate results by mutating shared context fields. `api.py` must know which stage set which field and manually copy them into `ScanRun`. A stage-output change is invisible to the `StageFn` interface.

**What should change:**  
Make `pipeline.run()` return a typed `PipelineResult` dataclass containing findings plus all fields currently written by stages to `Context`. Keep `Context` as a stage-local working structure, not exposed to `api.py`. `api.py` constructs `ScanRun` from one `PipelineResult`.

**Files:** `src/valvur/pipeline.py`, `src/valvur/api.py`, `tests/test_pipeline.py`

**Verdict (2026-09-21, measured):** ⚠️ **Real — open, judgment.** `pipeline.Context` (pipeline.py:35–57) has fifteen fields, of which stages write `artifacts`, `coverage`, the three `*_dropped` counts, `unpinned_files` and `identity_reset` while `StageFn` types only `list[Finding] -> list[Finding]`, and `api.py` copies each into `ScanRun` by name. A typed `PipelineResult` is the same move 26.3.2 made for the fleet's tuple. Lowest priority of the four refactors; do it with T3.2 if at all, since both touch how `api.py` assembles a `ScanRun`.

---

## Tier 4 — Housekeeping and polish
*4 items. No correctness impact.*

---

### T4.1 — `.council/` artefacts are not excluded from sdist
**Lens:** Structure  
**Severity:** Low

**What is wrong:**  
`.council/20260920-161505/` holds the structured JSON from the Sep 20 external code review (~25KB). The sdist exclude list in `pyproject.toml` covers `/tests`, `/.github`, `/.kiro`, `/docs`, `/scripts`, `/.gitleaks.toml`, and `/.githooks` — but not `/.council`. A user who installs valvur from the sdist and inspects the archive gets the review artefacts.

**What should change:**  
Add `/.council` to `[tool.hatch.build.targets.sdist] exclude` in `pyproject.toml`. Optionally move to `docs/council/` with a `README.md` explaining origin.

**Files:** `pyproject.toml` (sdist excludes), optionally `.council/` → `docs/council/`

**Verdict (2026-09-21, measured):** ⚠️ **Real — open, and worse than stated.** `.council/20260920-161505/` is not an untracked leftover: it was **committed** on `777c5ec` with Phase 26's documents, six files, and `uv build --sdist` on this tree puts all six in `valvur-0.3.0.tar.gz` — measured. Move it to `docs/council/` (already excluded from the sdist, and where the review it records is referenced from) rather than adding a fourth dot-path to the exclude list; the OPEN-ITEMS reference above changes with it.

---

### T4.2 — `.security-scan/` contains a stale scan result in the working tree
**Lens:** Structure  
**Severity:** Low

**What is wrong:**  
The `.security-scan/` folder at the repo root contains a full-profile scan result from Sep 19. `run.json` shows `"build": {"match": false}` — the shim and image were built from different trees at the time. The folder will never be committed (double-protected), but `valvur gate .` and `cat .security-scan/run.json` give misleading stale output to any developer working in the repo.

**What should change:**  
Delete the folder contents: `rm -rf .security-scan/`. It regenerates on the next `valvur scan`.

**Files:** `.security-scan/` (delete contents)

**Verdict (2026-09-21, measured):** ⚠️ **Real, trivial — open.** `.security-scan/` holds a `full` scan from 2026-09-19 15:14 with `build.match: false`; gitignored by both guards (ADR-0011). `rm -rf .security-scan/`. One caution: do not regenerate it on this machine until after the usability gate — a local scan re-warms the Mac the gate needs cold.

---

### T4.3 — `SECURITY.md` disclosure path should be verified as staffed
**Lens:** Operations  
**Severity:** Low

**What is wrong:**  
`SECURITY.md` exists but for a project in the security tooling space, the credibility of its own vulnerability disclosure process matters. The file should specify a response time commitment and a contact that is actively monitored.

**What should change:**  
Verify the contact is actively monitored. Ensure the file specifies: what is in scope, how to report, expected response time, and the coordinated disclosure timeline. GitHub's private security advisory feature is the easiest implementation.

**Files:** `SECURITY.md`

**Verdict (2026-09-21, measured):** ✅ **Mostly done already; one stale line.** `SECURITY.md` names GitHub private vulnerability reporting — **enabled on the repository, checked by API** — and an email fallback, gives response times (5 and 15 working days), scope and out-of-scope lists, and a disclosure commitment. The one thing wrong: *Supported versions* says `0.1.x` (line 84); it should say `0.3.x`, or "the latest release", which is the policy the sentence above it states.

---

### T4.4 — `release` environment placement not explained in `RELEASING.md`
**Lens:** Operations  
**Severity:** Low

**What is wrong:**  
ADR-0020 explains why the `release` environment sits on the `promote` job (after validation, before irreversible steps), but `RELEASING.md` does not cross-reference this. A maintainer without the ADR context would likely consider moving the environment to `verify` or `stage`, which would break the ADR-0020 guarantee.

**What should change:**  
Add a paragraph to the "Cutting a release" section of `RELEASING.md` explaining that the `release` environment is on `promote` deliberately, with a reference to ADR-0020.

**Files:** `docs/RELEASING.md`

**Verdict (2026-09-21, measured):** ✅ **Mostly done already; the cross-reference is missing.** `docs/RELEASING.md` explains the placement three times — lines 20–22 (the environment is on `promote` since 26.1.1, so a reviewer gates after validation), 224 (a red `artifact` leaves a candidate and nothing installable) and 319–324 (*"The `release` environment is the manual brake … the tag push is the wrong place"*). It does not say `ADR-0020` anywhere. Add the citation to the brake paragraph; a sentence, not a section.
