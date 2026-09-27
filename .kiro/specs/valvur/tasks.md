# valvur: tasks

**Written 2026-09-27, second version of the day.** The owner accepted every recommendation
in [the review](../../../docs/REVIEW-2026-09-27.md), section 11 included, and asked for a list
that runs end to end without them. This replaces the same day's Phases 31 to 37. It is
authoritative for what is open.

**IDs.** Tasks here are `R<phase>.<n>`. A bare ID such as `29.0.5` or `0.1` refers to
[the archive of Phases 0 to 30](../../../docs/history/tasks-phases-0-30.md). §9 maps the
first version's 31 to 37. Requirement IDs are never renumbered; a task that changes one
amends it in `requirements.md`.

**Contents:** 1 unattended running · 2 resuming · 3 how a task is built · 4 how a phase
ends · 5 decisions · 6 order · 7 the phases · 8 the owner queue · 9 earlier IDs

---

## 1. How this list runs unattended

- **One executor.** A Claude Code session in auto mode, in this checkout on this Mac, works
  the phases in order. It does not end its turn between tasks or phases. It ends only when
  §8 is all that remains, or on a stop condition.
- **Nothing on the critical path waits for the owner.** Signed tags, the release approval,
  the gate with a person, AWS spend and Kiro's GUI are collected in §8. The executor
  prepares everything up to them and moves on.
- **Every choice has a recorded answer** (§5). A measurement that misses its threshold takes
  the recorded fallback. Nothing waits for a decision.
- **The only stop conditions:**
  1. a change would cross `CLAUDE.md` §10;
  2. an action would delete or overwrite something outside this repository and the build
     cache;
  3. a required check fails three times for the same cause after fixes;
  4. the machine cannot run containers.

  On a stop, the executor writes what happened and what it needs as a row in §8, commits
  it, and ends its turn.
- **Cost cap.** Agent scoring with `claude -p` is capped at $25 across the build. Past the
  cap it is skipped and noted in §8.
- **Machine hygiene.** Builds, scans and e2e use `BUILD_CACHE=~/.cache/valvur-build` as
  `VALVUR_CACHE` and `VALVUR_IMAGE=valvur:dev`. Never touch `~/.cache/valvur`, pulled
  `ghcr.io/maverickhq/valvur:*` images, or containers the build did not start.

## 2. Resuming

Two mechanisms, armed by R0.1.

- **In-session schedule.** `CronCreate`, cron `17 * * * *`, recurring, with the resume
  prompt below. It fires only while the session is idle, so after a usage limit it resumes
  the same session at the first hourly mark after the limit resets. It lives only as long
  as the session and expires after seven days, so it is re-armed at the start of every
  phase: `CronList`, delete the old job, create a new one.
- **Durable fallback.** A desktop scheduled task, `valvur-build-resume`, cron `43 */3 * * *`,
  which starts a fresh session with the same prompt. It survives app restarts and the
  seven-day expiry. It acts only when the build looks abandoned for eight hours (step 1),
  longer than a usage window plus the hourly schedule, so it does not race a session that
  is only waiting for its limit to reset.

**The resume prompt, verbatim:**

> Resume the valvur build in /Users/maverick/security-scanner. Read CLAUDE.md, then follow
> section 2, "Resuming", of .kiro/specs/valvur/tasks.md exactly, and work unattended as its
> section 1 says.

**What a resuming session does:**

1. **Is another executor alive?**
   A build commit is one whose subject carries a phase scope, `(r<n>` or `(r<n>.<m>`, on
   `origin/main` or an `origin/build/r*` branch. Dependabot and the owner's own commits do
   not count.
   - *In a fresh session:* run `scripts/build_status.py`. If the newest build commit, or the
     newest change in the working tree, is younger than eight hours, end the turn and do
     nothing.
   - *In the session that was building:* if a build branch holds build commits this session
     did not make, another executor has taken over. Delete this session's schedule and end
     the turn.
2. **Where are we?** `git fetch --prune`, then `scripts/build_status.py` names the current
   phase, its branch `build/r<n>-<slug>`, and the first unchecked task. The current phase
   is the lowest-numbered one with an unchecked task, read from its branch if the branch
   exists on origin, otherwise from `main`. Check out the branch, creating it from `main`
   when absent.
3. **Leave nothing half-done.** The session that was building keeps its own changes and
   finishes its slice. A fresh session stashes any working-tree changes with
   `git stash push -u -m "resume <UTC time>: partial slice"` and redoes that slice from its
   last green commit, never trusting it. Either way, if the unit suite is red on HEAD, fix
   that first.
4. **Continue** with the first unchecked task, at its first behaviour without a passing test.
5. **Re-arm** the in-session schedule if `CronList` shows none.
6. **Finish.** When every task outside §8 is done, delete both schedules, write the build's
   summary into R8's STATUS, and end the turn.

## 3. How every task is built: test-driven

- **Each task lists behaviours in test order.** Each behaviour is one red-to-green slice:
  1. write that one test;
  2. run it and see it fail for the expected reason;
  3. write the least code that passes;
  4. run `ruff`, `mypy` and the unit suite
     (`PYTHONDONTWRITEBYTECODE=1 uv run --extra dev pytest -q -p no:cacheprovider -m "not e2e"`);
  5. commit. The commit message follows the repository's Conventional Commits hook, scoped
     by task, and names the behaviour: `feat(r3.4): a Scanner past its timeout is killed
     with its process group`.
- **Never write all the tests first. Never refactor while red.** A refactor is its own
  commit on green: `refactor(r3.4): …`.
- **Test through public interfaces:** `api.scan`, the MCP server over stdio, the CLI,
  `python -m valvur.engine`, `scripts/acceptance.py`. **Fake only two boundaries:** the
  container runtime, through `LocalRuntime` (R3.1), and the network, through
  `tests/fake_registry.py`. `git`, files and processes are real.
- **Assert on fields, kinds and counts.** Assert on a sentence only where the sentence is the
  contract.
- **A behaviour that needs a container** is tested through `LocalRuntime` and again with
  `-m e2e` against `valvur:dev`.
- **Measure first.** A task whose value is a number records the before in its first commit
  and the after in its STATUS.
- **Tick the task's checkbox** in the commit that turns its last behaviour green, so a
  resuming session can see where the build stands.
- **New tests go in new files.** The constraint suite stays at 48 tests unless a task
  restates a constraint, as R3.9 does.
- **Planted credentials are assembled at runtime.** Push protection is on for this
  repository, so no test or generator carries a credential as a literal.

## 4. How every phase ends: the phase commit

1. Every task is ticked and carries a `**STATUS <date>:** ✅` note with its measured after.
2. From R2 on, the phase exit is measured on both lanes (D18) and written to
   `docs/acceptance/r<n>.md`.
3. `CHANGELOG.md` `[Unreleased]` is updated, and so are the status and Next lines of
   `CLAUDE.md`.
4. **The phase commit:** `chore(r<n>): close phase R<n>, <title>, exit measured`.
5. **Land it.** Push, and open one PR for the phase. Wait for the required checks with
   `gh pr checks <number> --watch --fail-fast`, and fix any failure with new commits. Then
   fast-forward `main` with `git push origin refs/remotes/origin/<branch>:refs/heads/main`,
   run `git checkout main && git pull --ff-only`, and delete the local branch.
6. **A release rehearsal**, for a phase that prepares one, runs on the landed `main`
   (`gh workflow run release.yml --ref main`). Wait for its validation, then cancel it at
   the brake so the `release` concurrency group is free. The run id and outcome go into the
   next phase's first commit and into §8.
7. Re-arm the in-session schedule and start the next phase from the new `main`.

## 5. Decisions recorded before the build

The owner accepted all of these with the review on 2026-09-27. R0.5 writes the ADRs. The owner
may revisit any decision with `/grill-with-docs`; a change becomes a new task, and the
executor does not wait for it.

| # | decision | fallback when a measurement disagrees |
|---|---|---|
| D1 | **The File Set is the git view.** It holds tracked files and untracked files git does not ignore. Even when ignored, `.env*` and every agent-configuration file are included, as today. A directory that is not a repository is walked, skipping only VCS metadata and dependency caches, each skip named; past 20,000 files that walk refuses before any container starts, naming the largest directories and the exclude line. A git view over 20,000 files proceeds, with the same names as a warning, because tracked source is the user's code. `scope = "tree"` walks instead. ADR-0021. | none needed |
| D2 | **An exclude is a root-relative path prefix**, applied once, to the File Set. ADR-0021. | none needed |
| D3 | **History is scanned for secrets** in a repository, on all refs. The bound is 5,000 commits or 200 MB of patch, whichever comes first, and the report says when it was hit. `[scan] history = false` turns it off. Measured: this repository's 357 commits make 10.9 MB in 1.2 s. ADR-0021. | a lower bound if a corpus repository exceeds 60 s |
| D4 | **One Scan Container per Profile boundary.** `offline` runs one container with no network. `full` adds one more with a network, for OSV-Scanner and the registry questions. The Snapshot arrives on stdin, into a tmpfs up to 512 MB, or a per-scan volume beyond that, removed afterwards. Protocol 2. One memory ceiling per container: 3 GiB, or 75% of the runtime's memory if that is less. ADR-0022. | none needed |
| D5 | **Freshness.** A stale vulnerability database (over 7 days), Name Index (over 30 days) or OSV database is refreshed inside a scan, announced, and recorded in `network.fetched`. `fetch = "never"`, as a setting or `VALVUR_FETCH=never`, serves air-gapped use. A new `update` MCP tool. This is approved under `CLAUDE.md` §10. ADR-0025. | none needed |
| D6 | **`scan` returns the result.** It blocks within the budget, default 300 s, and sends progress. A second call on the same workspace attaches. Past the budget it returns a partial result naming the cuts. ADR-0024. | if R6.1 finds Claude Code loses a backgrounded result, keep start-and-poll with the schema-2 reply |
| D7 | **Reply schema 2.** `structuredContent` comes first. It carries a `report` field holding the Markdown summary, plus `error.kind` and `next`, and stays under 25,000 tokens. | none needed |
| D8 | **The Scanner set, by rule.** zizmor is adopted if it reports every unpinned action and every write permission that Checkov's GitHub Actions checks found on the corpus. KICS replaces Checkov only if it finds at least 90% of Checkov's distinct failed rules on repositories 5 and 6 and the corpus infrastructure, and runs at least twice as fast. Otherwise Checkov stays and runs only where infrastructure exists. Trivy's SBOM replaces Syft if its component count is within 5% of Syft's on the corpus. OSV's offline database joins `offline` if it reports repository 8's planted `MAL-` package. ADR-0023. | each rule names its own fallback: the current tool stays |
| D9 | **The Results Folder.** SARIF is always written. The SBOM is always written when it comes from Trivy's pass, and otherwise only with `--sbom`. | none needed |
| D10 | **`init` prints and never writes.** A JSON Schema for `.security-scan.toml`, which `doctor` validates. | none needed |
| D11 | **Two settings files.** Project policy lives in `.security-scan.toml`, machine settings in `~/.config/valvur/config.toml`. Environment variables remain only as overrides: `VALVUR_IMAGE`, `VALVUR_CACHE`, `VALVUR_RUNTIME`, `VALVUR_DEBUG`, `VALVUR_FETCH`, and the mirror settings. The rest print a deprecation line for one release, then go. | none needed |
| D12 | **Seven CLI commands.** `findings` absorbs `explain`. `doctor` shows cache sizes, and `update --prune` and `--clear` absorb `cache`. The old names work for one release and print the new form. | none needed |
| D13 | **Repository hygiene is reported, not ranked.** A missing `SECURITY.md`, no dependency-update configuration, or write-all default workflow permissions go in a Hygiene section of `SUMMARY.md` and `run.json`. They are never Findings and never change the Status. | none needed |
| D14 | **Borrowed injection patterns.** Cisco mcp-scanner's rules (Apache-2.0) are translated into the AI Artifact Check only where they add no finding on the corpus's real files. They are credited in `NOTICE`. | patterns that add any finding are left out |
| D15 | **The image as a pipeline step comes after `1.0.0`** (R8). AWS itself appears only in §8. | none needed |
| D16 | **Releases.** `0.6.0` after R1, `0.7.0` after R3, `1.0.0` after R7. Each is prepared and rehearsed by the executor. The tag and the approval are the owner's and block nothing. | none needed |
| D17 | **`1.0.0` criteria.** On both lanes, every acceptance repository yields its expected findings and none unexpected at high or critical. Zero containers remain after every lifecycle probe. Repository 1 completes warm in under 30 s on the Mac; when host swap is over 4 GB the Mac number is recorded and the threshold is judged on Linux. The agent pass reaches a correct report in 6 turns or fewer on every repository. Every bad input fails synchronously. | none needed |
| D18 | **Two lanes.** The Mac lane is this machine, run by the executor at every phase exit. The Linux lane is `acceptance.yml` on GitHub's runners. | none needed |
| D19 | **Agent scoring budget:** $25 in total. | skip scoring and note it in §8 |
| D20 | **Kiro.** A stdio probe that replays Kiro's call sequence runs in CI. The GUI pass is the owner's. | none needed |

## 6. Order

```
R0 pre-flight ─► R1 0.6.0 ─► R2 acceptance set ─► R3 engine ─► R4 Scanner set
                                                        (0.7.0)          │
      R8 pipeline step ◄── R7 documents, 1.0.0 ◄── R6 agent surface ◄── R5 report
```

- **R0** makes an unattended run possible: resuming armed, the machine and access verified,
  the decisions written.
- **R1** fixes what `0.5.0` users can be misled by today, touching the current engine as
  little as possible.
- **R2** measures the current engine before it is replaced, so every later exit compares
  numbers, not memories.
- **R3** is the critical path. It removes the three engine causes, and history scanning
  rides on its input pipeline. It ends with `0.7.0` prepared, because that release carries
  the timeout and reliability fixes.
- **R4 before R5 and R6**, so the report and the reply are built on the final Scanner set.
- **R5 before R6**, because the reply carries the report's groups.
- **R7** closes the documents against what exists, then prepares `1.0.0`.
- **R8** follows `1.0.0` by decision D15.

---

## 7. The phases

### Phase R0: pre-flight

Nothing is built until R0 passes. Its checks are its tests. Each check is a command whose
output is recorded in `docs/acceptance/r0.md`. A failing check is fixed, or becomes a stop
condition.

- [ ] **R0.1** **Resuming, armed** (§2). Behaviours:
  1. `scripts/build_status.py`, test-first against a fixture `tasks.md` and a fixture git
     repository. It names the current phase, its branch and the first unchecked task. It
     answers "alive" when the newest build commit or file change is under eight hours old,
     and ignores commits without a phase scope.
  2. The in-session job exists: `CronList` shows it.
  3. The durable task exists: `list_scheduled_tasks` shows `valvur-build-resume`.
  4. From a fresh shell, `scripts/build_status.py` prints R0.2 as the next task and changes
     nothing.
- [ ] **R0.2** **The machine.** Record: the macOS version; Docker Desktop's version, VM
  memory and CPUs; host swap in use; free disk, which must be at least 30 GB; and one
  `docker run --rm --network=none valvur:dev true`. When host swap is over 4 GB, D17's Mac
  time rule applies for the whole build, and the record says so.
- [ ] **R0.3** **The toolchain and access.** Record each:
  - `uv`, and Python 3.11, 3.12 and 3.13 through it; `docker buildx`; `cosign`.
  - `gh auth status` with the `repo` and `workflow` scopes.
  - The signing key: `ssh-add -L` holds the key in `.github/allowed_signers`. A signed
    commit on a throwaway local branch verifies, and the branch is deleted.
  - `claude auth status` reports logged in.
  - HTTPS reach to `ghcr.io`, `pypi.org`, `mirror.gcr.io`, `github.com` and
    `api.github.com`.
  - AWS is not needed: R8 uses a local registry.
- [ ] **R0.4** **The repository.** Record each:
  - `main` is clean and equal to `origin/main`, and its last three CI runs are green.
  - No open PR from another session. Worktrees are listed and left alone.
  - The unit suite is green and traceability holds.
  - The state of rehearsal run 36317791899.
- [ ] **R0.5** **The decisions, written** (§5). Test: `scripts/check_traceability.py`
  passes, with every new ADR citing its requirements.
  - ADR-0021 *The File Set* (D1 to D3); ADR-0022 *One Scan Container and the Snapshot*
    (D4); ADR-0023 *The Scanner set, by rule* (D8), to be amended with R4.1's table;
    ADR-0024 *`scan` returns the result* (D6, D7); ADR-0025 *Fresh data without a terminal*
    (D5).
  - `CONTEXT.md` gains **File Set**, **Snapshot** and **Scan Container**, each with an
    _Avoid_ list.
  - `requirements.md` amends F1.1 and F1.6 for the Snapshot, and F10.8 for freshness.
- [ ] **R0.6** **The working materials.**
  - `valvur:dev` is built from `main` with `SOURCE_DATE_EPOCH`.
  - `BUILD_CACHE` holds the vulnerability database and the Name Index, fetched once.
  - The e2e suite is green on this Mac against them, with its time recorded.

**Exit:** every check recorded in `docs/acceptance/r0.md`, both schedules armed, the ADRs on
`main`.

### Phase R1: the `0.6.0` safety release

The current engine, patched where `0.5.0` users can be misled today.

- [ ] **R1.1** **A cancel stops the queue** (F1.11). Behaviours:
  1. With a fake runtime at `jobs=1`, a cancel during the first Scanner means the second is
     never launched.
  2. `CANCELLED` is reported only once the runtime lists none of the scan's containers.
  3. e2e at width 2: at the moment the state reads `CANCELLED`, `docker ps` shows no
     `valvur-` container.
- [ ] **R1.2** **A workspace must exist** (F9.1, N2.2). Behaviours, through the MCP handlers
  and the CLI:
  1. A relative path resolves against `CLAUDE_PROJECT_DIR` when it is set, and is refused
     otherwise.
  2. A missing path, or a file, is refused synchronously with `isError`.
  3. No refusal creates a directory.
  4. `list_findings` and `explain_finding` refuse the same way.
- [ ] **R1.3** **An exclude means the same to every Scanner** (F2.1). Measure each tool's
  root-anchored form inside the image first. Behaviours, e2e on a planted tree with
  `archive` excluded:
  1. Every Scanner reports the flows planted in `src/archive/` and `src/app/`.
  2. A tool with no anchored form gets no exclude, and its findings are filtered afterwards.
- [ ] **R1.4** **Built-in skips are named** (F7.7). Behaviour: a tree with `mypkg/build/`
  names that directory and its file count in `run.json`, `SUMMARY.md`, the CLI output and
  the `scan_status` reply.
- [ ] **R1.5** **Input errors fail at the call, and `doctor` is suggested only when it can
  help** (F9.10). Behaviours:
  1. Each bad argument is refused synchronously, in one plain sentence with no exception
     class name.
  2. `doctor_may_help` is true only for a precondition failure: runtime, image, database,
     index, SELinux or TLS.
  3. A Busy refusal carries `next` and does not mention `doctor`.
- [ ] **R1.6** **Trivy never reports to its vendor** (N2.1, ADR-0010). Behaviour: every
  Trivy argv, the database fetch included, carries `--disable-telemetry` and
  `--skip-version-check`, held by the argv snapshots.
- [ ] **R1.7** **The README says what the secrets step reads** (P2). Behaviour: the README's
  Gitleaks row matches the adapter's mode. R3.7 restores the history claim.
- [ ] **R1.8** **`0.6.0` prepared** (D16).
  - Cancel rehearsal run 36317791899.
  - Set the version to `0.6.0`. The CHANGELOG's `[1.0.0]` entry becomes `[0.6.0]`,
    without the stability claim. The README status line and `SECURITY.md` follow
    `test_version.py`.
  - After the phase lands, rehearse per §4 step 6. §8 gets its row.

**Exit:** R1.1 to R1.4's regression tests pass on Linux CI and on the Mac. The `0.6.0`
rehearsal follows the landing (§4 step 6).

### Phase R2: the acceptance set

The judge for every later phase, and a baseline of today's engine. The first commit records
R1's rehearsal.

- [ ] **R2.1** **Eight acceptance repositories, generated** (P1, N1.1). `scripts/acceptance/`
  builds each from nothing, into a temporary directory:
  1. *gate-shaped*: 300 source files, a gitignored 100,000-file data directory, a `.venv`;
  2. *lockfiles*: a copy of `tests/fixtures/broken-repo`, with known CVEs;
  3. *history secret*: a credential committed, then removed in the next commit;
  4. *nested names*: flows planted in `archive/`, `src/archive/` and `mypkg/build/`;
  5. *infrastructure*: `terraform-aws-vpc` at a pinned commit;
  6. *self*: this repository at a pinned commit;
  7. *local exposure*: an unignored `.mcp.json` holding an absolute home path, and a
     workflow with write-all permissions;
  8. *malicious dependency*: a manifest and lockfile naming one pinned `MAL-` entry from
     ossf/malicious-packages. It is never installed.

  Each repository has an `expected.toml` listing the rules and paths that must be found,
  those that must not, and `until = "R<n>.<m>"` on expectations a later task delivers.
  Behaviours:
  1. The generator is deterministic: two runs produce byte-identical trees.
  2. No generated credential exists as a literal in the repository.
- [ ] **R2.2** **The harness**, `scripts/acceptance.py`. It runs a CLI scan per repository
  and reports JSON plus a Markdown table: expected findings present, unexpected ones,
  status, wall time, containers alive afterwards, platform and host swap. Behaviours:
  1. Against a fixture results folder, a missing expected finding fails.
  2. An unexpected finding is listed, and fails only at high or critical.
  3. An `until` expectation is reported as pending, not failed, until its task is ticked.
- [ ] **R2.3** **Lifecycle probes**: cancel mid-scan, a budget cut, `kill -9` of the MCP
  server mid-scan, and stdin closed mid-scan. Behaviours:
  1. After each, no container remains.
  2. The next scan starts.
- [ ] **R2.4** **Agent scoring.** One `claude -p` sentence per repository, using the
  repository's generated `.mcp.json`. Records turns, cost, seconds, whether the answer names
  every expected finding, and containers left. Tracks the running total against D19.
  Behaviour: against a recorded transcript, the scorer computes turns and cost and checks
  names.
- [ ] **R2.5** **The Linux lane.** `acceptance.yml`, run nightly and on dispatch, uploads
  the report. A local registry stands in for GHCR where a test needs a mirror. Behaviour:
  the workflow's first dispatched run is green, except for the `until` rows.
- [ ] **R2.6** **The baseline.** The `0.6.0` tree on both lanes, plus agent scoring on the
  Mac, written to `docs/acceptance/r2.md`.

**Exit:** the baseline recorded. The harness fails where today's engine is wrong, each row
marked with the task that fixes it: repository 1 without configuration (R3.2), 3 (R3.7),
4's `mypkg/build/` (R3.2), 7 (R4.2, R5.3) and 8 (R4.6).

### Phase R3: one scan, one container, fed the files git would publish

The engine rebuilt under D1 to D4. The old path serves until R3.9 deletes it, and
`VALVUR_ENGINE=2` selects the new one until then.

- [ ] **R3.1** **Tracer bullet.** Behaviours:
  1. Through `LocalRuntime`, which runs `python -m valvur.engine` as a host subprocess,
     the engine receives a Snapshot of two files and writes a Gitleaks report and a
     manifest.
  2. `api.scan` with `VALVUR_ENGINE=2` through `LocalRuntime` reports the planted secret in
     `findings.json`.
  3. The same, e2e, through one real container.
- [ ] **R3.2** **The File Set** (D1, D2; F1.1, F7.7). Behaviours, on real temporary git
  repositories:
  1. The git view lists tracked files and untracked-not-ignored files, never `.git/`.
  2. Ignored `.env*`, `.mcp.json`, `.claude/` and `.kiro/settings/` are included.
  3. `exclude = ["archive"]` removes `archive/` and keeps `src/archive/`.
  4. A symlink leaving the repository is listed as a link and never followed. A submodule is
     named and not entered. An LFS pointer is scanned as the pointer file.
  5. A directory that is not a repository is walked, and each skipped directory is named.
  6. Past 20,000 files, the walk refuses before any container starts, naming the largest
     directories and the exclude line. A git view past 20,000 files proceeds, with the same
     names as a warning.
  7. The manifest records the count, the bytes and the list's sha256. Measured:
     repository 1 lists in under half a second.
- [ ] **R3.3** **The Snapshot** (D4). Behaviours:
  1. Up to 512 MB goes to a tmpfs, and beyond that to a per-scan volume removed afterwards.
  2. The engine reports the count it received. A mismatch with the manifest refuses the
     scan.
  3. The source tree is never mounted: an e2e test inspects the container's mounts.
- [ ] **R3.4** **The engine runs every `offline` Scanner** (F2.4 to F2.7). Adapters return
  a plan entry holding argv, report path and timeout, and parsing is unchanged. The timeout
  model is MegaLinter's, as an idea only. Behaviours, through `LocalRuntime` with fake
  tools:
  1. The tools run in parallel, each in its own process group.
  2. One that sleeps past its timeout is killed with its whole group and recorded as timed
     out, exit 124, with a stderr excerpt cut at a word boundary.
  3. One that crashes, or writes an unreadable report, fails alone and the others stand.
  4. Progress arrives as JSON lines, one as each tool starts and one as it ends.
  5. The argv snapshots are re-taken.
- [ ] **R3.5** **One deadline and one kill** (F1.11, F2.7). Behaviours:
  1. At the budget, the engine stops what is running and writes a partial manifest naming
     each cut.
  2. If the engine does not return within a grace period, the host kills the container.
  3. `scan_cancel` sends one kill and waits until the runtime confirms the container is gone
     before `CANCELLED`.
  4. e2e: zero containers after each of these.
- [ ] **R3.6** **Nothing outlives its owner** (F1.11, F1.12). Behaviours:
  1. Every container carries the labels `valvur.generation` and `valvur.pid`.
  2. At each scan start and in `doctor`, containers whose owner process is dead are removed.
  3. The MCP server exits on stdin EOF, and on parent death, found by polling `getppid()`.
     Shutdown kills by label within three seconds.
  4. The workspace lock records its holder's PID, and *Busy* says whether that holder is
     alive.
  5. e2e: after `kill -9` of the server mid-scan, the next scan reaps the orphan and runs.
- [ ] **R3.7** **Secrets in history** (D3; F2.1, P2). Behaviours:
  1. The host writes `git log -p --all` into the Snapshot with commit markers, within the
     bound, and says when the bound was hit.
  2. Gitleaks scans it, and each hit is mapped to its commit and path.
  3. Repository 3's credential is reported with its commit.
  4. `history = false` turns it off. The README's history claim is restored.
- [ ] **R3.8** **`full` adds one networked container** (D4; N2.1, ADR-0010, ADR-0016).
  Behaviours:
  1. OSV-Scanner and dependency-reality's registry questions run in the second container;
     `egress.py` stays the only authority.
  2. The exfiltration constraint tests, restated for two containers, pass.
  3. `offline` starts exactly one container, with no network.
  4. Trivy never runs in the networked container.
- [ ] **R3.9** **Switch over and delete.** The new engine becomes the only engine. Deleted:
  the thread-pool fleet, both name registries, `skip_args`, `VENDORED`, the generated
  Gitleaks config (the project's own `.gitleaks.toml` is still honoured),
  `verify_workspace_readable`, width-from-memory, and `honour_gitignore`. `PROTOCOL.md`
  moves to 2, with `org.valvur.protocol="2"`. Behaviours:
  1. A major-1 image is refused, with the fix named.
  2. The constraint suite is restated for the new invariants: one container per `offline`
     scan; the workspace never mounted; zero containers after any stop.
- [ ] **R3.10** **`0.7.0` prepared** (D16). The version, the CHANGELOG and the README status
  line. The rehearsal runs after landing, per §4.

**Exit**, on both lanes:
- every expected finding, except those marked for R4 and R5;
- repository 1 complete warm in under 30 s on the Mac, under D17's swap rule;
- one container per `offline` scan, and zero after every lifecycle probe;
- the net line change of `api.py` and `runner.py` recorded.

### Phase R4: the Scanner set, by rule

The first commit records R3's rehearsal.

- [ ] **R4.1** **The spike** (D8; F2.1, N1.1). Measure, on the thirteen corpus repositories
  and the acceptance set:
  1. zizmor against Checkov's GitHub Actions checks;
  2. KICS and Trivy against Checkov on infrastructure. The first data point is in the
     review's 11.6;
  3. Trivy's CycloneDX output, through `trivy convert`, against Syft's;
  4. OSV-Scanner's offline database on repository 8's `MAL-` package.

  Apply D8's rules and amend ADR-0023 with the table. Each tool's licence, offline mode and
  pinning are checked before it enters the image.
- [ ] **R4.2** **zizmor** (F3.11), pinned by hash in the image, credited in `NOTICE`, run
  with `--offline`. Behaviours: planted workflows with an unpinned action, write-all
  permissions and template injection each produce one ranked Finding. Repository 7's
  workflow is reported.
- [ ] **R4.3** **Checkov only where there is infrastructure** (F2.1, F2.2), or KICS in its
  place if D8 says so. Behaviours:
  1. Repository 5's expected findings hold.
  2. A repository with only workflows skips Checkov, and the skip is reported.
  3. The image size is recorded before and after.
- [ ] **R4.4** **The SBOM from Trivy's pass** (D8, D9; P3, F10.3), if D8 says so.
  Behaviours: `sbom.cdx.json` validates as CycloneDX, and its component count matches the
  parity recorded in R4.1.
- [ ] **R4.5** **The action-pin rule moves to zizmor**, if parity holds (F3.11). Behaviour:
  the pin findings on the corpus are unchanged in count and path. Opengrep keeps the sink
  inventory and the taint rules.
- [ ] **R4.6** **OSV's offline database on `offline`**, if D8 says so (F3.2). Behaviours:
  1. The database is fetched and recorded like Trivy's, for the ecosystems in the File Set.
  2. Repository 8's `MAL-` package is reported at critical.

**Exit:** ADR-0023 amended. The fastest application-repository scan on Linux is at most half
of R2's baseline. Repositories 5 and 8 behave as D8 decided. `NOTICE`, the licence checks and
the reproducible-image check are green.

### Phase R5: the report

- [ ] **R5.1** **Groups** (F5.8, F7.5, F7.14). Behaviours:
  1. 3,890 `generic-api-key` hits under one directory form one group, ranked below eight
     distinct findings, and labelled as possible machine-written data.
  2. `findings.json` keeps every Finding with its group id.
- [ ] **R5.2** **`SUMMARY.md` leads with what matters** (F7.4 to F7.7, N1.3). Behaviours:
  1. The order is: verdict, scope manifest, what did not run, top groups, Hygiene, then a
     shortened agent block at the end.
  2. No title is cut mid-word, at every truncation site.
  3. The golden files are re-taken.
- [ ] **R5.3** **Local agent configuration that would leak** (F3.6). Behaviour: `.mcp.json`,
  `.claude/settings.local.json`, `.kiro/settings/mcp.json` and their peers, when git does not
  ignore them and they hold absolute local paths or credential-shaped values, yield a medium
  Finding. Repository 7 is reported.
- [ ] **R5.4** **`REMEDIATION.md` per group** (F7.14). Behaviour: the gate's flood yields one
  action naming the count and the exclude line.
- [ ] **R5.5** **Repository hygiene** (D13). Behaviours:
  1. A missing `SECURITY.md`, no dependency-update configuration, and write-all default
     workflow permissions each appear in the Hygiene section.
  2. None of them changes the Status.
  3. The corpus is measured and its counts recorded.
- [ ] **R5.6** **Borrowed injection patterns** (D14; F3.6, F3.12). Behaviours:
  1. Each translated pattern fires on its planted fixture.
  2. The corpus's real agent files gain no finding.
  3. `NOTICE` credits the source.

**Exit:** repository 1's `SUMMARY.md` fits one screen. Repository 7 is fully reported. The
corpus gains no finding from R5.6.

### Phase R6: the agent surface

- [ ] **R6.1** **Measure the client before relying on it** (F9.1). In Claude Code, a stdio
  tool call that runs 150 s and sends progress: is it backgrounded at two minutes, and does
  its result reach the model? The answer is recorded in ADR-0024, and D6's fallback applies
  if needed.
- [ ] **R6.2** **Reply schema 2** (D7; F9.8 to F9.10). Behaviours:
  1. The snapshot is re-taken.
  2. The largest acceptance repository's reply stays under 25,000 tokens.
  3. Every state's fields agree with its text, which is rendered from the fields.
- [ ] **R6.3** **`scan` blocks and returns** (D6; F9.1). Behaviours, over stdio:
  1. One call yields the result, with progress notifications on the way.
  2. A disconnect, then a second call, yields the same generation.
  3. `scan_status` attaches.
- [ ] **R6.4** **Inputs from the client's roots** (F9.1, N2.2). Behaviours:
  1. The workspace defaults to `CLAUDE_PROJECT_DIR`, or the first root from `roots/list`.
  2. A workspace outside the roots is refused.
  3. Every schema has `additionalProperties: false`.
  4. Every violation fails synchronously, with a kind and one sentence.
- [ ] **R6.5** **One `findings` tool, seven CLI commands** (D12; F9.1, F9.3, F9.8). Behaviours:
  1. The tool filters by fingerprint, group, rule and path, and says when it clamped.
  2. `valvur findings` absorbs `explain`; `doctor` and `update` absorb `cache`.
  3. The old names print the new form.
  4. A parity test runs over every MCP tool and its CLI command.
- [ ] **R6.6** **Fresh data without a terminal** (D5; F10.8). Behaviours:
  1. An eight-day-old database is refreshed inside a scan and recorded.
  2. With `fetch = "never"`, the result is `inconclusive` with the reason.
  3. The `update` tool fetches, and says what it fetched.
- [ ] **R6.7** **Two settings files** (D11). Behaviours:
  1. Machine settings are read from `~/.config/valvur/config.toml`.
  2. Each retired environment variable still works and prints one deprecation line.
  3. `doctor` prints the effective settings and where each came from.
- [ ] **R6.8** **`valvur init` and the schema** (D10). Behaviours:
  1. `init` prints the client file for each client found and a starter `.security-scan.toml`
     with excludes suggested by the pre-flight count, and writes nothing.
  2. The JSON Schema validates every example in the README.
  3. `doctor` names the first invalid key.
- [ ] **R6.9** **`doctor` and the reply tell the truth about the session.** Behaviours:
  1. `doctor` says when the running server is older than the configuration names.
  2. The reply and the handshake say the Results Folder ignores itself.
- [ ] **R6.10** **The Kiro probe** (D20). Behaviour: a stdio client replaying Kiro's
  initialize, tools/list, calls and cancellation passes in CI.

**Exit:** agent scoring reaches a correct report in 6 turns or fewer on every repository.
Every bad input fails synchronously. The CLI parity test is green.

### Phase R7: documents, and `1.0.0` prepared

- [ ] **R7.1** **The README, rewritten against what exists** (P6). Behaviours:
  1. Every number in it is the acceptance set's.
  2. The tool table matches the image.
  3. The client table matches `doctor`.
- [ ] **R7.2** **`EVALUATING.md`, `design.md`, `PROTOCOL.md`, `AIR-GAPPED.md` and
  `requirements.md` as built.** Amendments only, and no ID renumbered. Behaviour:
  traceability holds.
- [ ] **R7.3** **Documents consolidated.** `OPEN-ITEMS.md`, `POSITIONING.md`, the reviews,
  `usability-gate.md`, `council/` and `gates/` move to `docs/history/`, and their still-true
  points move into the README or `EVALUATING.md`. Behaviour: a link check over every
  Markdown file finds no broken relative link.
- [ ] **R7.4** **`CLAUDE.md` and this file.** `CLAUDE.md` is refreshed within 200 lines. Closed
  phases move to `docs/history/`.
- [ ] **R7.5** **`1.0.0` prepared** (D16, D17). D17's criteria are measured on both lanes and
  recorded. The CHANGELOG states the stability claim. The rehearsal runs after landing, per
  §4.

**Exit:** the acceptance set fully green on both lanes, every `until` resolved, and D17 met.

### Phase R8: the image as a pipeline step

The first commit records R7's rehearsal.

- [ ] **R8.1** **The image scans on its own** (D15; F1.10). `valvur scan` runs inside the
  image on a mounted or cloned checkout, needing no socket. Behaviours:
  1. e2e: `docker run` of the image on a checkout writes the Results Folder to a mounted
     output directory.
  2. No cloud-specific code path exists: F1.10's test still holds.
- [ ] **R8.2** **A GitHub Actions container job**: a workflow example and a CI test that runs
  it. A GitLab snippet goes in the docs.
- [ ] **R8.3** **A mirror in the customer's own registry.** Behaviours:
  1. A CI test mirrors the image, the database and the index into a local OCI registry,
     standing in for ECR.
  2. A scan with the mirror settings completes with `left this machine: nothing`.
  3. `AIR-GAPPED.md` gains the ECR steps.
- [ ] **R8.4** **The build's summary**, written as this task's STATUS: what shipped, the
  acceptance numbers against R2's baseline, the cost of agent scoring, and what §8 holds.

**Exit:** the pipeline-step and mirror e2e tests green, and both schedules deleted.

---

## 8. The owner queue

Nothing here blocks the build. The executor adds a row when an item becomes ready.

| item | ready after | what the owner does |
|---|---|---|
| `v0.6.0` | R1 lands and is rehearsed | sign and push the tag on the recorded commit; approve at the brake |
| `v0.7.0` | R3 | the same |
| `v1.0.0` | R7 | the same |
| the gate with a person (12b.3, 10.1) | `1.0.0` | find someone outside the repository; they follow the README on a project of their own |
| Kiro's GUI pass | R6 | one scan through Kiro, recorded in `docs/gates/` |
| a self-hosted Mac runner, optional | R2 | register one with the label `docker-desktop` |
| a second maintainer (28.1.3) | any time | `MAINTAINERS.md`'s five steps |
| the runner move (28.3.8) | after 2026-11-19 | ask any session to move the pinned runner images and land it |
| AWS measured runs: ECR mirror and CodeBuild (F1.10) | R8 | run once in an AWS account and record the numbers |
| `init --write` | R6 | decide whether `init` may write files |
| revisit a decision in §5 | any time | `/grill-with-docs` |

## 9. Where the earlier IDs went

| first version, 2026-09-27 | here |
|---|---|
| 31.1 to 31.6 | R1.1 to R1.5, R1.7 |
| 31.7 | R1.8 |
| 32.1 to 32.6 | R2.1 to R2.6 |
| 33.1 | R0.5 |
| 33.2 to 33.8 | R3.1 to R3.9 |
| 34.1 to 34.5 | R4.1 to R4.5 |
| 34.6 | R3.7 |
| 35.1 to 35.4 | R5.1 to R5.4 |
| 36.1 to 36.7 | R6.1 to R6.4, R6.5, R6.6, R6.9 |
| 37.1 to 37.3 | R7.1, R7.2, R7.4 |
| 37.4 to 37.7 | §8 |
| Phase 30's seven, from the second gate | R1.1, R1.2, R1.5, R5.1, R6.9, R6.2, R6.5 |
| C10, git history | R1.7, R3.7 |
