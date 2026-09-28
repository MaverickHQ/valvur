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
   when absent. A phase finished on its branch whose landing was refused to the session
   waits for the owner (§8): the next phase is built on a branch stacked on it, and the
   script steps over the waiting phase to that branch, listing it in `waiting_to_land`.
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
     (`PYTHONDONTWRITEBYTECODE=1 uv run --extra dev pytest -q -p no:cacheprovider -m "not e2e"`).
     A slice that touches only `scripts/`, documents or a new test file runs its own
     tests and lint; the full suite runs at the end of every task and before every push.
     *Adopted in R0: the full suite takes one to two minutes on this Mac under swap.*
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

- [x] **R0.1** **Resuming, armed** (§2). Behaviours:
  1. `scripts/build_status.py`, test-first against a fixture `tasks.md` and a fixture git
     repository. It names the current phase, its branch and the first unchecked task. It
     answers "alive" when the newest build commit or file change is under eight hours old,
     and ignores commits without a phase scope.
  2. The in-session job exists: `CronList` shows it.
  3. The durable task exists: `list_scheduled_tasks` shows `valvur-build-resume`.
  4. From a fresh shell, `scripts/build_status.py` prints R0.2 as the next task and changes
     nothing.
  **STATUS 2026-09-27:** ✅ `scripts/build_status.py` with eight tests; `CronCreate` job `5138717e` and the desktop task `valvur-build-resume` armed; a fresh shell read R0.2 as next. Record: `docs/acceptance/r0.md`.
- [x] **R0.2** **The machine.** Record: the macOS version; Docker Desktop's version, VM
  memory and CPUs; host swap in use; free disk, which must be at least 30 GB; and one
  `docker run --rm --network=none valvur:dev true`. When host swap is over 4 GB, D17's Mac
  time rule applies for the whole build, and the record says so.
  **STATUS 2026-09-27:** ✅ 8 GB Mac, host swap 14.05 of 14.34 GB, 32 GB free, a container start 4.99 s: D17's swap rule holds for the build, and §8 asks the owner to free memory.
- [x] **R0.3** **The toolchain and access.** Record each:
  - `uv`, and Python 3.11, 3.12 and 3.13 through it; `docker buildx`; `cosign`.
  - `gh auth status` with the `repo` and `workflow` scopes.
  - The signing key: `ssh-add -L` holds the key in `.github/allowed_signers`. A signed
    commit on a throwaway local branch verifies, and the branch is deleted.
  - `claude auth status` reports logged in.
  - HTTPS reach to `ghcr.io`, `pypi.org`, `mirror.gcr.io`, `github.com` and
    `api.github.com`.
  - AWS is not needed: R8 uses a local registry.
  **STATUS 2026-09-27:** ✅ Everything present; Python 3.13.12 installed through `uv`; a signed probe commit verified against `.github/allowed_signers`.
- [x] **R0.4** **The repository.** Record each:
  - `main` is clean and equal to `origin/main`, and its last three CI runs are green.
  - No open PR from another session. Worktrees are listed and left alone.
  - The unit suite is green and traceability holds.
  - The state of rehearsal run 36317791899.
  **STATUS 2026-09-27:** ✅ `main` current and green; no open PRs; one fix: `pyproject.toml` excludes `/.claude` from the sdist, where R0.1's schedule keeps its lock. Unit suite 1,274 passed.
- [x] **R0.5** **The decisions, written** (§5). Test: `scripts/check_traceability.py`
  passes, with every new ADR citing its requirements.
  - ADR-0021 *The File Set* (D1 to D3); ADR-0022 *One Scan Container and the Snapshot*
    (D4); ADR-0023 *The Scanner set, by rule* (D8), to be amended with R4.1's table;
    ADR-0024 *`scan` returns the result* (D6, D7); ADR-0025 *Fresh data without a terminal*
    (D5).
  - `CONTEXT.md` gains **File Set**, **Snapshot** and **Scan Container**, each with an
    _Avoid_ list.
  - `requirements.md` amends F1.1 and F1.6 for the Snapshot, and F10.8 for freshness.
  **STATUS 2026-09-27:** ✅ ADRs 0021 to 0025; File Set, Snapshot and Scan Container in `CONTEXT.md`; F1.1, F1.6 and F10.8 amended; traceability holds.
- [x] **R0.6** **The working materials.**
  - `valvur:dev` is built from `main` with `SOURCE_DATE_EPOCH`.
  - `BUILD_CACHE` holds the vulnerability database and the Name Index, fetched once.
  - The e2e suite is green on this Mac against them, with its time recorded.
  **STATUS 2026-09-27:** ✅ `valvur:dev` built from this tree and verified; the build cache
  holds the database and the index (1.5 GB, 121 s). e2e: 34 of 35 in 354 s after Docker
  Desktop was restarted; the one failure is C1, reproduced (Scanners launched after the
  client disconnected), and is R1.1's to fix.

**Exit:** every check recorded in `docs/acceptance/r0.md`, both schedules armed, the ADRs on
`main`.

### Phase R1: the `0.6.0` safety release

The current engine, patched where `0.5.0` users can be misled today.

- [x] **R1.1** **A cancel stops the queue** (F1.11). Behaviours:
  1. With a fake runtime at `jobs=1`, a cancel during the first Scanner means the second is
     never launched.
  2. `CANCELLED` is reported only once the runtime lists none of the scan's containers.
  3. e2e at width 2: at the moment the state reads `CANCELLED`, `docker ps` shows no
     `valvur-` container.
  **STATUS 2026-09-27:** ✅ Before (R0.6): after a disconnect at width 2 the fleet launched
  two or three containers and the server exited 3.0 to 7.6 s later. After: a queued
  Scanner checks the flag before it launches, and a cancelled scan waits until the runtime
  lists none of its containers before it raises. The e2e test failed 3 of 3 on the old
  engine, each time with two containers launched after the cancel, and passes on the new;
  `test_mcp_shutdown` passes with it. `tests/test_cancel_stops_the_queue.py`, four tests.
- [x] **R1.2** **A workspace must exist** (F9.1, N2.2). Behaviours, through the MCP handlers
  and the CLI:
  1. A relative path resolves against `CLAUDE_PROJECT_DIR` when it is set, and is refused
     otherwise.
  2. A missing path, or a file, is refused synchronously with `isError`.
  3. No refusal creates a directory.
  4. `list_findings` and `explain_finding` refuse the same way.
  **STATUS 2026-09-27:** ✅ One resolver, `operations.resolve_workspace`, for every MCP tool:
  the workspace defaults to `CLAUDE_PROJECT_DIR` or the server's directory, a relative path
  resolves against `CLAUDE_PROJECT_DIR` or is refused, and a missing path or a file is
  refused with `isError` in one sentence, creating nothing. The CLI checks the same at
  parse time, through the `path` argument's type, and exits 2. The server now shows a
  refusal as its sentence, without an exception class. Fourteen tests in
  `tests/test_workspace_must_exist.py`.
- [x] **R1.3** **An exclude means the same to every Scanner** (F2.1). Measure each tool's
  root-anchored form inside the image first. Behaviours, e2e on a planted tree with
  `archive` excluded:
  1. Every Scanner reports the flows planted in `src/archive/` and `src/app/`.
  2. A tool with no anchored form gets no exclude, and its findings are filtered afterwards.
  **STATUS 2026-09-27:** ✅ Measured inside the image: Opengrep anchors only on the container
  path (`--exclude=/workspace/archive`); Checkov matches its regular expression against the
  full container path, so `^/workspace/archive(/|$)` anchors and `^/archive` matches
  nothing; OSV-Scanner has no anchored form, so a configured prefix is filtered afterwards.
  The e2e test on a planted tree, `full` Profile, now finds `src/archive/` through every
  Scanner and nothing under `archive/`; before, Opengrep missed it.
- [x] **R1.4** **Built-in skips are named** (F7.7). Behaviour: a tree with `mypkg/build/`
  names that directory and its file count in `run.json`, `SUMMARY.md`, the CLI output and
  the `scan_status` reply.
  **STATUS 2026-09-27:** ✅ `exclusions.skipped_builtin` names each directory the built-in
  list skipped and counts its files, capped at 100,000; valvur's own folder and version
  control's metadata are skipped but not named. The names reach `run.json`
  (`excluded_builtin`), `SUMMARY.md`, the CLI and `scan_status`, text and field; the MCP
  snapshot is re-taken. Six tests in `tests/test_builtin_skips_named.py`. R3.2 removes the
  list itself.
- [x] **R1.5** **Input errors fail at the call, and `doctor` is suggested only when it can
  help** (F9.10). Behaviours:
  1. Each bad argument is refused synchronously, in one plain sentence with no exception
     class name.
  2. `doctor_may_help` is true only for a precondition failure: runtime, image, database,
     index, SELinux or TLS.
  3. A Busy refusal carries `next` and does not mention `doctor`.
  **STATUS 2026-09-27:** ✅ `profile`, `budget_s`, `limit` and `fingerprint` are checked at
  the call and refused in one sentence without an exception class; a refused `scan` starts
  no job; a number sent as a string is still a number. `doctor_may_help` defaults to false
  and a precondition declares it: no runtime, a container that will not start, an
  unreadable workspace, an image that will not pull or does not match, no index, TLS or a
  connection. A busy workspace says to wait. Three older tests had faked a missing runtime
  with a bare `RuntimeError`; they raise `NoContainerRuntime` now. Fourteen tests in
  `tests/test_input_errors_at_the_call.py`.
- [x] **R1.6** **Trivy never reports to its vendor** (N2.1, ADR-0010). Behaviour: every
  Trivy argv, the database fetch included, carries `--disable-telemetry` and
  `--skip-version-check`, held by the argv snapshots.
  **STATUS 2026-09-27:** ✅ Both flags on both Trivy commands, the scan and the database
  fetch, through one constant; both argv snapshots re-taken. Measured inside the image with
  a network: Trivy now logs *Version check and telemetry are disabled, skipping request*.
- [x] **R1.7** **The README says what the secrets step reads** (P2). Behaviour: the README's
  Gitleaks row matches the adapter's mode. R3.7 restores the history claim.
  **STATUS 2026-09-27:** ✅ The row reads *Secrets in the files scanned*, and a test holds it
  to the adapter's mode: while Gitleaks runs in `dir` mode, the row claims no history.
- [x] **R1.8** **`0.6.0` prepared** (D16).
  - Cancel rehearsal run 36317791899.
  - Set the version to `0.6.0`. The CHANGELOG's `[1.0.0]` entry becomes `[0.6.0]`,
    without the stability claim. The README status line and `SECURITY.md` follow
    `test_version.py`.
  - After the phase lands, rehearse per §4 step 6. §8 gets its row.
  **STATUS 2026-09-27:** ✅ Rehearsal 36317791899 cancelled. `pyproject.toml` and the lock
  at `0.6.0`; the README's status line says *release in progress* and waits for the owner's
  tag; its macOS row names the tree each number was measured on; `SECURITY.md` supports
  `0.6.x`. The CHANGELOG's `[1.0.0]` entry is `[0.6.0]`, says why `1.0.0` was not tagged,
  and carries R1's seven fixes, the two changes the `1.0.0` preparation held, and R0's
  notes. The rehearsal of the landed commit is recorded in R2's first commit.

**Exit:** R1.1 to R1.4's regression tests pass on Linux CI and on the Mac. The `0.6.0`
rehearsal follows the landing (§4 step 6).

### Phase R2: the acceptance set

The judge for every later phase, and a baseline of today's engine. The first commit records
R1's rehearsal.

- [x] **R2.1** **Eight acceptance repositories, generated** (P1, N1.1). `scripts/acceptance/`
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
  **STATUS 2026-09-27:** ✅ `scripts/acceptance/generate.py` builds all eight in 10.7 s on
  this Mac; repository 1 holds 100,683 files. Repository 8 names OSV's `MAL-2023-1`,
  `@hyperion-util/cookies` 77.77.79. Three tests; the determinism test was confirmed to
  catch a time-stamped file. The generator was written before its tests, against §3;
  the break was the check that they test something.
- [x] **R2.2** **The harness**, `scripts/acceptance.py`. It runs a CLI scan per repository
  and reports JSON plus a Markdown table: expected findings present, unexpected ones,
  status, wall time, containers alive afterwards, platform and host swap. Behaviours:
  1. Against a fixture results folder, a missing expected finding fails.
  2. An unexpected finding is listed, and fails only at high or critical.
  3. An `until` expectation is reported as pending, not failed, until its task is ticked.
  **STATUS 2026-09-27:** ✅ `scripts/acceptance.py`: judges a results folder against
  `expected.toml` (missing, pending, forbidden, blocking-unexpected, incomplete), runs a
  repository through the CLI with its time and the containers left, and writes
  `report.json` and `report.md` with the platform and host swap. Eight tests. On this Mac,
  repository 4 passes in 13.5 s with `mypkg/build/` pending until R3.2.
- [x] **R2.3** **Lifecycle probes**: cancel mid-scan, a budget cut, `kill -9` of the MCP
  server mid-scan, and stdin closed mid-scan. Behaviours:
  1. After each, no container remains.
  2. The next scan starts.
  **STATUS 2026-09-27:** ✅ `scripts/acceptance/probes.py` drives a real MCP server over
  stdio, on `broken-repo` plus 30,000 files so the Scanners are still running when a probe
  stops them (on the bare fixture an orphan finished inside any grace, and a first version
  of the probes passed `kill -9` for that reason). On this Mac: cancel, budget and stdin
  leave nothing and the next scan starts; `kill -9` leaves two orphans still listed when
  the next scan starts, pending R3.6. `scripts/acceptance.py --probes` reports them.
- [x] **R2.4** **Agent scoring.** One `claude -p` sentence per repository, using the
  repository's generated `.mcp.json`. Records turns, cost, seconds, whether the answer names
  every expected finding, and containers left. Tracks the running total against D19.
  Behaviour: against a recorded transcript, the scorer computes turns and cost and checks
  names.
  **STATUS 2026-09-27:** ✅ `scripts/acceptance/agent.py`: writes the repository's
  `.mcp.json` against this checkout's shim, runs one `claude -p` sentence with the six
  valvur tools and `Read`, scores turns, cost, seconds and each live expected finding
  named by path, and keeps the build's running cost in `~/.cache/valvur-build`, refusing
  past $25. `scripts/acceptance.py --agent` reports it. Two tests on a recorded result;
  the first live run is R2.6's baseline.
- [x] **R2.5** **The Linux lane.** `acceptance.yml`, run nightly and on dispatch, uploads
  the report. A local registry stands in for GHCR where a test needs a mirror. Behaviour:
  the workflow's first dispatched run is green, except for the `until` rows.
  **STATUS 2026-09-27:** ✅ `.github/workflows/acceptance.yml`: nightly, on dispatch, and on a
  pull request that changes the acceptance code, since GitHub dispatches only a workflow
  already on `main`; its first run is R2's own PR. It builds the image from the tree, runs
  the eight repositories and the four probes, uploads the report, and on a scheduled
  failure opens or comments on one issue. The scheduled-workflow constraint names it.
- [x] **R2.6** **The baseline.** The `0.6.0` tree on both lanes, plus agent scoring on the
  Mac, written to `docs/acceptance/r2.md`.
  **STATUS 2026-09-28:** ✅ Both lanes recorded. Every repository passes with its gaps
  pending on the task that closes them, the same rows on the Mac and on Linux; cancel,
  budget and stdin leave nothing; `kill -9` leaves containers on both, pending R3.6.
  Repository 1 is 166 s on the Mac (10 GB of swap, recorded under D17) and 105 s on
  Linux. Agent scoring named every live finding on seven of eight repositories, for
  $7.15. The Linux lane's first runs found three harness defects, fixed: a shallow
  checkout, a relative workspace the server refused, and a 117 MB artifact.

**Exit:** the baseline recorded. The harness fails where today's engine is wrong, each row
marked with the task that fixes it: repository 1 without configuration (R3.2), 3 (R3.7),
4's `mypkg/build/` (R3.2), 7 (R4.2, R5.3) and 8 (R4.6).

### Phase R3: one scan, one container, fed the files git would publish

The engine rebuilt under D1 to D4. The old path serves until R3.9 deletes it, and
`VALVUR_ENGINE=2` selects the new one until then.

- [x] **R3.1** **Tracer bullet.** Behaviours:
  1. Through `LocalRuntime`, which runs `python -m valvur.engine` as a host subprocess,
     the engine receives a Snapshot of two files and writes a Gitleaks report and a
     manifest.
  2. `api.scan` with `VALVUR_ENGINE=2` through `LocalRuntime` reports the planted secret in
     `findings.json`.
  3. The same, e2e, through one real container.
  **STATUS 2026-09-27:** ✅ `valvur.engine` (in the image) unpacks the Snapshot from stdin,
  runs the plan and writes a manifest; `engine_host` builds the Snapshot and the plan and
  runs the engine through `LocalRuntime` or `ContainerRuntime`, whose `/workspace` is a
  tmpfs and whose source tree is never mounted. `api.scan` takes that path under
  `VALVUR_ENGINE=2`. The real container reports the planted key in 1.7 s. On the way: two
  chained string replaces corrupted a local path containing `/results`, and the first
  `fileset` import closed a cycle the ratchet caught.
- [x] **R3.2** **The File Set** (D1, D2; F1.1, F7.7). Behaviours, on real temporary git
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
  **STATUS 2026-09-28:** ✅ `valvur.fileset.build`: the git view plus ignored `.env*` and
  agent configuration (an ignored directory searched at most 5,000 files deep), the
  project's excludes applied once and root-relative, outward links and submodules named,
  a non-repository walk skipping only dependency caches, the 20,000-file ceiling (a walk
  refuses, a git view warns), and the manifest. Measured on this Mac: repository 1, 100,683
  files on disk, lists its 304 in 0.08 to 0.10 s. Eight tests in `tests/test_fileset.py`.
  `Refusal` moved to a leaf module so `fileset` can raise it.
- [x] **R3.3** **The Snapshot** (D4). Behaviours:
  1. Up to 512 MB goes to a tmpfs, and beyond that to a per-scan volume removed afterwards.
  2. The engine reports the count it received. A mismatch with the manifest refuses the
     scan.
  3. The source tree is never mounted: an e2e test inspects the container's mounts.
  **STATUS 2026-09-28:** ✅ Up to 512 MB the Snapshot lands in a tmpfs; beyond, in a volume
  named for the scan and removed after it, and the e2e test sees the volume in the one case
  and not the other. `docker inspect` of a running Scan Container shows no mount of the
  source tree in either case; the only bind mounts are the scratch directory and valvur's
  cache. A Snapshot that arrives short refuses the scan with the numbers.
- [x] **R3.4** **The engine runs every `offline` Scanner** (F2.4 to F2.7). Adapters return
  a plan entry holding argv, report path and timeout, and parsing is unchanged. The timeout
  model is MegaLinter's, as an idea only. Behaviours, through `LocalRuntime` with fake
  tools:
  1. The tools run in parallel, each in its own process group.
  2. One that sleeps past its timeout is killed with its whole group and recorded as timed
     out, exit 124, with a stderr excerpt cut at a word boundary.
  3. One that crashes, or writes an unreadable report, fails alone and the others stand.
  4. Progress arrives as JSON lines, one as each tool starts and one as it ends.
  5. The argv snapshots are re-taken.
  **STATUS 2026-09-28:** ✅ Every tool starts at once in its own session; past its timeout
  its whole process group is killed, recorded as exit 124 with the stderr kept from a word
  boundary, and the host's reason reads *timed out after Ns and was stopped* with an
  excerpt ending on a whole word. A crash, a missing tool (exit 127) or an unreadable
  report fails its Scanner alone. Progress streams as each tool starts and ends. The
  group-kill test was confirmed to fail when only the tool is killed. No adapter's argv
  changed, so the snapshots stand. Ten engine tests; the container tests pass on an image
  rebuilt from this tree.
- [x] **R3.5** **One deadline and one kill** (F1.11, F2.7). Behaviours:
  1. At the budget, the engine stops what is running and writes a partial manifest naming
     each cut.
  2. If the engine does not return within a grace period, the host kills the container.
  3. `scan_cancel` sends one kill and waits until the runtime confirms the container is gone
     before `CANCELLED`.
  4. e2e: zero containers after each of these.
  **STATUS 2026-09-28:** ✅ The engine cuts at the plan's budget and names each cut; what
  finished stands. Twenty seconds past the budget the host stops the engine: SIGTERM, then
  SIGKILL after five, and for a container `docker kill` first, confirmed by the runtime no
  longer listing it. The engine now handles SIGTERM by stopping every tool it started,
  because each tool has its own process group and a signal to the engine's never reached
  them; the test fails without the handler. Both runtimes share `kill` and
  `wait_stopped`, and `scan_cancel` over MCP uses the Scan Container under
  `VALVUR_ENGINE=2`. On an image rebuilt from this tree, zero containers after a budget
  cut, a grace kill and a cancel. Left for R3.9's switch-over: the host does not yet turn
  the engine's progress into status lines, and the Scan Container path skips the
  first-run fetches that the fleet's runner performs.
- [x] **R3.6** **Nothing outlives its owner** (F1.11, F1.12). Behaviours:
  1. Every container carries the labels `valvur.generation` and `valvur.pid`.
  2. At each scan start and in `doctor`, containers whose owner process is dead are removed.
  3. The MCP server exits on stdin EOF, and on parent death, found by polling `getppid()`.
     Shutdown kills by label within three seconds.
  4. The workspace lock records its holder's PID, and *Busy* says whether that holder is
     alive.
  5. e2e: after `kill -9` of the server mid-scan, the next scan reaps the orphan and runs.
  **STATUS 2026-09-28:** ✅ One leaf module, `owner`, gives every container `valvur.pid`,
  `valvur.generation` and a third label, `valvur.host`: a PID means nothing on another
  machine, so a runtime shared between hosts never has another host's scan reaped. A
  structural test refuses a `run` without the labels, at all four launch sites. Each scan
  start and `doctor` remove containers whose owner has ended on this host, and say which.
  The server kills its own by label before it waits for its jobs, under three seconds with
  a fake runtime, and exits when its parent dies while stdin stays open. The lock file
  holds its exclusive holder's PID, and *Busy* says whether that process runs. On the real
  image, after `kill -9` of the server mid-scan, the next scan removed the orphans and ran,
  and the acceptance set's kill probe passes: it is judged from now on. The runtime is
  faked by `tests/fixtures/fake-runtime`, a JSON-backed stand-in for the four commands.
- [x] **R3.7** **Secrets in history** (D3; F2.1, P2). Behaviours:
  1. The host writes `git log -p --all` into the Snapshot with commit markers, within the
     bound, and says when the bound was hit.
  2. Gitleaks scans it, and each hit is mapped to its commit and path.
  3. Repository 3's credential is reported with its commit.
  4. `history = false` turns it off. The README's history claim is restored.
  **STATUS 2026-09-28:** ✅ One deviation from the letter, for the reason in ADR-0021's
  own terms: the history goes into valvur's scratch directory, not the Snapshot, so no
  other Scanner reads it as a workspace file. The host writes only the lines each commit
  added, on all refs, newest first, bounded at 5,000 commits or 200 MB, keeping where each
  commit's lines for each path begin; this repository is 445 commits, 7.1 MB, 1.5 s.
  Gitleaks reads it as a second pass, and each hit maps back to its commit and path. The
  project's path allowlists and excludes are applied on the host, because every hit is in
  one file and Gitleaks cannot apply them; this repository's own allowlist is by content,
  so it holds. A secret still in the tree stays one Finding at its line. Findings gain a
  `commit` field. Repository 3 on a real image reports `config.py` with the root commit,
  and the layout would have exposed an off-by-one line. `history = false` reads nothing
  and says so; `run.json`, the Summary and progress say what was read and any bound. The
  README's row and configuration paragraph claim history with its bounds, held by a test.
- [x] **R3.8** **`full` adds one networked container** (D4; N2.1, ADR-0010, ADR-0016).
  Behaviours:
  1. OSV-Scanner and dependency-reality's registry questions run in the second container;
     `egress.py` stays the only authority.
  2. The exfiltration constraint tests, restated for two containers, pass.
  3. `offline` starts exactly one container, with no network.
  4. Trivy never runs in the networked container.
  **STATUS 2026-09-28:** ✅ Before this, a `full` scan through the Scan Container gave
  every tool, Trivy included, the network, because one tool needed it; the new constraint
  test caught it. The plan now splits on each Invocation's own grant, which only the
  Profile gives: what needs the network runs in a second Scan Container fed the same
  Snapshot, both at once under one budget and one cancel, and everything else in one with
  no interface. The flags still come from `egress`. Three constraint tests hold it: one
  container on `offline`, with `--network=none`; two on `full`, the networked one holding
  exactly OSV-Scanner and dependency-reality; Trivy never networked. The suite's count
  check now reads "not one fewer", as its comment always said. A real `full` scan on the
  image ran both containers in 8 s, every Scanner ok and none left behind.
- [x] **R3.9** **Switch over and delete.** The new engine becomes the only engine. Deleted:
  the thread-pool fleet, both name registries, `skip_args`, `VENDORED`, the generated
  Gitleaks config (the project's own `.gitleaks.toml` is still honoured),
  `verify_workspace_readable`, width-from-memory, and `honour_gitignore`. `PROTOCOL.md`
  moves to 2, with `org.valvur.protocol="2"`. Behaviours:
  1. A major-1 image is refused, with the fix named.
  2. The constraint suite is restated for the new invariants: one container per `offline`
     scan; the workspace never mounted; zero containers after any stop.
  3. The engine's progress events become the status lines the fleet produced (29.0.4),
     and the CLI scans through the Scan Container too. Found at R3.5.
  4. A first run still fetches the absent image, database and index before the Scan
     Container starts (24.1). Found at R3.5.
  **STATUS 2026-09-28:** ✅ The CLI and the MCP server scan through the Scan Container,
  chosen because the runtime says it runs the engine; a scan through anything else is
  refused. Deleted, each with its tests or a restatement: the thread-pool fleet, the
  Checks batch, width from memory, the per-runner and per-process name registries,
  `skip_args` and every adapter's skip flags, the Checks' exclude environment,
  `VENDORED` and the vendored stage, the generated Gitleaks config (the project's own
  `.gitleaks.toml` is read by Gitleaks from what it scans), `verify_workspace_readable`,
  `honour_gitignore` and `include`, the workspace mount and relabelling. The File Set is
  built once per scan and feeds the count, applicability, the coverage notes and the
  record (`scope`, `not_read` with reasons). `--jobs` bounds the engine; the status
  lines keep their words; the fetches of a first run are unchanged. Protocol 2, and a
  protocol-1 image is refused with the fix. Each Scan Container gets D4's ceiling, 3 GiB
  or three quarters of the runtime's memory; four gigabytes asked for is exit 137 in
  9.7 s. The constraint suite holds the source never mounted, one container per
  `offline` scan and zero containers after a budget cut, a grace kill and a cancel.
  Found and fixed on the way, all in the new path: "nothing to scan" read as a failure
  and a missing report as a pass; a refusing adapter raising out of the scan; a cancel
  counting killed tools as finished; the Scan Container's mounts unlabelled for
  SELinux; a signal kill recorded as -9; the lifecycle probes waiting for two
  containers. `doctor` no longer fails an enforcing SELinux host over the source's
  label. The e2e suite on the rebuilt image: 45 passed and 3 failed on the fleet's old
  API, restated and green.

- [x] **R3.10** **`0.7.0` prepared** (D16). The version, the CHANGELOG and the README status
  line. The rehearsal runs after landing, per §4.
  **STATUS 2026-09-28:** ✅ `pyproject.toml`, `uv.lock`, the CHANGELOG's `[0.7.0]` entry,
  the README status line (release in progress, after `0.6.0`'s tag) and SECURITY.md's
  `0.7.x`. The image built as `0.7.0` carries protocol 2.

**Exit**, on both lanes:
- every expected finding, except those marked for R4 and R5;
- repository 1 complete warm in under 30 s on the Mac, under D17's swap rule;
- one container per `offline` scan, and zero after every lifecycle probe;
- the net line change of `api.py` and `runner.py` recorded.

**Exit STATUS 2026-09-28, the Mac** (`docs/acceptance/r3.md`): every repository passes, the
pending rows are R4.2, R4.6 and R5.3's alone; repository 1 took 8.1 s against 166 s at the
baseline, recorded under D17 with 10.4 GB of swap; zero containers after all four probes,
each now required to have seen a Scan Container; one container per `offline` scan held by
the constraint suite; `api.py` +64 and `runner.py` −179 lines, 115 fewer together. The e2e
suite: 48 passed in 6.4 minutes. The exit run found two defects, fixed before this:
Opengrep's own ignore list, and probes that measured nothing. Linux: the pull request's
`acceptance` run, recorded in R4's first commit with the rehearsal.

### Phase R4: the Scanner set, by rule

The first commit records R3's rehearsal.

- [x] **R4.1** **The spike** (D8; F2.1, N1.1). Measure, on the thirteen corpus repositories
  and the acceptance set:
  1. zizmor against Checkov's GitHub Actions checks;
  2. KICS and Trivy against Checkov on infrastructure. The first data point is in the
     review's 11.6;
  3. Trivy's CycloneDX output, through `trivy convert`, against Syft's;
  4. OSV-Scanner's offline database on repository 8's `MAL-` package.

  Apply D8's rules and amend ADR-0023 with the table. Each tool's licence, offline mode and
  pinning are checked before it enters the image.
  **STATUS 2026-09-28:** ✅ Measured on this Mac, every tool with no network, scripts in
  `scripts/spikes/`, the record in `docs/acceptance/r4.md`, ADR-0023 amended. **zizmor is
  adopted**: 85 of 85 unpinned actions and 18 of 18 of Checkov's write permissions at
  `--persona pedantic --min-severity medium`, 1.1 s for sixteen repositories. **Checkov
  stays**: KICS finds 14 of its 22 distinct rules on repositories 5 and 6 (Trivy 12), and
  is slower on repository 6; Checkov runs only where there is infrastructure other than
  workflows, one corpus repository in thirteen. **Syft stays**: Trivy's SBOM is 66.6% of
  Syft's components, 98.1% without the GitHub Actions Syft lists; by D9 the SBOM is
  written only with `--sbom`. **OSV's offline database joins `offline`**: MAL-2023-1 on
  repository 8 with `--network=none`, npm's database 207 MB. The spike also found
  zizmor's default persona misses a one-job workflow's `write-all`, which decided the
  persona.
- [x] **R4.2** **zizmor** (F3.11), pinned by hash in the image, credited in `NOTICE`, run
  with `--offline`. Behaviours: planted workflows with an unpinned action, write-all
  permissions and template injection each produce one ranked Finding. Repository 7's
  workflow is reported.
  **STATUS 2026-09-28:** ✅ zizmor 1.30.1 (MIT) in its own environment in the image, the
  musl wheels for both architectures pinned by hash in `requirements-zizmor.txt`, which
  the tree hash covers; credited in `NOTICE`; a row in `PROTOCOL.md` and the README. It
  runs with `--offline --persona pedantic --min-severity medium --no-exit-codes`, only
  where the File Set holds a workflow or an action definition, on both Profiles. A real
  scan of the planted workflow reports each of the three classes once, ranked, and
  repository 7's `write-all` is `excessive-permissions`, high, at line 3. Rules keep
  zizmor's audit names; the fingerprint is SAST-shaped, keyed on the offending text.
- [x] **R4.3** **Checkov only where there is infrastructure** (F2.1, F2.2), or KICS in its
  place if D8 says so. Behaviours:
  1. Repository 5's expected findings hold.
  2. A repository with only workflows skips Checkov, and the skip is reported.
  3. The image size is recorded before and after.
  **STATUS 2026-09-28:** ✅ D8 kept Checkov (R4.1). GitHub Actions workflows no longer
  decide that it runs, by name or by the content sniff, which had taken fastify's
  `@fastify/swagger` for OpenAPI; where it runs it skips the `github_actions` framework,
  so a write-all permission is zizmor's one Finding. On the corpus Checkov now runs on
  one repository of thirteen, the Terraform module; on the other twelve it cost 4 to 6 s
  of startup to find nothing. Repository 5 passes, Checkov 54.5 s; a workflows-only
  repository reports the skip with its reason. The image: 640.3 MB at R3's exit, 665.0 MB
  with zizmor (+24.7 MB); Checkov's layer is unchanged.
- [x] **R4.4** **The SBOM from Trivy's pass** (D8, D9; P3, F10.3), if D8 says so.
  Behaviours: `sbom.cdx.json` validates as CycloneDX, and its component count matches the
  parity recorded in R4.1.
  **STATUS 2026-09-28:** ✅ Not applicable: D8 kept Syft (R4.1, 66.6% of its components).
  D9's other branch, Syft only with `--sbom`, is **not applied**: it rests on the review's
  premise that no Finding depends on the SBOM, and one does. The dependency licence
  policy (F4.4 to F4.6, `valvur.licence.copyleft-in-permissive`) reads Syft's SBOM, so
  making it optional would switch those checks off by default. Syft runs as before; the
  owner decides (§8). Worth weighing: the licence policy already ignores `pkg:github`
  components, and without them Trivy's SBOM was 98.1% of Syft's.
- [x] **R4.5** **The action-pin rule moves to zizmor**, if parity holds (F3.11). Behaviour:
  the pin findings on the corpus are unchanged in count and path. Opengrep keeps the sink
  inventory and the taint rules.
  **STATUS 2026-09-28:** ✅ Parity held in R4.1, so `valvur.pinning.mutable-action-ref` left
  Opengrep's rules and zizmor's `unpinned-uses` is the one pin Finding, ranked low as the
  rule was (22.E.2). Measured with real scans of the thirteen corpus repositories: 66 pin
  findings before and 66 after, the same path and line on every repository, no Scanner
  failed, 132 s for all thirteen. Opengrep's golden lost exactly its two pin hits.
  zizmor does not flag an action pinned to a full SHA or a local one. The rule's name
  changes, so a Suppression written for the old one no longer matches: said in the
  CHANGELOG. `mutable-git-ref`, the sink inventory and the taint rules stay Opengrep's.
- [x] **R4.6** **OSV's offline database on `offline`**, if D8 says so (F3.2). Behaviours:
  1. The database is fetched and recorded like Trivy's, for the ecosystems in the File Set.
  2. Repository 8's `MAL-` package is reported at critical.
  **STATUS 2026-09-28:** ✅ D8 said so. `osv_offline` maps the File Set's lockfiles to OSV's
  ecosystems and, when a database is absent, fetches its `all.zip` into the host cache in
  the layout OSV-Scanner reads, announced and recorded in `run.json` like the other
  first-run data, a failure costing OSV-Scanner alone with the reason; `VALVUR_OSV_URL`
  names a mirror. On `offline` OSV-Scanner runs with `--offline-vulnerabilities` against
  that cache, mounted read-only, with no network; `full` keeps OSV.dev's API. A `MAL-`
  advisory is critical. Both Profiles now run the same Scanners, so the Summary's caveat on
  `offline` says it does not ask the network, not that a Scanner did not run. On the real
  image, repository 8 reports MAL-2023-1 at `package-lock.json`, critical; the first run
  fetched npm's database, 217 MB in 6.7 s. **The cost:** OSV-Scanner loads the whole
  ecosystem database on every scan, 10.4 s warm on this Mac for one npm lockfile, so
  repository 8 went from 5.2 s at R3's exit to 14.2 s. D8's rule accepted that price for
  known-malicious packages; the Linux figure is R4's exit.

**Exit:** ADR-0023 amended. The fastest application-repository scan on Linux is at most half
of R2's baseline. Repositories 5 and 8 behave as D8 decided. `NOTICE`, the licence checks and
the reproducible-image check are green.

**Exit STATUS 2026-09-28** (`docs/acceptance/r4.md`), three of four met:
- ADR-0023 amended with R4.1's table. ✅
- **The fastest application-repository scan on Linux: 3.4 s against R2's 5.4 s, 63%, not
  half.** ❌ The `corpus` run 36375041325 against run 36250465513: every application
  repository is faster, by 18% (requests) to 55% (express), because Checkov no longer runs
  on them. The floor is now Opengrep, 2.7 to 3.4 s on every small repository, most of it
  startup: its one-file binary unpacks 243 MB into the Scan Container's tmpfs on every
  scan (0.45 s measured) and imports its CLI (1.25 s). The target assumed the review's set,
  Syft replaced and no OSV on `offline`; D8's measurements kept Syft and added OSV, both
  by rule. No fallback is recorded for this threshold, so the miss is recorded and the
  choice is the owner's (§8).
- Repositories 5 and 8 as D8 decided. ✅ Checkov still runs on repository 5 and its
  expected findings hold: 62.1 s on the Mac, 112.9 s on Linux, where R3 took 58.8 s and
  the corpus's run of the same module 79.1 s, so Linux's Checkov time is noisy. Repository
  8 reports MAL-2023-1, critical, on both lanes, at OSV's price: 15.2 s on the Mac and
  12.2 s on Linux, from 5.2 s and 2.4 s. Every scan of a project with an npm lockfile
  pays about 10 s, the probes included.
- `NOTICE`, the licence checks and the reproducible-image check green on #148. ✅

The acceptance set on both lanes: every repository passes once repository 6's pin moved, and
zero containers after all four probes. The exit run found three defects, fixed before this:
zizmor's eleven high findings on valvur's own workflows, which failed the self-scan gate,
and two scripts left on the pre-R3.9 runner, the corpus and `verify-offline.py`.

### Phase R5: the report

- [x] **R5.1** **Groups** (F5.8, F7.5, F7.14). Behaviours:
  1. 3,890 `generic-api-key` hits under one directory form one group, ranked below eight
     distinct findings, and labelled as possible machine-written data.
  2. `findings.json` keeps every Finding with its group id.
  **STATUS 2026-09-28:** ✅ Measured first: repository 1's flood no longer reaches a scan,
  because its `data/` is gitignored and the File Set (R3) leaves it out. A flood now comes
  only from tracked data or a folder walk. On the corpus, no rule repeats more than 17
  times under one directory, so a group starts at 25 hits of one rule under one top-level
  directory. Data files group apart from code, and only a group of data files is labelled
  possibly machine-written and ranked below every distinct Finding. A new pipeline stage,
  `group`, runs between `suppress` and `rank`. Each Finding carries `group`, and
  `findings.json` lists the groups derived from those ids, additive to schema 1. On the
  image, a tracked repository of 3,890 JSON files with API-key-shaped values and four
  planted files took 23.8 s. It produced 7,640 Findings in two groups, all under `data/`:
  Gitleaks' `generic-api-key` on 3,694 files, and Checkov's `CKV_SECRET_6` on 3,890. The 56
  distinct Findings ranked 1 to 56. Checkov's secrets framework reports nothing on the
  acceptance set or the corpus, so it stays.
- [x] **R5.2** **`SUMMARY.md` leads with what matters** (F7.4 to F7.7, N1.3). Behaviours:
  1. The order is: verdict, scope manifest, what did not run, top groups, Hygiene, then a
     shortened agent block at the end.
  2. No title is cut mid-word, at every truncation site.
  3. The golden files are re-taken.
  **STATUS 2026-09-28:** ✅ The review asked for a group to be "one entry with a count and
  its locations", which fixes the lab's one rule listed eight times. So a group now starts
  at two hits, and only a flood of 25 or more data files is machine-written and ranked
  last. Two real keys in `config/*.json` keep their rank. The document runs in this order:
  - the verdict and what qualifies it;
  - the Status and counts, in two lines;
  - `## Scope`: what was read, by which Scanners, what the File Set left out, and what
    the Profile leaves to the network;
  - `## What did not run`;
  - `## Most urgent`, a group as one line with its count and first three locations, and a
    flood that did not make the top list still named;
  - accepted risks and fixes;
  - `## For AI agents`, seven lines, which the cap never cuts.

  F7.6 is amended; the MCP handshake carries the rules in full (`AGENT_RULES`), and its
  snapshot changed in one sentence. Titles are cut at word boundaries on all five surfaces
  that cut them, through `text.cut`. Eight goldens are re-taken. On the image, repository
  1's `SUMMARY.md` went from 68 lines to 43. The tracked flood's went from 86 to 61, and
  names both floods. Observed and not changed: a run with a failed Scanner and no finding
  still has Status `clean`, with `complete: false` beside it. The gate fails it, but the
  agent block's gloss of `clean` does not fit it; this belongs to R6's reply.
- [x] **R5.3** **Local agent configuration that would leak** (F3.6). Behaviour: `.mcp.json`,
  `.claude/settings.local.json`, `.kiro/settings/mcp.json` and their peers, when git does not
  ignore them and they hold absolute local paths or credential-shaped values, yield a medium
  Finding. Repository 7 is reported.
  **STATUS 2026-09-28:** ✅ `valvur.ai-artifact.local-config-exposed` is medium and fires once
  per file. It reads nine local configuration files by path tail: `.mcp.json`, Claude
  Code's two settings files, and the MCP or settings files of Kiro, Roo, Cursor, Gemini,
  Continue and aider. It looks for a home directory on macOS, Linux or Windows, and for a
  quoted credential-shaped value under a token, secret, password, key or Authorization
  name. A value is never written, only its key; a reference like `${VAR}` is portable and
  not reported. The Check reads the Snapshot, which keeps ignored agent configuration
  (ADR-0021), and cannot ask git, so the File Set now records the files git ignores and a
  pipeline stage, `ignored`, drops the Finding on them. On the image, repository 7
  reports it at `.mcp.json` and passes with nothing pending. The thirteen corpus
  checkouts gain no such Finding. On this Mac, Claude Code's global git ignore already
  covers `.claude/settings.local.json`, so that file is correctly not reported here.
- [x] **R5.4** **`REMEDIATION.md` per group** (F7.14). Behaviour: the gate's flood yields one
  action naming the count and the exclude line.
  **STATUS 2026-09-28:** ✅ Before, on the tracked flood, `REMEDIATION.md` was 196 lines:
  one "rotate the credentials" item per data file, the top 25 shown. A flood of
  machine-written data is now one item, ranked last. It asks what the directory is,
  names every rule and the total, and gives the exclude line (`exclude = ["data"]`, a
  segment prefix) with "ask the human before adding it". An exclusion hides the directory
  from every Scanner, the cheaper path to zero that `CLAUDE.md` §4 names. Floods are
  keyed by directory, because one exclude resolves them all: Gitleaks and Checkov both
  flooded `data/`. After, on the image: 8 actions resolve 7,639 Findings in 109 lines, and
  the eighth is the flood of 7,584 hits. Other groups keep their per-file actions,
  because rotating two keys in two files is two actions.
- [x] **R5.5** **Repository hygiene** (D13). Behaviours:
  1. A missing `SECURITY.md`, no dependency-update configuration, and write-all default
     workflow permissions each appear in the Hygiene section.
  2. None of them changes the Status.
  3. The corpus is measured and its counts recorded.
  **STATUS 2026-09-28:** ✅ `hygiene.assess` reads three facts on the host from the File
  Set, because they concern which files exist:
  - a security policy where GitHub looks, the root, `.github/` or `docs/`;
  - Dependabot or Renovate configuration;
  - the workflows with no top-level `permissions:`.

  D13 was written before R4.2 made an explicit `write-all` zizmor's ranked Finding, which
  repository 7 expects, so that Finding stays. The third fact is what no Finding says: a
  workflow with no top-level `permissions:` runs with the repository's default token,
  write-all on repositories created before February 2023, and that setting is in no file.
  The facts are recorded in `run.json` as `hygiene`, with the paths, and a Hygiene section
  after the top entries names only what is missing. None is a Finding or changes the
  Status. On the corpus, of thirteen repositories:
  - 7 have no security policy of their own; express and flask publish theirs
    organisation-wide, which the line now says a scan cannot see;
  - 5 have no Dependabot or Renovate configuration;
  - 3 have workflows left to the default token: sinatra 1 of 2, smolagents 5 of 6 and
    terraform-aws-vpc 5 of 5.

  valvur itself has all three.
- [x] **R5.6** **Borrowed injection patterns** (D14; F3.6, F3.12). Behaviours:
  1. Each translated pattern fires on its planted fixture.
  2. The corpus's real agent files gain no finding.
  3. `NOTICE` credits the source.
  **STATUS 2026-09-28:** ✅ Measured first with `scripts/spikes/r5_6_patterns.py`. The
  spike ran every string of cisco-ai-defense/mcp-scanner's `prompt_injection`,
  `coercive_injection`, `data_exfiltration` and `credential_harvesting` YARA rules
  (Apache-2.0, commit `9e47aab`) over three sets:
  - the corpus's agent files, 2;
  - the 263 real instruction texts in awesome-cursorrules, which are not live surfaces
    but are the best false-positive corpus there is;
  - valvur's own agent files, 8, since the self-scan gate fails on any Finding.

  **41 adopted**: the strings Cisco's condition treats as a detection on their own, and
  that found nothing in any set. **Left out**:
  - five with a hit: `tool_injection_commands`, 4; `hidden_behavior`, 1;
    `conversation_exfil`, 1; `sends_conversation`, 1; `leak_param`, 14;
  - `upload_external` and `external_endpoints`, whose precision rests on a negation of
    template text;
  - credential harvesting's conjunction parts, for instance `access_actions_words` on
    134 of the 263 texts.

  The adopted patterns are in `checks/borrowed.py`, verified identical to the source.
  They extend `prompt-injection` and add three classes, all high and ranked beside it:
  `coercive-directive`, `exfiltration-directive` and `credential-harvesting`. Each title
  names the pattern. Matching is whole-text, so a hidden HTML comment spanning lines is
  read. Each fires on a sentence written for it, valvur's own agent files gain none, the
  weekly corpus run treats every class as suspect, and `NOTICE` credits the source at
  its commit. The telemetry test exempts the one detection pattern containing the word.

**Exit:** repository 1's `SUMMARY.md` fits one screen. Repository 7 is fully reported. The
corpus gains no finding from R5.6.

**Exit STATUS 2026-09-28** (`docs/acceptance/r5.md`), all three met:
- **Repository 1's `SUMMARY.md`: 45 lines, from 68 before R5.** It fits a laptop editor's
  screen with room. The exit measurement first read 50 once Hygiene joined, four of them
  the document explaining itself, so each was folded into the line it belonged to; a test
  holds a summary of that shape to 45. Nine lines are prose paragraphs over 120 columns,
  which a Markdown view flows and a narrow terminal wraps.
- **Repository 7 is fully reported:** zizmor's `excessive-permissions` and `artipacked`,
  `local-config-exposed` at `.mcp.json`, and the missing licence; nothing pending.
- **The corpus gains no finding from R5.6.** The `corpus` run 36382628508 on this branch
  against R4's 36375041325 shows no rule's count changed on either Profile, and no
  AI Artifact finding anywhere; the corpus passes.

The Mac lane: every repository passes with nothing pending, and zero containers remain
after all four probes. The e2e suite on the rebuilt image: 50 passed. Linux: #149's checks.

### Phase R6: the agent surface

- [x] **R6.1** **Measure the client before relying on it** (F9.1). In Claude Code, a stdio
  tool call that runs 150 s and sends progress: is it backgrounded at two minutes, and does
  its result reach the model? The answer is recorded in ADR-0024, and D6's fallback applies
  if needed.
  **STATUS 2026-09-28:** ✅ ADR-0024 confirmed, and D6's fallback does not apply. The spike
  is `scripts/spikes/r6_1_background.py`: a stdio server whose one tool runs for the time
  asked, sending progress every 10 s, and returns a number. Claude Code 2.1.283, headless,
  was asked for the number. For 150 s, the number reached the model as the call's own
  result, in 3 turns and 186.9 s, the same turns as a 5 s control; no polling, nothing
  lost. The interactive client's move to the background at two minutes is documented and
  cannot be driven unattended; for such a client, or one that times out, the second
  `scan` attaching (R6.3) is the path. Cost $0.95, so the agent ledger stands at $8.10 of
  $25.
- [x] **R6.2** **Reply schema 2** (D7; F9.8 to F9.10). Behaviours:
  1. The snapshot is re-taken.
  2. The largest acceptance repository's reply stays under 25,000 tokens.
  3. Every state's fields agree with its text, which is rendered from the fields.
  **STATUS 2026-09-28:** ✅ `reply.py` builds one schema for six states: `none`, `running`,
  `cancelling`, `cancelled`, `failed` and `done`. Its fields are `state`, `verdict`,
  `reason`, `complete`, `scope`, `counts`, `groups`, `not_run`, `not_read`, `progress`,
  `next`, `error.kind`, and `report`, which carries `SUMMARY.md`'s text. The text is a
  function of the fields alone, and a test holds that for every state. `error.kind`
  says why there is no result: `no-scan`, `cancelled`, `precondition`, `budget`, `busy`
  or `failed`. Every state but `done` says what to do in `next`. The tools/list output
  schema describes schema 2, and its snapshot is re-taken; sixteen tests move from the
  old shape. On the acceptance set the largest reply is repository 2's: 10,233
  characters structured, about 3,400 tokens. The bounds are the first 20 left-out
  entries with a total, and 30,000 characters of summary. They hold a pathological
  repository, 3,000 ignored directories and a 200-line summary of long lines, under
  25,000 tokens at three characters a token, both forms together.
- [x] **R6.3** **`scan` blocks and returns** (D6; F9.1). Behaviours, over stdio:
  1. One call yields the result, with progress notifications on the way.
  2. A disconnect, then a second call, yields the same generation.
  3. `scan_status` attaches.
  **STATUS 2026-09-28:** ✅ The protocol answers each `tools/call` on its own thread, with
  writes serialised, so `scan_cancel`, `ping` and a cancellation still reach a server
  whose `scan` is waiting. A call carries its progress token. `scan` starts the scan,
  or attaches to the one running here, forwards each progress message as
  `notifications/progress`, and returns schema 2 when it settles. A client that lets
  go, by cancelling the request or closing stdin, stops the wait and not the scan; the
  next `scan` attaches and returns the same generation, and a test holds that only one
  scan ran. A cancelled request is not answered, per MCP. `scan_status` attaches the
  same way and never starts a scan; its wait, 15 s since task 10.2.5, is now 330 s,
  since R6.1 measured the premise gone. The acceptance probes' client now routes
  replies by id. Its next-scan check reads that scan's own end state, where an immediate
  *Started* would have passed a scan that then failed. On the image, the cancel, budget
  and stdin probes and the shutdown test pass. The kill probe failed once, on the run
  whose image bake had timed out fetching Opengrep, and then passed three times on the
  rebuilt image.
- [x] **R6.4** **Inputs from the client's roots** (F9.1, N2.2). Behaviours:
  1. The workspace defaults to `CLAUDE_PROJECT_DIR`, or the first root from `roots/list`.
  2. A workspace outside the roots is refused.
  3. Every schema has `additionalProperties: false`.
  4. Every violation fails synchronously, with a kind and one sentence.
  **STATUS 2026-09-28:** ✅ The protocol keeps the capabilities the client declared at
  `initialize`, puts requests to the client under its own ids, and routes the answers
  back to the call that asked. A client's answer used to be read as a malformed request.
  A call naming no workspace scans `CLAUDE_PROJECT_DIR`; failing that, the first root
  of a client that declared roots, asked once per session and again after
  `roots/list_changed`; failing that, where a terminal stands. A workspace under none of
  the client's roots is refused before anything runs, naming them, and nothing is
  created there. The `Tool` closes every schema itself. The server checks each call
  against its schema first, refusing an unknown argument, a missing one, or one of the
  wrong type; a number sent as a string is still a number (R1.5). Every refusal
  carries its kind in the structured form, as schema 2's `refused` state:
  `invalid-argument`, `unknown-argument`, `missing-argument`, `relative-path`,
  `no-directory`, `not-a-directory`, `outside-roots`, `no-results` or
  `unknown-fingerprint`. Thirteen violations are each held to their kind, one sentence,
  and an answer within two seconds with no job started; the roots are driven over live
  stdio with the test client answering `roots/list`.
- [x] **R6.5** **One `findings` tool, seven CLI commands** (D12; F9.1, F9.3, F9.8). Behaviours:
  1. The tool filters by fingerprint, group, rule and path, and says when it clamped.
  2. `valvur findings` absorbs `explain`; `doctor` and `update` absorb `cache`.
  3. The old names print the new form.
  4. A parity test runs over every MCP tool and its CLI command.
  **STATUS 2026-09-28:** ✅ `findings_reply` is one operation for both surfaces.
  - **Filters:** group, rule, path prefix on whole segments, status and suppression.
    With a fingerprint it answers that Finding in full: its sources, exploitation,
    dependency path, suppression and group, as `detail`.
  - **Clamping:** a limit over 100 is clamped, and the reply says so in both forms.
  - **MCP:** `list_findings` and `explain_finding` stay one release, described as
    deprecated, because a client may have allowed them by name.
  - **CLI:** the usage names seven commands: `scan`, `update`, `findings`, `status`,
    `doctor`, `gate` and `suppress`. `findings` takes the four filters, `doctor` reports
    the host cache's parts, sizes, ages and total, and `update --prune` and `--clear`
    tidy it without fetching. `explain` and `cache` still work and say on stderr what
    replaced them. R6.8's `init` makes eight, by D10.
  - **Parity:** `tests/test_cli_parity.py` holds every tool to a CLI counterpart named in
    one table; `scan_cancel`'s is Ctrl-C. On one scanned `broken-repo` each reader's text
    and its command's output are identical, and an MCP scan and a CLI scan reach the same
    verdict and counts.

  The README and EVALUATING name the new forms.
- [x] **R6.6** **Fresh data without a terminal** (D5; F10.8). Behaviours:
  1. An eight-day-old database is refreshed inside a scan and recorded.
  2. With `fetch = "never"`, the result is `inconclusive` with the reason.
  3. The `update` tool fetches, and says what it fetched.
  **STATUS 2026-09-28:** ✅ ADR-0025 reverses task 14.2. A scan refreshes stale data as it
  fetches absent data, each fetch announced and recorded under `network.fetched`:
  - a vulnerability database over 7 days old (*refreshing the vulnerability database
    (8 days old)*);
  - a name index over 30;
  - an OSV database over 7.

  `VALVUR_FETCH=never`, read by a new `settings` module that R6.7 extends to the machine
  settings file, turns every fetch off. A nil result over stale data then says
  *fetching is off (fetch = never)* in its reason. Three tests of 14.2's line are restated
  to ADR-0025's. `valvur update`'s steps move from `cli.py` to `updating.py`, each saying
  its line through a `say` the caller passes. The new `update` MCP tool runs them, sends
  each line as progress, answers with what it fetched, and is not refused by
  `fetch = never`, being an explicit request. On the image, with the build cache's
  database aged eight days, a scan refreshed it: 123 MB in 29 s, recorded, a 40 s scan,
  and data 0.03 days old after. Found on the way: a test that failed when run alone,
  hidden by a cache an earlier test warmed.
- [x] **R6.7** **Two settings files** (D11). Behaviours:
  1. Machine settings are read from `~/.config/valvur/config.toml`.
  2. Each retired environment variable still works and prints one deprecation line.
  3. `doctor` prints the effective settings and where each came from.
  **STATUS 2026-09-28:** ✅ One `settings` module; every read the shim made of a
  `VALVUR_` variable goes through it: sixteen sites in eleven modules. The machine's file,
  `$XDG_CONFIG_HOME/valvur/config.toml` (by default `~/.config/...`), is read once per
  change and holds fifteen keys:
  - **overridable by their variable:** the image, the cache, the runtime, debugging,
    fetching, and the seven mirror settings;
  - **retired to the file:** `jobs`, `container_network` and `selinux_relabel`. Their
    variables still work in this release and say so once on stderr, naming the key.

  The container's own variables, set by the shim, are not settings and stay. An
  unreadable file is said and its settings not applied, and `doctor` warns with the path.
  `doctor` prints each setting in effect and where it came from: the variable, the
  file, or nothing set. The budget's levers, the CLI's help, the README and
  `docs/AIR-GAPPED.md` name the file's keys. Implemented as one commit: the three
  behaviours are one module.
- [x] **R6.8** **`valvur init` and the schema** (D10). Behaviours:
  1. `init` prints the client file for each client found and a starter `.security-scan.toml`
     with excludes suggested by the pre-flight count, and writes nothing.
  2. The JSON Schema validates every example in the README.
  3. `doctor` names the first invalid key.
  **STATUS 2026-09-28:** ✅ **`valvur init`** finds a client when a file it reads, or the
  folder that holds it, exists in the project or the home directory, the lookups
  `doctor` makes. For each it prints the file, the block and what to do after; with
  none found it names Claude Code and Kiro. The starter `.security-scan.toml` states
  every choice and lists the largest directories from the pre-flight count. It suggests
  excluding a directory holding most of the files, commented out, since that is the
  owner's decision. A test holds every file's mtime unchanged. The usage now names
  eight commands: D12's seven and D10's `init`.

  **The schema** ships as `src/valvur/data/security-scan.schema.json`: `[scan]`
  `exclude`, `history` and `scope`, and `[[suppress]]` with its five required fields.
  `project_schema.py` validates the subset it uses, with no dependency, and answers
  with the first problem, naming the key. The README gained the example it lacked; it,
  the repository's own file and `init`'s starter all validate. **`doctor`** warns with
  the first invalid key, for example `` `scan.exclud` is not a key it takes ``, which
  was ignored in silence before. Found on the way: ADR-0021's `scope = "tree"` was
  decided and never read, and is implemented.
- [x] **R6.9** **`doctor` and the reply tell the truth about the session.** Behaviours:
  1. `doctor` says when the running server is older than the configuration names.
  2. The reply and the handshake say the Results Folder ignores itself.
  **STATUS 2026-09-28:** ✅ From the second gate's C5 and C6, in 30.1.2's and 30.1.3's
  words. Inside the server, `doctor` compares its own executable with the command that
  `.mcp.json` or Kiro's file names, where that resolves to a path. When they differ it
  says *this server is <version> at <path>; .mcp.json names <command>; restart the
  client to use it*. A launcher like `uvx` resolves at start and is not compared. The
  CLI has no session and prints no such line; the parity test sets it aside and says
  why. The handshake says *the folder ignores itself; there is nothing to add to
  .gitignore*, and a finished scan's reply checks the folder's own `.gitignore` and
  says the same, as `results.ignores_itself` and one line of text.
- [x] **R6.10** **The Kiro probe** (D20). Behaviour: a stdio client replaying Kiro's
  initialize, tools/list, calls and cancellation passes in CI.
  **STATUS 2026-09-28:** ✅ `tests/fixtures/mcp/kiro-sequence.json` holds Kiro's calls in
  order. No transcript of Kiro exists in the repository, so this is the MCP TypeScript
  SDK client's shape as Kiro uses it, labelled a documented shape; the GUI pass is the
  owner's (§8). The sequence:
  1. `initialize` with Kiro's client info and roots;
  2. `notifications/initialized`;
  3. `tools/list`;
  4. `doctor` and `scan` with progress tokens;
  5. a `ping` while the scan runs;
  6. `notifications/cancelled` for the scan;
  7. `scan_cancel`;
  8. `scan_status`.

  Every request but the cancelled one is answered once, with no JSON-RPC error. The
  cancelled scan gets no reply and is stopped by `scan_cancel`. The sequence runs
  in-process on every test run, and as an e2e test against a real `valvur-mcp` and the
  image, which CI's end-to-end job runs: 17.8 s, no container left. **Observed, not
  changed:** a `scan_cancel` sent within milliseconds of `scan`, before the scan's job
  exists, cancels nothing, and the scan then runs. The in-process probe first went red
  on exactly that, until it waited, as Kiro does, for the scan to be running.

**Exit:** agent scoring reaches a correct report in 6 turns or fewer on every repository.
Every bad input fails synchronously. The CLI parity test is green.

**Exit STATUS 2026-09-28** (`docs/acceptance/r6.md`), two of three met:
- **Agent scoring: a correct report in six turns or fewer on 4 of 8 repositories, not
  all.** ❌ The first exit run reached 3. Its traces found four causes, fixed before the
  second run:
  1. `next` sent the agent to `explain_finding` and REMEDIATION.md after the whole summary
     was already in `report`;
  2. the deprecated MCP tools cost a deferred-tool load each;
  3. a group line repeated one location;
  4. the harness left `expected.toml` where the agent read it.

  The second run: turns 5, 4, 7, 6, 5, 3, 5, 7, so six of eight fit six turns. Six of eight
  named every expected finding. Repository 2's answer omitted `requirements.txt`, and
  repository 5's named neither of its two rules, though both are in the summary it was
  given. The ledger stands at $18.04 of D19's $25. The rest is kept for R7's exit, which
  measures the same criterion for `1.0.0` (D17). The answers are now kept beside the
  score, so the next misses can be read. The choice is the owner's (§8).
- Every bad input fails synchronously: ✅ thirteen violations held to their kind, one
  sentence and two seconds, with no job started (R6.4).
- The CLI parity test is green: ✅ every MCP tool against its command (R6.5).

The Mac lane on the rebuilt image, host swap 12.8 GB: every repository passes with nothing
pending, zero containers after all four probes, and the e2e suite 51 passed, the Kiro
probe against the real server among them. Linux: #150's checks.

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
| `v0.6.0` | **ready 2026-09-27**: R1 landed at `bbf77ef`; rehearsal 36353560849 green through validation on both architectures in 13 minutes, cancelled at the brake | sign and push the tag `v0.6.0` on `bbf77ef`; approve the real run at the brake |
| land R2, PR #145 | **ready 2026-09-28**: every check green on `d04e72f`, the Linux acceptance run included | fast-forward `main`: `git push origin refs/remotes/origin/build/r2-the-acceptance-set:refs/heads/main`. The build's own push to `main` was refused by the session's permission classifier on 2026-09-28 00:40; R3 continues on a branch rebased onto R2 and lands after it |
| `v0.7.0` | R3 lands (after R2's PR #145), then its rehearsal | sign and push the tag `v0.7.0` on the rehearsed commit, after `v0.6.0`; approve the real run at the brake |
| `v1.0.0` | R7 | the same |
| the gate with a person (12b.3, 10.1) | `1.0.0` | find someone outside the repository; they follow the README on a project of their own |
| Kiro's GUI pass | R6 | one scan through Kiro, recorded in `docs/gates/` |
| a self-hosted Mac runner, optional | R2 | register one with the label `docker-desktop` |
| a second maintainer (28.1.3) | any time | `MAINTAINERS.md`'s five steps |
| the runner move (28.3.8) | after 2026-11-19 | ask any session to move the pinned runner images and land it |
| AWS measured runs: ECR mirror and CodeBuild (F1.10) | R8 | run once in an AWS account and record the numbers |
| `init --write` | R6 | decide whether `init` may write files |
| free memory and disk on the build Mac | now | quit Chrome or restart the Mac: host swap was 14.05 of 14.34 GB and the Docker VM almost entirely paged out (R0.2); optionally `docker builder prune` to reclaim 21 GB of build cache the build will not touch itself |
| ~~stop: Docker Desktop is not running~~ **resolved 21:41** | 2026-09-27 21:38 | it was quit from its menu at 21:33:48, midway through R0.6's e2e run; the owner started it again at 21:41 and the build resumed |
| pre-approve the durable resume task | now | open *Scheduled* in the sidebar, `valvur-build-resume`, *Run now* once, and approve its tools, so a real resumption never pauses on a prompt |
| land R3, PR #146, then R4, PR #148 | R2 lands | the same fast-forward, one branch at a time, in order. Not a squash or a rebase merge: repository 6 of the acceptance set is pinned to R4's commit `eb3a199` and needs that hash on `main` |
| R4's speed exit, missed | **now** (R4's exit) | the fastest application-repository scan on Linux is 63% of R2's baseline, not half (§7, R4). Accept it, or take a task to unpack Opengrep in the image at build: measured 0.45 s faster per scan, 243 MB less tmpfs memory, `/tmp` no longer executable, and the image about 190 MB larger; about 3.0 s, still short of 2.7 s. A second lever is OSV's offline database, about 10 s on every npm project on both lanes, which D8 accepted for `MAL-` packages |
| land R5, PR #149 | R4 lands; **every check green on `7b4e6a6`** | the same fast-forward, after #148 |
| land R6, PR #150 | R5 lands | the same fast-forward, after #149 |
| R6's agent exit, missed | **now** (R6's exit; also D17 for `1.0.0`) | 4 of 8 repositories reach a correct report in six turns or fewer; six of eight fit six turns, and the misses are an answer that names a CVE without its file and one that describes two rules without their IDs. Decide whether a correct report must name the rule ID and the path, as the scorer demands, or whether it may describe them, which would pass both misses. The build's $6.96 left under D19 pays for one more full run, at R7's exit |
| the MCP tools `list_findings` and `explain_finding` | R6 (removed) | removed at R6's exit, not kept a release: each cost an agent a deferred-tool load. A client that allowed them by name needs `findings` instead; the CHANGELOG says so |
| D9 and the SBOM | now (R4.4) | decide whether Syft becomes `--sbom` only: that would switch the dependency licence policy (F4.4 to F4.6) off by default, which D9 did not weigh; or amend D8 to count packages without GitHub Actions, where Trivy's SBOM is 98.1% of Syft's and could carry both |
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
