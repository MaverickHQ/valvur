# valvur: tasks

**Written 2026-09-27, second version of the day.** The owner accepted every recommendation
in [the review](../../../docs/history/REVIEW-2026-09-27.md), section 11 included, and asked for a list
that runs end to end without them. This replaces the same day's Phases 31 to 37. It is
authoritative for what is open.

**IDs.** Tasks here are `R<phase>.<n>`; R0 to R6 are closed and in
[their archive](../../../docs/history/tasks-phases-r0-r6.md). A bare ID such as `29.0.5`
or `0.1` refers to [the archive of Phases 0 to 30](../../../docs/history/tasks-phases-0-30.md). §9 maps the
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
| D9 | **The Results Folder.** SARIF is always written. The SBOM is always written when it comes from Trivy's pass, and otherwise only with `--sbom`. *Amended by the owner 2026-09-28: Trivy's pass was not adopted (R4.4), so the SBOM is Syft's and opt-in, `--sbom` or `sbom = true` under `[scan]`, the dependency licence policy with it.* | none needed |
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

Phases R0 to R6 are closed, each with its STATUS notes and its exit as measured, in
[the archive of Phases R0 to R6](../../../docs/history/tasks-phases-r0-r6.md).

### Phase R7: documents, and `1.0.0` prepared

- [x] **R7.1** **The README, rewritten against what exists** (P6). Behaviours:
  1. Every number in it is the acceptance set's.
  2. The tool table matches the image.
  3. The client table matches `doctor`.
  **STATUS 2026-09-28:** ✅ `tests/test_readme_as_built.py` holds all three. A time, size or
  count the README cites is a code limit or a figure `docs/acceptance/` records with the
  same kind of unit: the old README failed on 17, dated measurements from four releases.
  What no record held was measured into `docs/acceptance/r7.md`: a first scan from an
  empty cache, 59 s; the index, 6,334,163 names; the published image, 256 MB to pull.
  The tool table is the adapters' seven Scanners with NOTICE's licences, and the three
  Checks. Rewriting found three defects, fixed:
  1. the client block lowercased every note after its first letter, so Kiro's users were
     told to enable `kiroagent.configuremcp`;
  2. the CLI and the `scan` tool said `full` adds OSV-Scanner and the dependency-reality
     Check, which have run on `offline` since R4.6 and ADR-0018 (`profiles.FULL_ADDS`);
  3. `doctor`'s fetch sizes were 118 and 34 MB, measured now at 123 and 36.
  The README also said a stale database is never refreshed by a scan, that a small VM
  runs two Scanners at a time, that `scan_status` is polled, and that a first run takes
  58 s on `0.3.0`; each now says what R3 to R6 built.
- [x] **R7.2** **`EVALUATING.md`, `design.md`, `PROTOCOL.md`, `AIR-GAPPED.md` and
  `requirements.md` as built.** Amendments only, and no ID renumbered. Behaviour:
  traceability holds.
  **STATUS 2026-09-28:** ✅ `check_traceability.py`: 0 uncited, 0 orphan ADRs, 136 IDs.
  - `design.md` 1.3: the Scan Container and its Snapshot in §1, zizmor, Checkov's rule
    and OSV on `offline` in §2, stale data refreshed in §6a, three readers in §8.
  - `EVALUATING.md`: the first run from `acceptance/r7.md`; OSV on `offline` for its
    `MAL-` data; the taint rules as 23.5.3 measured them; the index's counts; 25 ADRs.
  - `AIR-GAPPED.md`: four things, not three, OSV's mirror, the settings file first.
  - `requirements.md`: F1.1 and F10.8 met, F1.5, F2.1, F9.1, F9.3 and F10.5 amended.
  - `PROTOCOL.md`: the `container_network` setting; ADR-0023 notes its SBOM branch.
  One defect, fixed: `verify-mirror.py` refused OSV's mirror and read no settings file,
  so an honest air-gapped setup failed its own proof. `valvur update` does not fetch
  OSV's databases, which only a project names; the README and `AIR-GAPPED.md` say so.
- [x] **R7.3** **Documents consolidated.** `OPEN-ITEMS.md`, `POSITIONING.md`, the reviews,
  `usability-gate.md`, `council/` and `gates/` move to `docs/history/`, and their still-true
  points move into the README or `EVALUATING.md`. Behaviour: a link check over every
  Markdown file finds no broken relative link.
  **STATUS 2026-09-28:** ✅ `tests/test_links.py` reads every tracked Markdown file but the
  fixtures', code apart. Before the move it found 67 broken links, all in the two
  archives R0 had moved without re-pointing them; every link in a moved file is now
  resolved from where the file was written and re-pointed at where its target lives.
  `docs/` holds `AIR-GAPPED`, `EVALUATING`, `PROTOCOL` and `RELEASING`, the ADRs, the
  acceptance records and `history/`, which has an index. Carried forward: POSITIONING's
  measured limit on claim 3, that KEV rarely lists an application dependency, now in
  `EVALUATING.md` §5 and the README; OPEN-ITEMS' open refactors had closed in Phase 27;
  the usability gate stays the protocol for the owner's gate with a person (§8).
- [x] **R7.4** **`CLAUDE.md` and this file.** `CLAUDE.md` is refreshed within 200 lines. Closed
  phases move to `docs/history/`.
  **STATUS 2026-09-28:** ✅ this file drops to 335 lines: Phases R0 to R6, each with its
  STATUS and exit, are `docs/history/tasks-phases-r0-r6.md`. The acceptance harness
  reads that archive as well as this file, since an expectation that waited on R3.2 would
  otherwise read pending again (55 closed tasks, all still seen as done), and
  `build_status.py` finds the current phase unchanged. `CLAUDE.md`, 199 lines: the status as
  it stands (`main` at R1, R2 to R6 waiting to land, R7 and R8 next), the landing rule as it
  is (the owner lands each phase), OSV's databases among the moat's recorded fetches, and
  the rule that the README cites only measured numbers.
- [x] **R7.5** **`1.0.0` prepared** (D16, D17). D17's criteria are measured on both lanes and
  recorded. The CHANGELOG states the stability claim. The rehearsal runs after landing, per
  §4.
  **STATUS 2026-09-28:** ✅ `823259f`: the version, the lock, the README status line and
  `SECURITY.md` at `1.0.0`. The CHANGELOG's `1.0.0` entry names what 1.x keeps: the six MCP
  tools and reply schema 2, the eight commands and their exit status, the Results Folder's
  files and schemas, `fp_version` 1, the three Statuses, both settings files and protocol
  2; the deprecated names keep working through 1.x, and the code and documents that said
  "for one release" say so. D17 is measured in `docs/acceptance/r7.md`, four criteria of
  five; the agent pass is not (below). One defect found on the way, fixed: `doctor`
  declared `readOnlyHint: true` and "changes nothing" while it removes the containers of
  ended scans (R3.6), and its image line named the deprecated `valvur cache --prune`.

**Exit:** the acceptance set fully green on both lanes, every `until` resolved, and D17 met.

**Exit STATUS 2026-09-28** (`docs/acceptance/r7.md`):
- **The acceptance set, the Mac lane:** ✅ the image baked as `1.0.0`, host swap 13.6 GB:
  every repository passes with nothing pending, repository 1 in 7.6 s, zero containers
  after all four probes, and the e2e suite 51 passed. **Linux:** the `acceptance` check on
  R7's PR; R6's commit passed there with nothing pending (#150, recorded in `r7.md`).
- **Every `until` resolved:** ✅ nothing pending on either lane; the harness reads the
  closed phases from their archive (R7.4).
- **D17:** ❌ four criteria of five. The agent pass reached a correct report in six turns
  or fewer on 3 of 8 repositories: five of eight answers named every expected finding,
  and the three misses each describe a finding without the literal the scorer demands, a
  path or a rule ID. The ledger stands at $22.51 of D19's $25; the $2.49 left pays for
  less than a run, so by D19's fallback no further scoring runs in this build (§8).
- **Addendum, the owner's decisions applied** (`docs/acceptance/r7.md`): with the rule
  that a report names the rule ID and the path, the three repositories that missed name
  every expected finding. D17's agent criterion: 5 of 8 in six turns or fewer, every
  answer complete; still ❌ on turns (repositories 3, 4 and 8: 8, 9 and 7). The SBOM is
  opt-in. The ledger closes at $24.60 of $25.

### Phase R8: the image as a pipeline step

The first commit records R7's rehearsal.

- [x] **R8.1** **The image scans on its own** (D15; F1.10). `valvur scan` runs inside the
  image on a mounted or cloned checkout, needing no socket. Behaviours:
  1. e2e: `docker run` of the image on a checkout writes the Results Folder to a mounted
     output directory.
  2. No cloud-specific code path exists: F1.10's test still holds.
  **STATUS 2026-09-28:** ✅ both. The image sets `VALVUR_IN_IMAGE` and carries a `valvur`
  command; inside it `for_scan()` is `ImageRuntime`, the Scan Container's engine run as a
  process with the job's cache at `/cache`, Trivy's database fetched by the image's own
  Trivy. `scan --out DIR` writes `.security-scan/` under DIR for a read-only checkout, and
  `gate`, `findings` and `status` read DIR. With no `git` in the image a checkout is walked
  and history is not read, each said. `run.json`'s `network.boundary` names the job's
  container and whether it had a network, and on `offline` with one the Summary says that
  `--network=none` makes the guarantee structural; `doctor` in the image needs no runtime.
  `tests/test_image_scans_alone.py`'s e2e test runs the image with `--network=none` on a
  read-only checkout: the planted secret, a CVE in `requirements.txt` and a non-empty SBOM
  come back in `/out`, and the checkout is untouched. Measured on acceptance repository 2
  (`docs/acceptance/r8.md`): the host's 96 findings, two notes and 16 SBOM components, in
  17.2 s. The first run found three defects, fixed: reports named the engine's temporary
  workspace, Syft's `dir:/workspace` went unmapped, and down tunnel devices read as a
  network. F1.10's test passes unchanged: nothing added names a cloud.
- [x] **R8.2** **A GitHub Actions container job**: a workflow example and a CI test that runs
  it. A GitLab snippet goes in the docs.
  **STATUS 2026-09-28:** ✅ `docs/examples/github-actions.yml`: a job on the runner whose
  steps `docker run` the image, fetching with a network, scanning with `--network=none`
  into a mounted directory, and gating. Not a `container:` job: GitHub's JavaScript
  actions, `actions/checkout` among them, do not run in an Alpine job container, and the
  image has no `git`. `tests/test_pipeline_example.py` runs its three `run:` blocks
  against the image built from the tree, in CI's e2e job: 40.6 s here from an empty
  cache, complete. It found a defect, fixed: OSV's databases were fetched only by a
  scan, so a scan with no network failed OSV-Scanner and the gate; `valvur update PATH`
  now fetches them for PATH's lockfiles. `docs/examples/gitlab-ci.yml` is the GitLab
  job, the image as its container, a documented shape not run here. A test holds both
  examples to the version's image tag.
- [x] **R8.3** **A mirror in the customer's own registry.** Behaviours:
  1. A CI test mirrors the image, the database and the index into a local OCI registry,
     standing in for ECR.
  2. A scan with the mirror settings completes with `left this machine: nothing`.
  3. `AIR-GAPPED.md` gains the ECR steps.
  **STATUS 2026-09-28:** ✅ all three. `tests/test_customer_mirror.py`, in the e2e suite:
  a pinned `registry:2` on an `--internal` network holds the image, the database and the
  index; KEV and OSV's PyPI database are files on a server beside it; the image run there
  with the mirror settings updates and scans, complete and `clean`, `what_left_the_machine:
  nothing`, nothing fetched during the scan, and nothing left behind. 68 s on this Mac. The
  image is pushed from `docker save`'s OCI layout and verified by digest, since Docker
  Desktop's daemon cannot reach a registry on the Mac's loopback; on Linux it is pulled
  back and scanned from. `AIR-GAPPED.md` gains the ECR steps, a documented shape: valvur
  fetches the index, KEV and OSV anonymously, so in ECR those are files served inside the
  account. The measured AWS run stays the owner's (§8).
- [x] **R8.4** **The build's summary**, written as this task's STATUS: what shipped, the
  acceptance numbers against R2's baseline, the cost of agent scoring, and what §8 holds.
  **STATUS 2026-09-28, the build's summary.** Nine phases in two days, unattended, each
  closed by a phase commit and a PR stacked on the last.

  *What shipped.* Four releases prepared, each waiting for the owner's tag:
  - `0.6.0` (R1): the safety fixes for `0.5.0`'s users, on `main`, rehearsed.
  - `0.7.0` (R3): the rebuilt engine. One Scan Container fed a Snapshot of the files git
    would publish, the source never mounted, secrets read from history, one deadline and
    one kill, and nothing outliving its owner (ADR-0021, ADR-0022).
  - `1.0.0` (R4 to R7), with its stability claim:
    - the Scanner set by measured rule: zizmor, Checkov only where there is
      infrastructure, OSV-Scanner offline for its `MAL-` data (ADR-0023);
    - the report: groups, a summary that leads with what matters, local agent
      configuration that would leak, hygiene, and 41 borrowed injection patterns;
    - the agent surface: `scan` returns the result, reply schema 2, one `findings`
      tool, fresh data without a terminal, two settings files, `init` and a schema;
    - the documents as built, every README number from the acceptance set.
  - `1.1.0` (R8): the image as a pipeline step, examples run on every commit, and a
    mirror in the customer's own registry measured on every commit.

  *The acceptance set against R2's baseline* (`docs/acceptance/r2.md` to `r8.md`):

  | | R2, Mac | now, Mac (R8) | R2, Linux | now, Linux (R7) |
  |---|---|---|---|---|
  | repository 1, the gate's shape | 166.2 s | 7.5 s | 105.4 s | 8.1 s |
  | the other application repositories | 5.3 to 10.6 s | 5.7 to 17.8 s | 2.7 to 6.6 s | 3.8 to 18.4 s |
  | repository 5, Checkov on Terraform | 67.9 s | 61.0 s | 76.3 s | 114.2 s |
  | expectations pending | 5, on four repositories | 0 | 5 | 0 |
  | containers after the kill probe | 2 | 0 | 5 | 0 |

  Repository 1 is 22 times faster on the Mac and 13 on Linux, because the File Set never
  reads its 100,000 ignored files. The other repositories are slower where OSV-Scanner
  loads npm's database, about ten seconds a scan, for the `MAL-` data it alone carries;
  R4's speed exit missed by that and is in the queue below. The probes take longer
  because each now waits until the runtime confirms the containers gone.

  *Agent scoring* cost $22.51 of D19's $25: R2's baseline $7.15, R6.1's spike $0.95, R6's
  two runs and two traced runs $9.94, R7's run $4.47. A correct report in six turns or
  fewer: 0 of 8 at R2 (7 to 17 turns), 4 of 8 at R6, 3 of 8 at R7 (3 to 9 turns). Every
  miss since R6 is an answer that describes a finding without the path or rule ID the
  scorer wants; that choice is the owner's.

  *What §8 holds:* landing R2 to R8 in order; the four tags, each after its rehearsal
  on the landed commit; four decisions (the agent criterion, R4's speed exit, D9 and
  the SBOM, `init --write`); the gate with a person; Kiro's GUI pass; the measured AWS
  run; a second maintainer; the runner move after 2026-11-19; and memory on the build
  Mac. The build's schedules are deleted; nothing resumes it.

**Exit:** the pipeline-step and mirror e2e tests green, and both schedules deleted.

**Exit STATUS 2026-09-28** (`docs/acceptance/r8.md`):
- **The pipeline-step and mirror e2e tests green:** ✅ on the Mac, in the e2e suite's 54
  passed; Linux is R8's PR, whose e2e job runs the same three tests.
- **Both schedules deleted:** ✅ the in-session hourly resume and the durable
  `valvur-build-resume` task, at this commit's close.
- The acceptance set on the Mac: every repository passes with nothing pending, zero
  containers after all four probes.

---

## 8. The owner queue

Nothing here blocks the build. The executor adds a row when an item becomes ready.

| item | ready after | what the owner does |
|---|---|---|
| `v0.6.0` | **ready 2026-09-27**: R1 landed at `bbf77ef`; rehearsal 36353560849 green through validation on both architectures in 13 minutes, cancelled at the brake | sign and push the tag `v0.6.0` on `bbf77ef`; approve the real run at the brake |
| land R2, PR #145 | **ready 2026-09-28**: every check green on `d04e72f`, the Linux acceptance run included | fast-forward `main`: `git push origin refs/remotes/origin/build/r2-the-acceptance-set:refs/heads/main`. The build's own push to `main` was refused by the session's permission classifier on 2026-09-28 00:40; R3 continues on a branch rebased onto R2 and lands after it |
| `v0.7.0` | R3 lands (after R2's PR #145), then its rehearsal | sign and push the tag `v0.7.0` on the rehearsed commit, after `v0.6.0`; approve the real run at the brake |
| `v1.1.0` | R8 lands, then its rehearsal | sign and push the tag `v1.1.0` on the rehearsed commit, after `v1.0.0`; approve the real run at the brake. The pipeline step and the examples need it: `1.0.0`'s image predates them |
| `v1.0.0` | R7 lands, then its rehearsal | sign and push the tag `v1.0.0` on the rehearsed commit, after `v0.7.0`; approve the real run at the brake. D17's agent criterion is the one unmet (the row below) |
| the gate with a person (12b.3, 10.1) | `1.0.0` | find someone outside the repository; they follow the README on a project of their own, by `docs/history/usability-gate.md` |
| Kiro's GUI pass | R6 | one scan through Kiro, recorded in `docs/acceptance/` |
| a self-hosted Mac runner, optional | R2 | register one with the label `docker-desktop` |
| a second maintainer (28.1.3) | any time | `MAINTAINERS.md`'s five steps |
| the runner move (28.3.8) | after 2026-11-19 | ask any session to move the pinned runner images and land it |
| AWS measured runs: ECR mirror and CodeBuild (F1.10) | **ready**: R8 closed; the ECR steps are in `AIR-GAPPED.md`, the pipeline step in `docs/examples/` | run once in an AWS account and record the numbers |
| ~~`init --write`~~ **decided 2026-09-28: yes** | R6 | the owner approved `init` writing files into the project (CLAUDE.md §10); built in R8, `init --write`, an addition in `1.1.0`: never overwrites (`tests/test_init_write.py`) |
| free memory and disk on the build Mac | now | quit Chrome or restart the Mac: host swap was 14.05 of 14.34 GB and the Docker VM almost entirely paged out (R0.2); optionally `docker builder prune` to reclaim 21 GB of build cache the build will not touch itself |
| ~~stop: Docker Desktop is not running~~ **resolved 21:41** | 2026-09-27 21:38 | it was quit from its menu at 21:33:48, midway through R0.6's e2e run; the owner started it again at 21:41 and the build resumed |
| ~~pre-approve the durable resume task~~ **moot 2026-09-28** | R0 | the build finished and its schedules are deleted |
| land R3, PR #146, then R4, PR #148 | R2 lands | the same fast-forward, one branch at a time, in order. Not a squash or a rebase merge: repository 6 of the acceptance set is pinned to R4's commit `eb3a199` and needs that hash on `main` |
| ~~R4's speed exit, missed~~ **decided 2026-09-28: accepted** | R4's exit | the fastest application-repository scan on Linux stays 63% of R2's baseline, not half; no task follows |
| land R5, PR #149 | R4 lands; **every check green on `7b4e6a6`** | the same fast-forward, after #148 |
| land R6, PR #150 | R5 lands | the same fast-forward, after #149 |
| ~~R6's agent exit, and D17's agent criterion, missed~~ **decided 2026-09-28: a correct report names the rule ID and the path** | R6's and R7's exits | the scorer stands. The MCP handshake and `SUMMARY.md` now tell the agent so; re-run on the three that missed, every answer names every expected finding, and 5 of 8 fit six turns (`docs/acceptance/r7.md`). Agent scoring ended at $24.60 of $25 |
| land R7, PR #151 | R6 lands; its checks rerun on `f1016e2`, the owner's decisions applied | the same fast-forward, after #150 |
| land R8, PR #152 | R7 lands | the same fast-forward, after #151 |
| the MCP tools `list_findings` and `explain_finding` | R6 (removed) | removed at R6's exit, not kept a release: each cost an agent a deferred-tool load. A client that allowed them by name needs `findings` instead; the CHANGELOG says so |
| ~~D9 and the SBOM~~ **decided 2026-09-28: the SBOM is opt-in** | R4.4 | Syft runs, and the dependency licence policy (F4.4 to F4.6) with it, when a scan asks: `--sbom`, or `sbom = true` under `[scan]`. In `1.0.0`, whose Results Folder contract says so |
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
