# The self-healing supply chain: tasks

**Written 2026-10-21, after the nightly `acceptance` run failed on 2026-10-20 and
2026-10-21 (#234).** The owner asked how the build could check and update itself when this
happens, without them in the loop and without another incident like it. This spec is the
answer: [requirements.md](requirements.md) says what, and [design.md](design.md) says how,
including the decisions D81a to D81v with their fallbacks.

**Amended 2026-10-24,** while 1.5.4 was prepared. The owner's goal is updates that are "fully
automated and headless", without babysitting. Four things found that day would still need
the owner, or fail in silence. Each is a requirement, a D81 row and its tasks:
- a watchdog over the scheduled workflows (Requirement 15, D81s, R42.5);
- a gate on the image that ships, not only the tree (Requirement 16, D81t, R43.4);
- a heal for a base image whose tag has stopped moving (Requirement 17, D81u, R44.9);
- Scanner upgrades that prepare themselves (Requirement 18, D81v, Phase R47).

**Approved in halves** (the owner, 2026-10-24): R42 and R43 now, R44 onward after a decision
of the owner's, as §0's item 7 says. R42.1 records the date and the half.

**IDs.** Phases R42 to R47 continue [the main list](../valvur/tasks.md). Tasks are
`R<phase>.<n>`, in the main list's format, so `scripts/build_status.py` can read them once
R42.1 has taught it to. Each task names the criteria it builds, as `_Requirements:_`.

**Contents:** 0 starting the build · 1 order · 2 the phases · 3 the owner queue · 4 what this
does not change

---

## 0. Starting the build

**The start prompt, verbatim:**

> Build the spec in .kiro/specs/self-healing-supply-chain/ in /Users/maverick/security-scanner.
> Read CLAUDE.md, then that spec's tasks.md §0, and work unattended as
> .kiro/specs/valvur/tasks.md §1 to §4 say, starting at R42.1 on a branch cut from
> origin/spec/self-healing-supply-chain.

**The main list's §1 to §4 apply unchanged:** one executor, test-driven slices, phase commits,
phases stacked, never a push to `main` or of a tag, the stop conditions, and the build caches.
Seven things differ:

1. **Until R42.1 is ticked,** `build_status.py` reads only the main list and would report the
   build finished. Resume with the start prompt above. After R42.1, the main list's resume
   prompt finds this spec by itself.
2. **Branches.** `origin/spec/self-healing-supply-chain` holds this spec. It sits on
   `2d000ce`, the first commit of `chore/before-1.5.4`: #227's commit, carried by cherry-pick,
   because #227 no longer fast-forwarded and auto mode refuses a force-push.
   `release/1.5.4` carries that commit to `main`, so once 1.5.4 lands, the spec's base is in
   `main` and R42's pull request fast-forwards. Cut R42's branch,
   `build/r42-the-incident-closed`, from `origin/spec/self-healing-supply-chain`, so the spec
   lands with R42's pull request. Later phases stack as the main list's §4 says. The local
   branch of that name on `3d502c4` on the owner's Mac is the first draft; it was never
   pushed.
3. **R42.2 did not stack.** The lock fix closed a live incident, so it was a pull request of
   its own: #235, from `fix/checkov-lock-aiohttp-certifi-signed`, landed on `main` as
   `1cc920a` and `af7f82c` on 2026-10-24.
4. **Tasks marked 👤 run in the owner's session.** In R28.2 the executor's auto mode refused to
   write an auto-merge workflow, as a merge without review, and the owner built it. The 👤
   tasks write workflows that grant merge, tag or promote power. For each one, the executor:
   1. writes and tests every script the workflow calls;
   2. attempts the workflow itself;
   3. if auto mode refuses, never routes around it. It writes the workflow's design into the
      task's STATUS, adds a §3 row, and goes on with the next task that does not depend on
      it.
5. **Owner settings gate the live steps, never the tests.** The App, the environments and the
   tag key are §3's. Every test fakes the network, so nothing waits for them except the live
   proofs (R44.8, R45.5).
6. **No agent runs.** No `claude -p` here, so there is no cost cap to keep.
7. **Approved in halves** (the owner, 2026-10-24).
   - **Now:** R42 and R43, with the watchdog (R42.5) and the image gate (R43.4). Neither
     grants any power to merge, tag or release.
   - **Later:** R44 onward, with the base-image heal (R44.9) and Phase R47. R44 and R45 give
     an App standing power to merge, tag and release on a security tool's repository. Every
     security re-lock of October 2026 (10-02, 10-08, 10-21, 10-23) came from Checkov's tree
     of 97 packages, and valvur itself has no runtime dependency. So the owner first weighs
     R44 and R45 against fewer packages: Checkov's tree shrunk, or Checkov replaced, which
     ADR-0019's reopening would decide. Any D81 row that changes is changed before R44
     starts.
   - **The executor stops after R43's phase commit,** as the main list's §1 stops after R39.
     It says in §3's decision row that the row is ready. The second half starts with the
     prompt above once the owner has decided.

**Signed commits.** The executor signs its commits with the owner's SSH key on this Mac
(`commit.gpgsign`), or in a cloud session as D61 (g) says. `698b21e` was made unsigned in a
scratch clone; R42.2 carried it as a signed cherry-pick.

---

## 1. Order

```
R42 the incident closed, one writer for the lock ─► R43 the nightly judges valvur
                                                          │
R46 time to heal, the documents ◄── R45 security patches release ◄── R44 the lock heals itself
   │
   └─► R47 Scanner upgrades prepare themselves
```

- **R42 first:** it closes #234's cause and stops the two Dependabot updaters writing a lock
  that the heal will own.
- **R43 before R44:** the heal plans from `advisory_published` (R43.1), and the healing window
  (R43.3) is what makes a heal in progress green rather than an incident.
- **R44 before R45:** a release needs a healed `main`.
- **R45 needs three owner settings** (§3), so the work that needs none comes first.
- **R46 after R45:** it measures and documents what exists.
- **R47 last:** a Scanner upgrade lands as the App, under R44's policy, so it needs R44 and
  R45 built. The watchdog (R42.5) and the image check (R43.4) grant no power to merge, tag or
  release, so they sit in the first two phases.

---

## 2. The phases

### Phase R42: the incident closed, and one writer for the Checkov lock

- [x] **R42.1** **This spec on the build's rails** (D81). Behaviours:
  1. `build_status.position` reads the main list, then each other `.kiro/specs/*/tasks.md` in
     name order, and returns this spec's first unchecked task when the main list has none.
     A spec missing on a ref reads as an empty list, not an error.
  2. `shape_errors` checks each list.
  3. `acceptance.ticked` reads every spec's list, so an `until` naming a task here resolves.
  4. The main `tasks.md` gains:
     - an amendment paragraph in its header: approved in halves on 2026-10-24, at the owner's
       word, R42 and R43 first (§0, item 7), with Phases R42 to R47 here;
     - D81's row in §5, pointing to design.md;
     - R42 to R47 in §6;
     - a §8 row pointing to §3 here.

     `CLAUDE.md` §9's *Spec-driven* line names `.kiro/specs/*/`.

  _Requirements: 14.1, 14.2, 14.3_

  **STATUS 2026-10-24:** ✅ 1 to 4, in a cloud session (D61).
  - `build_status.position` takes the lists in order, and `task_lists(repo, ref)` reads the main
    list, then every other `.kiro/specs/*/tasks.md` on the ref by name; a spec the ref does not
    hold is not read, so `origin/main` reads as today until R42 lands.
  - The live lists both pass `shape_errors`; `acceptance.task_list` reads every spec's list
    before the archives, so `ticked` resolves an `until` naming R42 to R47.
  - The main list gained the amendment paragraph (approved in halves on 2026-10-24, R42 and R43
    first), D81's row, R42 to R47 in §6 and §8's row pointing to §3 here. `CLAUDE.md` §9 names
    `.kiro/specs/*/`, at 199 lines. Requirement 14 is defined as N3.6.

- [x] **R42.2** **The lock fix lands** (#234). Behaviours:
  1. `fix/checkov-lock-aiohttp-certifi` (`698b21e`) is signed again on `origin/main`, by a
     cherry-pick onto a new branch (auto mode refuses `git commit --amend`), pushed, and
     opened as its own pull request. The body has these sections:
     - the advisory table in requirements.md;
     - the change;
     - why Dependabot did not fix it;
     - the verification below;
     - the follow-up (behaviour 3);
     - `Refs #234`.
  2. Its required checks pass.
  3. §3: the owner lands it and releases 1.5.4. If 1.5.4 is published before R43.2 lands, a
     one-line pull request moves `SELF_PIN` to v1.5.4's commit, under its comment's own rule,
     so that #234 closes on the next nightly.

  **STATUS 2026-10-21, measured in the owner's session before this spec was written:**
  - **The re-lock.** The recipe's flags plus `--upgrade-package aiohttp --upgrade-package
    certifi` moved aiohttp 3.14.3 to 3.14.5 and certifi 2026.7.22 to 2026.10.19. yarl moved
    from 1.24.5 to 1.25.1, because every fixed aiohttp requires `yarl>=1.25.1`. Nothing else
    moved, and the asteval override held.
  - **`check_package`:** all four versions exist and none is flagged, against the index of
    2026-10-21.
  - **The acceptance set:** `scripts/acceptance.py --generate --only 6` with `SELF_PIN` at
    `d0417c4` fails with the same four Findings. With `SELF_PIN` at the fix commit it passes,
    with 0 blocking.
  - **The suites:** 2,343 passed and 8 skipped, after the image guard was re-run against
    `valvur:dev`. `-m e2e` against `valvur:dev`: 70 passed, 6 skipped.

  **STATUS 2026-10-23/24:** ✅ behaviours 1 and 2. Behaviour 3 waits for 1.5.4.
  - **Signed by cherry-pick, not amended.** Auto mode refused `git commit --amend` as
    destructive. `698b21e` was cherry-picked onto `origin/main` on a new branch,
    `fix/checkov-lock-aiohttp-certifi-signed`, which signs a new commit and rewrites nothing.
    It opened as #235.
  - **GitPython, found by the pull request's own gate.** #235's self-scan release gate
    (N2.5) found CVE-2026-114145 (GHSA-83vg-56qc-22m7, high), published 2026-10-22 at 16:41
    UTC, against GitPython 3.1.62. A second commit, `af7f82c`, moved it to 3.2.1, which
    Checkov 3.3.22 accepts (any GitPython below 4); nothing else in the lock moved. On
    2026-10-23, after `valvur update` and a forced database refresh, the `offline` profile
    still did not know the advisory. Only `--profile full` (OSV.dev) found it, which is what
    CI's gate runs (design.md §4).
  - **Landed** on 2026-10-24 at 06:36:40 UTC, by fast-forward, as `1cc920a` and `af7f82c`.
    `ci` passed on `main` (run 40070884696), and Dependabot's alerts #5 to #12 closed when
    GitHub re-read the lock.
  - **Behaviour 3:** 1.5.4 is prepared on `release/1.5.4`. The `SELF_PIN` move ships in
    `docs/1.5.4-published`, after 1.5.4 is published.
  - **Behaviour 3, 2026-10-25:** after 1.5.4 was published at `5c8a7a4`, `SELF_PIN` moved to
    that commit in `main`'s `c298b6d` (#245, `docs/1.5.4-published`), and `acceptance` on `main`
    passed 8 of 8 (run 40183393214); #234 closed. R42's pull request had carried the same move
    while #245 was unpushed; on the rebase it gave way to `main`'s. R43.2 then removes the pin.
  - **Ticked 2026-10-24 with behaviour 3 recorded as waiting**, as R21.3's smoke run was
    (D61h), so that `build_status.py` does not send every resuming session back to it: the
    release is the owner's (§3), and R43.2 removes `SELF_PIN` in any case.

  _Requirements: none here. It closes the incident the requirements answer._

- [x] **R42.3** **Dependabot stays out of the Checkov lock** (D81p). Behaviours:
  1. `.github/dependabot.yml`'s `pip` and `uv` entries carry `exclude-paths` naming
     `requirements-checkov.in`, `.overrides` and `.txt`. A new test holds it, and the comment
     says why: #231 and #236 came from `uv`, #232 and #237 from `pip`.
  2. `scripts/dependabot_auto_merge.py` leaves for the owner any pull request that changes
     `requirements-checkov.*`, naming why. Its existing twenty-one tests still pass.
  3. **The live check:** Dependabot's next weekly run opens no pull request that touches those
     files, recorded with its date. If it does, D81p's fallback applies: the files move to
     `locks/checkov/` as a new task, the next free ID in R42, with the Dockerfile,
     `prepare_release.py`'s `MACHINERY`, the tests and the documents moving with them.

  **The baseline, 2026-10-24:** without `exclude-paths`, Dependabot rebuilt the lock's pull
  requests within minutes of `main` moving. #235 landed at 06:36 UTC; at 06:39 Dependabot
  closed #231 and #232 itself and opened #236 (`uv`) and #237 (`pip`), the same re-lock
  (asteval 1.0.6, the `win32` markers dropped) with auto-merge on. Only their red checks
  held them. Both were closed with `@dependabot close` the same day.

  **STATUS 2026-10-24:** ✅ 1 and 2; 3 waits for R42 to land, since Dependabot reads its
  configuration from `main` alone.
  - `.github/dependabot.yml`'s `uv` and `pip` entries name the three files under
    `exclude-paths`, with the four pull requests in the comment. The `pip` entry is left with
    zizmor's lock, and its group is renamed from `checkov` to `zizmor`.
    `tests/test_checkov_lock_one_writer.py` holds both entries, line by line.
  - `scripts/dependabot_auto_merge.py` refuses a pull request that changes any of the three,
    naming the file and the recipe. Of its twenty-one tests, twenty pass unchanged. The first
    took #200's shape, the Checkov lock and its input, as its example of a pull request that
    may land itself, which is exactly what this task reverses, so it now uses zizmor's lock and
    `uv.lock`, and its docstring says why.
  - **Behaviour 3, waiting:** the first weekly Dependabot run after R42 lands, recorded here with
    its date. Requirement 4 is defined as N3.7.

  _Requirements: 4.1, 4.2_

- [x] **R42.4** **The lock is what its recipe writes**. Behaviours:
  1. **Measure first:**
     - Does `scripts/lock-checkov.sh` with `--no-build` reproduce today's lock byte for byte?
       This needs pypi.org, which `src/valvur/egress.py` names.
     - Which uv does CI's `setup-uv` install, read from a CI log, and where does it take a
       pinned version from?
  2. The recipe passes extra arguments through after its own and keeps `--no-build`. It is
     tested with small wheels built in `tmp_path`, through `--no-index --find-links`.
  3. The uv version is pinned in the one place both `setup-uv` and the Mac read. A test holds
     every `setup-uv` step to it.
  4. `.github/workflows/lock.yml` runs on `pull_request` for the recipe's paths: the recipe,
     then `git diff --exit-code requirements-checkov.txt`. It has `permissions: {}` with the
     job's `contents: read` and pinned actions, and zizmor finds nothing. A test holds its
     shape.
  5. **Proof:** the check is green on R42's pull request. Run locally, its command fails on a
     copy of the tree whose lock pins asteval 1.0.6, and on one whose markers were stripped.

  _Requirements: 4.3, 4.4, 4.5, 4.6_

  **STATUS 2026-10-24:** ✅ 1 to 5, the pull request's half of 5 recorded at R42's exit.
  - **Measured, `--no-build`:** the recipe with `--no-build` rewrites today's lock byte for
    byte, under uv 0.11.32 (this VM's) and under uv 0.13.5. With no lock to prefer, 0.13.5
    moves beartype, certifi, charset-normalizer and more, so the existing lock as uv's
    preference is what keeps a re-lock to the packages named.
  - **Measured, CI's uv:** `astral-sh/setup-uv` v10.2.0 looks for a version in `uv.toml`, then
    `pyproject.toml`, and finding none installs the latest: 0.13.5, in `ci`'s run 40070884696
    on `main` that morning. `pyproject.toml` now names `[tool.uv] required-version = "==0.13.5"`,
    which uv itself enforces on the Mac and in a session, and which every one of the 17
    `setup-uv` steps reads from its checkout; a test holds that none names a version of its own.
    The Mac needs uv 0.13.5 (`uv self update 0.13.5`) from this commit on.
  - **The recipe** prints `uv --version`, adds `--no-build`, and passes `"$@"` after its own
    arguments. `tests/test_checkov_lock_recipe.py` builds wheels in `tmp_path` and resolves
    through `--no-index --find-links`: a constraint reaches uv, the existing lock is kept until
    `--upgrade-package` names a package, and an sdist-only package is refused by name.
  - **`.github/workflows/lock.yml`:** `pull_request` on the recipe's paths, `permissions: {}`,
    the job's `contents: read`, pinned actions, one run per pull request; zizmor at the auditor
    persona finds nothing (it first asked for the concurrency group).
  - **Proof, locally:** the check's command exits 1 on a copy whose lock pins asteval 1.0.6,
    and on one whose `win32` markers were stripped; on the unchanged lock it exits 0.

- [x] **R42.5** **A watchdog over the scheduled workflows** (D81s, amendment 1). Behaviours:
  1. **Measure first:** every workflow with a `schedule:`, its crons and its longest gap
     between two cron times. For each, the start delay of its last 30 scheduled runs, from
     `run_started_at` against the cron time, read from the Actions API. (The nightly has
     been starting about 5 hours after its 03:37 UTC cron.) The STATUS records the table and
     the margin D81s gives.
  2. `scripts/watchdog.py`, against the Actions API and issues faked in the tests:
     - a last scheduled run that failed, with no open issue, gives one issue to open;
     - one that failed with its issue open gives a comment, never a second issue;
     - no scheduled run within the gap plus the margin gives an `overdue` issue;
     - a pass closes the open issue, naming the run;
     - a workflow without `schedule:` is never read.
  3. **The incident replayed:** `refresh.yml`'s runs of 2026-10-12 and 2026-10-19, from
     their recorded API answers, are failures that filed no issue. Kept as a regression test.
  4. `.github/workflows/watchdog.yml`: daily at 06:47 UTC, with a checkout that always runs,
     `permissions: {}` and the job's `actions: read` and `issues: write`, pinned actions and
     no expression inside `run:`. zizmor finds nothing, and a test holds its shape.
     `tests/test_ci_builds_once.py`'s test that every local action has a checkout that always
     runs (1.5.4) holds it too.
  5. `acceptance.yml` checks the watchdog's own last run by the same rule.
  6. **Proof:** a dispatch on the build branch with `dry_run=true` lists what it would file,
     and files nothing.

  _Requirements: 15.1 to 15.6_

  **STATUS 2026-10-24:** ✅ 1 to 6, behaviour 6 by a dry run against the live API, since GitHub
  dispatches only a workflow already on `main`.
  - **Measured,** from `GET /repos/MaverickHQ/valvur/actions/workflows/<file>/runs
    ?event=schedule&branch=main` (the API filters by event, so D81s's fallback is not needed):
    start delay is `run_started_at` against the cron time before it.

    | workflow | cron (UTC) | longest gap | scheduled runs read | median delay | longest delay |
    |---|---|---|---|---|---|
    | `acceptance.yml` | `37 3 * * *` | 24 h | 25 | 6.4 h | 7.7 h |
    | `fuzz.yml` | `29 3 * * *` | 24 h | 20 | 5.7 h | 7.7 h |
    | `index.yml` | `23 3 * * *` | 24 h | 30 | 6.4 h | 7.7 h |
    | `corpus.yml` | `17 6 * * 1` | 168 h | 6 | 7.5 h | **9.0 h** |
    | `eval.yml` | `47 4 * * 1` | 168 h | 3 | 7.1 h | 7.7 h |
    | `refresh.yml` | `23 5 * * 1` | 168 h | 3 | 7.0 h | 7.9 h |
    | `retention.yml` | `17 4 * * 1` | 168 h | 4 | 7.1 h | 7.6 h |
    | `scorecard.yml` | `23 5 * * 2` | 168 h | 3 | 6.7 h | 7.4 h |
    | `mutation.yml` | `41 5 * * 3` | 168 h | 2 | 4.9 h | 4.9 h |

    D81s's margin is twice the longest, 18 hours (over its floor of 12): `MARGIN_HOURS`.
  - **`scripts/watchdog.py`**, standard library only, reads the crons line by line and the
    runs and issues through the REST API (`GITHUB_API_URL`, `GH_TOKEN`). Its 19 tests run it
    against GitHub's API on loopback (`tests/fake_github.py`): a failure opens one issue,
    `watchdog: <file>`, naming the run and its date; a second comments; a daily cron is overdue
    after 42 hours and not at 41.98; a pass closes the issue naming the run; a pass with no issue
    writes nothing; a workflow without `schedule:` is never read; a 404 means never run.
  - **The design said each finding goes through `file-issue`.** One composite call per title
    cannot loop over a list the script finds, so the script keeps the issues itself, by
    `file-issue`'s rule (one open issue per exact title, a comment after, a close naming the
    run).
  - **The incident replayed:** `refresh.yml`'s scheduled runs as the API answered on 2026-10-24
    (`tests/fixtures/watchdog/refresh-runs-2026-10-24.json`), seen at 2026-10-12 15:00 and
    2026-10-19 12:00, each open the issue nobody filed, naming runs 38254221059 and 39240320485.
  - **`watchdog.yml`:** daily at 06:47 UTC, `workflow_dispatch` with `dry_run`, `permissions: {}`
    and the job's `actions: read` and `issues: write`, its checkout first with no `if`, pinned
    actions, nothing spliced into `run:`. Its own failure files `watchdog: watchdog.yml` through
    `file-issue`, which the constraint suite asks of every scheduled workflow
    (`test_a_scheduled_workflows_failure_becomes_an_issue`, restated: its set gains
    `watchdog.yml`, and `permissions: {}` counts as no more than read), and a pass closes it,
    as `test_issues_close_themselves.py` asks. zizmor's two findings, at either persona, are a
    low `self-repository` on each of those steps, which it reports on every workflow that calls
    a local action (`acceptance.yml` had three before this task). `docs/MAINTENANCE.md`'s
    routine names the workflow, as its test asks. The 1.5.4 test of every local action's
    checkout is not on this branch yet; this checkout is the first step, with no `if`.
  - **The nightly watches the watchdog:** `acceptance.yml` gains a job, `--only watchdog.yml`,
    with the same two grants, `--dry-run` on a pull request, and its own failure filed and closed. zizmor's
    low findings on the file rise from three to five, both that same `self-repository`.
  - **Proof, a dry run against the live API** (`GH_TOKEN` of the session, 2026-10-24 ~20:00 UTC):
    `would open: watchdog: acceptance.yml` (red since 2026-10-20, #234), `would open: watchdog:
    refresh.yml` (its failure of 2026-10-19), `would open: watchdog: watchdog.yml` (never run),
    and nothing filed. On the day R42 lands, the nightly may open `watchdog: watchdog.yml` before
    the watchdog's first run; that run's pass closes it the next night. Requirement 15 is N3.8.

### Phase R43: the nightly judges valvur, not the calendar

- [x] **R43.1** **An advisory's publication date on its Finding** (D81o). Behaviours:
  1. Trivy's adapter carries `PublishedDate` as `Dependency.advisory_published`, normalised to
     `YYYY-MM-DDTHH:MM:SSZ`, from a fixture that has the field. Recapture one if none does,
     as `docs/MAINTENANCE.md` describes.
  2. OSV-Scanner's adapter carries `published`.
  3. When both Scanners report a Finding, the earlier date is kept.
  4. An absent or unparseable date gives `""`.
  5. Every fixture Finding's Fingerprint is unchanged, compared before and after.
  6. `findings.json` carries the field. Measure whether the contract tests treat an addition as
     a `schema` bump, and record the answer.
  7. `-m e2e` against `valvur:dev`: a scan of the acceptance set's dependency repository
     carries dates.
  8. **The Score:** `scripts/eval.py --tracks <the tracks Trivy and OSV-Scanner reach>
     --compare`, with every track unchanged. The STATUS gives each delta. If a track moves,
     D81o's fallback applies.

  _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  **STATUS 2026-10-24:** ✅ 1 to 8, in a cloud session (D61).
  - **No recapture needed:** both golden fixtures carry the dates, `trivy-0.75.0.json`'s
    `PublishedDate` (with milliseconds, `2022-12-24T04:15:08.787Z`) and
    `osv-scanner-2.6.0.json`'s `published`.
  - `Dependency.advisory_published`, normalised by `findings.advisory_date` to
    `YYYY-MM-DDTHH:MM:SSZ` in UTC, `""` for an absent or unreadable date; the merge keeps the
    earlier of two (`_earlier_advisory`), so an advisory's age is never understated.
  - **Fingerprints, before and after:** the 40 Fingerprints of the broken fixture's Trivy and
    OSV-Scanner scan, measured before the field existed, are the same 40 with the dates and with
    every date stripped from both fixtures.
  - **The schema, measured:** the contract tests (`test_contract.py`, `test_findings_json_*`)
    pass unchanged and none treats an added field as a bump; `artifacts.py` already records
    `generation`, `groups` and `cwe` as additions to schema 1. So `findings.json` stays schema
    1, and the field is documented on `Dependency`, where the rest of the schema is, and as F5.11.
  - **e2e** against `valvur:dev` built from this branch by `scripts/cloud_image.py`
    (`tests/test_advisory_published_e2e.py`): a scan of the acceptance set's `2-lockfiles`
    gives every dependency vulnerability a date. 1 passed.
  - **The Score,** `--tracks dependencies,package-reality --compare`: dependencies 100.0 and
    package-reality 100.0, each Δ 0 against the baseline; D81o's fallback is not needed.

- [x] **R43.2** **`6-self` is the latest release** (D81c). Behaviours:
  1. Generation archives `git describe --tags --abbrev=0 --match 'v[0-9]*'`. It is tested on a
     temporary repository with two tags and a commit after the second.
  2. With no tag reachable, generation raises and names the cause.
  3. The report names the tag and its commit.
  4. `SELF_PIN` is gone, and a test refuses a forty-hex literal on `6-self`'s path.
  5. **Measured on this Mac:** `scripts/acceptance.py --generate --only 6`, its tag and its
     blocking count. Until 1.5.4 is published, the latest tag is v1.5.3, whose lock has the
     advisories 1.5.4 fixes: the four in requirements.md's table, GitPython's, and the five
     medium and low ones in aiohttp. They are past the window by then, so the high and
     critical ones block. Record that as it is.

  _Requirements: 1.1, 1.2, 1.3, 1.4_

  **STATUS 2026-10-24:** ✅ 1 to 5.
  - `self_at_release(root, repo=REPO)` replaces `self_at_pin`: `git describe --tags --abbrev=0
    --match 'v[0-9]*'`, then `git archive <tag>`, and `expected.toml`'s `[run]` gains `tag` and
    `commit`. With no tag it raises, naming the cause and the fix (a checkout needs
    `fetch-depth: 0`, which `acceptance.yml` has). Tested on a temporary repository with two
    release tags, a commit after the second and a non-release tag on it.
  - The report says `6-self scanned <tag> (<commit>)` under the table, and `report.json` gives
    `release: {tag, commit}`. `SELF_PIN` is gone, and a test refuses a forty-hex literal in
    `self_at_release`. Requirement 1 is N4.5.
  - **Measured on this VM**, `scripts/acceptance.py --generate --only 6`: `6-self scanned v1.5.3
    (1434c44)`, FAIL with 5 blocking, the high and critical ones in v1.5.3's lock that 1.5.4
    fixes: CVE-2026-111064, CVE-2026-111066 and GHSA-2g87-pp6c-29x5 (aiohttp),
    GHSA-6q48-6c7w-9gw2 (certifi, critical) and CVE-2026-114145 (GitPython). The six others
    are medium, low or unknown: CVE-2026-111065, -111748, -111750, -111749, -111063 and
    PYSEC-2026-4320. Recorded as it is: they are past the window, so R43.3 does not hide them.

- [x] **R43.3** **The healing window** (D81b). Behaviours, on Results Folders written by the
  test:
  1. In a repository with `healing_window_hours = 48`, a dependency vulnerability Finding whose
     advisory was published an hour before the Scan Run is `healing`, not blocking.
  2. One published 49 hours before blocks.
  3. One with no date blocks.
  4. A `MAL-` one blocks, however young.
  5. A young secret or static-analysis Finding blocks: the window is for dependency
     vulnerabilities alone.
  6. A repository without the key is judged as today.
  7. The report has a `healing` column, and `report.json` has the field.
  8. `6-self`'s `expected.toml` sets 48.

  _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

  **STATUS 2026-10-24:** ✅ 1 to 8, in `tests/test_acceptance_healing.py`, on Results Folders the
  test writes.
  - **Against when the scan started, not `run.json`.** design.md §1 measures the age against
    the Scan Run's start in `run.json`, which records no time (read from a real one: `kev_catalog`
    and `epss_scored` are dates of data, not of the run). Adding one would change a product
    artifact for the harness's sake, so `run_repo` reads the clock before it scans and passes
    it to `judge` as `scanned_at`, the clock by default.
  - Healing: a Finding with a `dependency` whose `advisory_published` reads, is under the window
    and not in the future, and whose rule and aliases name no `MAL-` entry and which is not
    `valvur.dependency.malicious`. An hour old is healing, 49 hours blocks, no date, `soon` or a
    date after the scan block, a secret and a static-analysis Finding block, and a repository
    without the key is judged as before.
  - The report's table gains a `healing` column, and `report.json` a `healing` list of
    "rule at path (severity), <n> h old". `6-self`'s `expected.toml` sets 48, and no other
    repository sets a window. Requirement 2 is N4.6.
  - On 2026-10-24, `6-self` at v1.5.3 would have nothing healing: its five blocking advisories
    were published from 2026-10-19 17:07 to 2026-10-22 16:41 UTC (`advisory_published` in
    R43.2's scan), and the youngest, GitPython's, was about 51 hours old at the scan.

- [x] **R43.4** **The image, scanned as it ships** (D81t, amendment 2). Behaviours:
  1. **Measure first, the positive control:** design.md §10's command against the published
     `ghcr.io/maverickhq/valvur:1.5.3` reports OpenSSL's fixes in 3.5.7 and 3.5.8, musl's
     CVE-2026-107891, xz's CVE-2026-34743, zlib's CVE-2026-85091, and CVE-2026-111943 in the
     Go binaries' standard library. If it misses one, D81t's fallback applies. The STATUS
     records each, and how long the check takes on each architecture. (On 2026-10-24 these
     were measured by hand, with an Alpine secdb comparison and a Go build-information
     reader, kept with the handover.)
  2. `scripts/image_gate.py`, on recorded Trivy output:
     - a vulnerability with a fixed version blocks;
     - one listed in `.github/image-accepted.yaml` with an expiry ahead does not;
     - an entry without an expiry, or past it, is refused, naming it;
     - one with no fixed version is reported and does not block;
     - input it cannot read exits 2.
  3. A test holds that nothing in the tree writes `.github/image-accepted.yaml`.
  4. A `ci.yml` job after "the image, built once", on both architectures, loads the run's
     image and runs the check with no network and the run's database. It is not a required
     check; §3 holds that choice for the owner.
     `tests/test_ci_builds_once.py`'s count of image builds is unchanged.
  5. `release.yml` runs it on the staged image before `promote`. The nightly runs it against
     the latest published image.
  6. Its JSON is uploaded as an artifact, which `observe` reads as its second input (R44.6).
  7. No document claims image scanning for users. A test reads the README and `docs/` for
     it, and the ROADMAP's *being considered* row stays.
  8. **Proof:** the job is green on R43's pull request, with the Alpine 3.24 base and every
     unfixed finding listed. Behaviour 1 is its red.

  **Exit:** the acceptance set on both lanes, with the `healing` column, and the image check
  green on the phase's pull request.

  _Requirements: 16.1 to 16.7_

  **STATUS 2026-10-24:** ✅ 1 to 7; 8, the pull request's run, recorded at R43's exit.
  - **The positive control, measured** on this VM against the published
    `ghcr.io/maverickhq/valvur:1.5.3`, with design.md §10's command plus `--cache-backend memory`
    (the database is mounted read-only, and Trivy otherwise writes its cache there) and
    `--skip-java-db-update`. 208 vulnerabilities, 203 with a fixed version. Every one of the
    five is there, so D81t's fallback is not needed:
    - OpenSSL: 25 CVEs, on `libssl3` and `libcrypto3` 3.5.6-r0, fixed in 3.5.7-r0 and 3.5.8-r0;
    - musl's CVE-2026-107891 (1.2.5-r12, fixed in 1.2.5-r13, `musl` and `musl-utils`);
    - xz's CVE-2026-34743 (`xz-libs` 5.8.1-r0, fixed in 5.8.3-r0);
    - zlib's CVE-2026-85091 (1.3.2-r0, fixed in 1.3.2-r1);
    - CVE-2026-111943 in the standard library of all four Go Scanners: gitleaks (Go 1.24.13),
      osv-scanner (1.27.0), syft (1.26.8) and trivy (1.27.1), fixed in 1.26.10 and 1.27.3.

    Its time here: 3.1 s on amd64, the first run. On #244's CI, the scan step took 0.89 s on amd64
    and 0.64 s on arm64.
  - **The image on Alpine 3.24** (#241's base, built here): 0.9 s, and no OS package blocks.
    131 still block, so the check will be red until the owner decides:
    - 125 are in the Go Scanners' binaries: their standard library and `golang.org/x/*`
      modules (52 high in all, gitleaks the most, at 69). That is R47's ground, or a Scanner
      release built with a newer Go.
    - 6 are in the base image's own `pip` 25.0.1 (CVE-2025-8869, CVE-2026-13346, -3219, -6357,
      -8643, -1703; medium and low).
    - 5 have no fix: ecdsa's CVE-2024-23342 and GO-2026-5932 in four binaries.
  - **`scripts/image_gate.py`**, standard library only, on Trivy's recorded answer
    (`tests/fixtures/image-gate/trivy-rootfs-1.5.3.json`, trimmed to the fields it reads):
    - a fixed version blocks, exit 1;
    - an entry in `.github/image-accepted.yaml` with an expiry ahead accepts;
    - one without an expiry, or past it, is refused by name and accepts nothing;
    - no fixed version is reported and passes;
    - an unreadable scan or accepted file exits 2;
    - `--out` writes `{blocking, accepted, unfixed, refused}`.

    The accepted file is a list under `accepted:` read line by line. It does not exist yet:
    §3's row is the owner's. A test holds that no script, source file or workflow writes it.
  - **Where it runs:**
    - `ci.yml`'s `imagegate`, "the image, scanned as it ships (amd64/arm64)", after "the
      image, built once". It loads that run's image, takes `valvur update`'s database and
      uploads `image-gate-<arch>`. It is not in `ci_verdict.REQUIRED`, and the image builds
      stay at three (`test_ci_builds_once.py`).
    - `release.yml`'s `artifact` job, both architectures, on the staged image by digest, before
      `promote`, which needs `artifact`. **A release after R43 lands stops there** until the
      Go Scanners move or the owner accepts their findings.
    - `acceptance.yml`'s `image` job, nightly against `ghcr.io/maverickhq/valvur:latest`, which
      files and closes its own issue.
  - **No document offers image scanning:** a test reads the README and `docs/*.md` for it, and
    holds the ROADMAP's *being considered* row. zizmor's only new findings are two low
    `self-repository` notes on `acceptance.yml`'s new `file-issue` steps.
  - **Behaviour 8, on #244's CI (head `9d25a7f`):** both legs ran and were red, as expected,
    with the same verdict: 192 blocking, 0 accepted, 5 with no fix. On this branch's Alpine 3.22
    base, 61 are OS packages, 125 are in the Go binaries and 6 are `pip`. The Alpine 3.24 base
    (#241) removes the 61. The green the task names waits for the Go Scanners' releases, or for
    the owner's entries in `.github/image-accepted.yaml` (§3).
  - `test_issues_close_themselves.py`'s step parser let a job-level `if:` leak into the step
    before it; a step now ends where the next job begins. Requirement 16 is N2.7.

  **The build's summary, 2026-10-24** (the first half, R42 and R43, in one cloud session under
  D61). Nine tasks ticked; R42.2's behaviour 3, R42.3's live check and R43.4's pull-request
  run are recorded as waiting.
  - **What changed:**
    - the build reads every spec's list (N3.6);
    - the Checkov lock has one writer, its recipe, checked by `lock.yml`, with uv pinned to
      0.13.5 (N3.7);
    - a watchdog keeps one issue per failed or overdue scheduled workflow (N3.8);
    - dependency Findings carry `advisory_published` (F5.11);
    - `6-self` is the latest release (N4.5), with a 48-hour healing window (N4.6);
    - the image is scanned as it ships (N2.7).
  - **Measured at each exit** (`docs/acceptance/r42.md`, `r43.md`): the Score 74.1, every track at
    its baseline; the acceptance set 7 of 8, `6-self` red on the advisories 1.5.4 fixes.
  - **Pull requests:** R42 is #242 and R43 is #244, stacked on it. Both land after 1.5.4. The
    base move they need for a green image gate is #241, carried into `release/1.5.4`.
  - **Left for the owner,** in §3:
    - the scope of R44 and R45, which is ready now;
    - the image's accepted findings, or Scanner releases built with a newer Go, before the next
      release from a `main` that holds R43;
    - making `lock.yml` and the image check required, both optional;
    - dispatching `eval.yml` on the R42 and R43 branches for the Linux Score lane;
    - the Mac lane (D61a): one run of the acceptance set and the Score over the landed stack,
      and `uv self update 0.13.5`.
  - **The executor stops here,** as §0's item 7 says. R44 onward waits for the owner.

### Phase R44: the Checkov lock heals itself

- [ ] **R44.1** **Measure first** (D81e, D81k). Behaviour: the STATUS records each of these:
  1. **Provenance:** for each package in the lock, whether its locked version's distributions
     carry a PyPI provenance attestation, and from which publisher. The same for aiohttp
     3.14.5, certifi 2026.10.19 and yarl 1.25.1. They are read from pypi.org's integrity API.
  2. **The recipe:** R42.4's answer on `--no-build`, and the uv it ran.
  3. **Replaying the incident:** on a copy of `1434c44`'s lock, `--upgrade-package` with a
     `--constraint` file of the three pins writes `698b21e`'s lock byte for byte.
  4. **Rulesets:** the repository's rulesets for tags and branches, from `gh api
     repos/MaverickHQ/valvur/rulesets`, and whether `v*` tags are restricted. This answers
     §3's row.

- [ ] **R44.2** **The plan** (D81d, D81e). Behaviours, against `tests/fake_registry.py`
  extended with PyPI's JSON and integrity endpoints, and with small wheels:
  1. One Finding with a fix past the cooldown: the newest fixing version past the cooldown, in
     the same major.
  2. A fix younger than the cooldown, at least 24 hours old, attested by the replaced
     version's publisher: `young-attested`.
  3. Under 24 hours old, unattested, or from a different publisher: escalated as
     `young-unattested`.
  4. No `fixed_version`: `no-fix`.
  5. Fixes only in the next major: `major`.
  6. A floor the resolution forces, such as yarl under aiohttp, is pinned by the same rule.
  7. A package added by the resolution gives `new-package`. Checkov moving gives `checkov`.
  8. A moved version that `valvur check` flags gives `check-failed`. This runs the real CLI
     against a small Name Index and malicious list in a temporary `VALVUR_CACHE`.
  9. Several Findings on one package: the highest `fixed_version` is the floor.
  10. No Findings: an empty plan, and nothing else written.
  11. **The incident replayed:** 2026-10-21's Findings, with PyPI faked at the real upload
      times, give aiohttp 3.14.5 and yarl 1.25.1 by cooldown. certifi 2026.10.19 is
      `young-attested` or escalated, as R44.1 found. It is kept as a regression test.

  _Requirements: 5.1 to 5.8, 6.1, 6.2, 6.3_

- [ ] **R44.3** **The proposal**. Behaviours:
  1. `heal.py apply` runs the recipe with the plan's pins and refuses a result where an
     unplanned package moved.
  2. It adds one `### Security` item per package under `[Unreleased]`.
  3. The commit message and its trailers, as design.md's data model gives them.
  4. `heal.py verify` accepts a correct artifact. It refuses a third file, an unplanned move,
     and a lock it cannot parse.
  5. `scripts/signed_push.py` accepts `heal/<date>-<hash>`, and still refuses `main`, tags and
     any other branch.
  6. The pull request's body carries the plan, asserted on its fields.

  _Requirements: 7.1, 7.2, 7.3, 7.5, 7.6_

- [ ] **R44.4** **The policy**. Behaviours, through `heal_policy.py lock`, with
  `gh pr view`'s JSON on stdin, the pull request's two files given as data, and resolution
  that is real and hermetic:
  1. A heal pull request exactly as the recipe makes it: 0.
  2. A third file: 1.
  3. A commit not by the App, unsigned, or without `Heal-Pin`: 1.
  4. A lock one byte different, such as asteval at 1.0.6, a hash dropped or a marker dropped:
     1.
  5. A new package name, a major version, or Checkov moved: 1.
  6. CHANGELOG lines removed, or added outside `[Unreleased]`: 1.
  7. Input it cannot read: 2.
  8. It reads only the two named files. A script planted beside them in the data directory is
     never run.

  _Requirements: 8.1, 8.2, 8.6_

- [ ] **R44.5** **Escalations** (D81m). Behaviours:
  1. `heal.py escalations` turns the plan and the observed Findings into issues to open, to
     comment on and to close, one per `heal: <reason>: <subject>`.
  2. The reasons are design.md's closed list, and a test reads that table.
  3. A cause that has gone is closed, with the run named.
  4. `no-fix`'s body describes the Suppression: its Fingerprint, what it accepts, and an
     expiry 30 days out. A test asserts that nothing writes `.security-scan.toml`.
  5. A Finding at `uv.lock` gives `dependabot-stalled` after half the window.
  6. A second run with the same cause comments, and never opens another issue.

  _Requirements: 11.1 to 11.6_

- [ ] **R44.6** 👤 **The workflows** (D81j, D81k, D81n). Behaviours:
  1. `heal.yml`'s `observe`, `plan`, `propose` and `escalate` jobs, as design.md §4 lays them
     out. The release and tag jobs come in R45.4.
  2. `heal-auto-merge.yml`'s `judge` and `merge` jobs.
  3. **Shape tests:**
     - the triggers;
     - top-level `permissions: {}` and each job's grant;
     - the environments;
     - pinned actions;
     - no expression inside `run:`;
     - the App's login in the gate;
     - only `heal`-environment jobs name the App's secrets;
     - the jobs that resolve hold none.
  4. zizmor finds nothing in `.github/`, at the auditor persona too.
  5. A dispatch on the build branch with `dry_run=true` observes, plans and uploads its plan,
     and opens nothing. It needs only the workflow's token.

  _Requirements: 7.4, 8.3, 8.4, 8.5, 12.1 to 12.5_

- [ ] **R44.7** **Checkov's new versions, for the owner** (D81q). Behaviours:
  1. On a Monday's first run, a newer Checkov past the cooldown gives mode `checkov`.
  2. The plan edits `requirements-checkov.in` and re-locks with `--upgrade-package checkov`.
  3. The pull request is opened, and the policy leaves it for the owner because Checkov moved.
     No escalation issue is opened: the pull request is the notice.
  4. An open Checkov pull request is rebuilt, never duplicated.

- [ ] **R44.8** **The live proof**. Behaviours:
  1. Once the App exists (§3) and R44 has landed: the first real heal, end to end. The App
     opens the pull request, the policy finds it eligible, the checks are green, and GitHub
     squashes it, signed. It is recorded with its run IDs.
  2. Until a real advisory arrives, a `dry_run` dispatch on `main` against `v1.5.3`'s tree
     plans the incident's three pins.

  Ticked with behaviour 1 recorded as waiting, as R28.2's behaviour 4 was, so that
  `build_status.py` does not send every resuming session back to it.

  _Requirements: 13.3_

- [ ] **R44.9** **A base image whose tag has died is replaced** (D81u, amendment 3).
  Behaviours:
  1. **Measure first,** once the owner has allowed `hub.docker.com` (§3): each `FROM` base's
     `last_updated` today, and, from the `python` image's tag list, how often Docker's
     official images have retired an Alpine suffix, and how long the retired tag was still
     listed. The STATUS records both.
  2. `scripts/base_heal.py plan`, against the registry faked in the tests:
     - a tag unmoved for 30 days, with a newer Alpine suffix of the same Python minor that
       moved within 30 days, gives one move;
     - a tag that still moves gives none;
     - a newer Python minor is never proposed;
     - an index without `linux/amd64` and `linux/arm64` gives an escalation, never a move.
  3. `apply` rewrites every place the base is named, as 1.5.4's move did: the Dockerfile's
     two stages, `ci.yml`'s and `release.yml`'s licence diff, `check_image_licences.py` and
     `tests/test_licences.py`. Each is pinned by the index digest, with the tag beside it.
     Afterwards `git grep` finds the old tag only in history.
  4. **2026-10-24 replayed:** `python:3.12-alpine3.22`, last moved 2026-04-19, gives
     `python:3.12-alpine3.24`. Kept as a regression test.
  5. The pull request carries R43.4's verdict on the old image and the new.
  6. `heal.yml` runs it weekly, in `plan`'s grant, and `propose` opens the pull request. A
     pass takes R45's path, and a failure files one issue. With R44.6: 👤 if auto mode
     refuses.

  _Requirements: 17.1 to 17.6_

### Phase R45: security patches release themselves

- [ ] **R45.1** **ADR-0032** (D81h, D81i). Behaviours:
  1. `docs/adr/0032-security-patches-promote-after-a-delay.md`, from design.md's text. It cites
     the requirement IDs it touches (N2.5, N4.3 and section N5's), because the traceability
     check fails an ADR that cites none.
  2. ADR-0020 gains a note that ADR-0032 amends it. `CLAUDE.md` §6 gains the row. The main
     `tasks.md` §5 notes the amendment of D64(e) and D62a for this class.
  3. §3 holds the owner's acceptance.

  _Requirements: 10.6_

- [ ] **R45.2** **Release eligibility and the release policy** (D81g). Behaviours, each on a
  temporary repository:
  1. `heal_release.py check` accepts heal commits, Dependabot's squashed commits and
     patch-class commits since the tag. It refuses `feat`, `!`, and any other machinery
     change.
  2. `opening` renders the template from the plans.
  3. `prepare_release.py` takes `--date`, if it does not already, so the policy can
     reproduce it.
  4. `heal_policy.py release` accepts a release pull request that `prepare_release.py`,
     run on the base, reproduces. It refuses any other change, a version that is not patch
     plus one, and history that `check` refuses.
  5. `verify --tag` is `check` plus the patch-plus-one rule.

  _Requirements: 9.1, 9.2, 9.3, 9.4, 9.7_

- [ ] **R45.3** 👤 **The signer chooses the brake** (D81h). Behaviours:
  1. `verify`'s tag step writes the principal as `signer`. It is tested on a temporary
     repository with two allowed signers, the owner and `valvur-heal`, signed for real with
     `ssh-keygen` keys made in `tmp_path`.
  2. A tag that the heal signed and that fails `heal_release.py verify` stops the release in
     `verify`, naming the check.
  3. `brake` is `release-security` only for a heal-signed tag that passed, and `release`
     otherwise. A rehearsal takes it from the `security_patch` input.
  4. `promote`'s environment is the expression. `notice` opens its issue only for
     `release-security`.
  5. `.github/allowed_signers` gains `valvur-heal`, with the public key the owner gives (§3).
  6. R16.3's release constraint tests are restated for the new job and its grant, and zizmor
     finds nothing.

  _Requirements: 10.1 to 10.5_

- [ ] **R45.4** 👤 **The heal's release and tag jobs**. Behaviours:
  1. Release mode: `release-plan` and `release-propose`, as design.md §4 describes them.
  2. Tag mode tags only a merged App release commit on `main` that has no tag yet. The key is
     written with mode 600 and deleted, and the tag is pushed with the App's token.
  3. A tag with no release gives `release-stopped`.
  4. Shape tests show that only `tag` reads `HEAL_TAG_KEY`. zizmor finds nothing.

  _Requirements: 9.4, 9.5, 9.6, 12.6_

- [ ] **R45.5** **The proof**. Behaviours:
  1. A rehearsal of R45's branch, dispatched with `security_patch=true`, selects
     `release-security`, opens the notice issue, and waits at the timer. It is cancelled
     there, as the main list's §4 step 6 cancels rehearsals at the brake. This needs the
     environment (§3).
  2. The first real security release, end to end, recorded with its run IDs. Ticked as
     waiting until it happens.

  _Requirements: 13.3_

### Phase R46: how fast it heals, and the documents

- [ ] **R46.1** **Time to heal** (D81r). Behaviours:
  1. `scripts/heal_report.py --month YYYY-MM` reads the trailers of merged heal pull requests,
     and the releases, from GitHub's API, faked in the tests. For each advisory it prints
     publication, pull request, merge and promotion, against the 48-hour target.
  2. Each heal run's summary lists the open heals and the month so far.
  3. October 2026's incident is computed as the baseline: publication to the promotion of
     1.5.4.

  _Requirements: 13.1, 13.2_

- [ ] **R46.2** **The documents**. Behaviours:
  1. `docs/RELEASING.md` gains *A security patch, released by the heal*: what it checks, the
     notice, how to cancel, and what `release-stopped` means.
  2. `docs/MAINTENANCE.md` says what heals itself, what reaches the owner (the escalation
     table), and what is left for the weekly routine.
  3. `SECURITY.md` states the window as a target, with D81e's residual risk, in a sentence
     the owner approves (§3).
  4. `CLAUDE.md` gets ADR-0032's row and its status and Next lines, and stays under 200 lines.
  5. The CHANGELOG's `[Unreleased]` is updated.

  The link check reads every new document.

### Phase R47: Scanner upgrades that prepare themselves

- [x] **R47.1** **Measure first** (D81v, amendment 4). Behaviour: the STATUS records each of
  these:
  1. every place each Scanner's version is pinned today: the Dockerfile's stage,
     `scripts/scanner_pins.py`'s sources, the adapters, the golden fixtures, the documents.
     Say why #229 and #230 have been red since 2026-10-17, and #238 since 2026-10-24;
  2. for each Scanner, whether recapturing its fixtures twice, as `docs/MAINTENANCE.md`
     describes, gives the same bytes;
  3. for each Scanner's newest release, its Go toolchain, read from the binary's build
     information. A `go.mod` line is a minimum, not the toolchain.

  **STATUS 2026-10-25:** ✅ 1 to 3, in a cloud session (D61). **Pulled forward** into 1.6.0
  with R47.2 and R47.3, at the owner's word of 2026-10-25 (§3); R47.4 and R47.5 stay with R44
  to R46.
  1. **The pins.** Each Scanner's version is written in four kinds of place:
     - *its stage*, which Dependabot moves: the Dockerfile's `FROM` for Gitleaks, Trivy,
       OSV-Scanner and Syft; for Opengrep, `ARG OPENGREP_URL` with its two sha256 `ARG`s;
       `requirements-zizmor.txt`; `requirements-checkov.in` and the lock
       `scripts/lock-checkov.sh` writes from it. `scripts/scanner_pins.py` reads exactly these;
     - *its adapter*: `VERSION` in `src/valvur/adapters/<tool>.py`, which `run.json` records;
     - *its golden*: `tests/fixtures/golden/<tool>-<version>.json`, and the version in
       `PINNED_VERSIONS` in `tests/conftest.py`, which names it. Gitleaks has no golden:
       conftest builds its output;
     - *the documents*: `docs/PROTOCOL.md`'s Scanner table, and for Opengrep the default
       `VERSION` in `scripts/verify-opengrep.sh`.

     Not pins: test literals that build a `ScannerOutput` with a version, conftest's quiet
     fakes, comments that cite the version a behaviour was measured on, and records
     (`ROADMAP.md`, the CHANGELOG, `docs/history/`, `docs/acceptance/`).
     **Why #229, #230 and #238 are red:** each moves the stage alone (OSV-Scanner 2.7.0 and
     Syft 1.54.1 since 2026-10-17, Trivy 0.76.0 since 2026-10-24). Applying #238's one line to
     this tree fails exactly two tests, both in `test_scanner_pins.py`: the adapter still
     declares 0.75.0, and `PINNED_VERSIONS` and the golden's name still say 0.75.0. Nothing
     else fails (2,328 passed).
  2. **Twice, the same bytes?** `docs/MAINTENANCE.md` described no recapture, so the recipe
     is the one the goldens' commits used (`e521840`, `ef3c335`): the adapter's own command,
     as the `offline` Profile builds it, in one Scan Container fed a Snapshot of a fixture
     copy, its report kept as written. Opengrep, Checkov and OSV-Scanner on `broken-repo`;
     Trivy on its `package-lock.json` and `requirements.txt`; Syft on its `requirements.txt`;
     zizmor on `workflows-repo`. OSV-Scanner needs its offline databases first, and the
     networked adapter writes an empty report in a container with none. Two captures each,
     on today's image and data:
     - **byte for byte:** Opengrep (41,526 bytes), zizmor (7,999) and OSV-Scanner (1,411,614);
     - **only the run's identity differs:** Trivy's `ReportID` and `CreatedAt`, and Syft's
       `serialNumber` and `metadata.timestamp`;
     - **only the order differs:** Checkov's `failed_checks` (the same 13 checks), as
       `ef3c335` saw.

     So "the same" is judged after those fields are blanked and Checkov's checks sorted, and
     only those: anything else that differs refuses the recapture (R47.3).
  3. **Go toolchains,** by `go version` on each binary, copied from its image:

     | Scanner | pinned | its Go | newest | its Go |
     |---|---|---|---|---|
     | Gitleaks | 8.30.1 | go1.24.13 | 8.30.1 (2026-03-12) | go1.24.13 |
     | Trivy | 0.75.0 | go1.27.1 | 0.76.1 | go1.27.3 |
     | OSV-Scanner | 2.6.0 | go1.27.0 | 2.7.0 | go1.27.0 |
     | Syft | 1.54.0 | go1.26.8 | 1.55.0 | go1.26.8 |

     Opengrep is OCaml, zizmor Rust and Checkov Python: no Go. Gitleaks' go1.24 left Go's
     support when go1.26 was released, and its last release is 227 days old.

- [x] **R47.2** **Every pin moves with the Dockerfile's.** Behaviours:
  1. `scripts/scanner_upgrade.py`, given a Scanner and its old and new versions, updates
     every other pin R47.1 lists. It is tested on a copy of the tree with #238's change, and
     the tests that kept #238 red pass.
  2. A Scanner it does not know, or a change to more than one Scanner, is left for the owner,
     naming why.

  _Requirements: 18.1_

  **STATUS 2026-10-25:** ✅ 1 and 2, in `tests/test_scanner_upgrade.py`, on a copy of the
  committed tree. With #238's line applied, the script moves three pins (the adapter, conftest
  and the protocol table) and names `trivy-0.76.0.json` for R47.3; the two tests that kept
  #238 red then pass in the copy. "More than one Scanner" is read from the tree itself: the
  stages `scanner_pins.py` reads against the versions the adapters declare. A stage that does
  not pin the new version is left for the owner too. Exit 3 means left for the owner.

- [x] **R47.3** **The fixtures, recaptured, and the Score.** Behaviours:
  1. It recaptures the Scanner's fixtures twice and refuses a recapture that differs.
  2. It runs `scripts/eval.py --compare tests/eval/baseline.json` and writes each track's
     delta into the pull request's body.
  3. It writes the new binary's Go toolchain into the body.

  _Requirements: 18.2, 18.3, 18.4_

  **STATUS 2026-10-25:** ✅ 1 to 3, in `tests/test_scanner_recapture.py`, with the container
  runtime faked and `scripts/eval.py` stood in for by the `score.json` it writes. Against the
  image: zizmor's recapture is its committed golden byte for byte, and `go_toolchain` reads
  each binary R47.1 measured as `go version` does. `docs/MAINTENANCE.md` describes the recapture.

- [ ] **R47.4** 👤 **It lands only when nothing moved** (D81v). Behaviours:
  1. `scanner-upgrade.yml`, as design.md §12 lays it out: on a Dependabot pull request that
     moves a Scanner's stage, and nothing else.
  2. `heal_policy.py scanner`: every track unchanged and every required check green gives 0;
     any track moved gives 1, and the pull request waits for the owner with the deltas.
  3. Shape tests: the triggers, `permissions: {}` and each job's grant, the environment,
     pinned actions, and package code only in `prepare`, which holds no secret. zizmor finds
     nothing.

  _Requirements: 18.5, 18.6_

- [ ] **R47.5** **The proof.** Behaviour: the next Scanner pull request Dependabot opens is
  completed by the workflow, and lands or reaches the owner with its deltas, recorded with
  its run IDs. Ticked as waiting until it happens.

  _Requirements: 18.1 to 18.6_

---

## 3. The owner queue for this spec

R42.1 adds one row to the main list's §8 that points here. Nothing here blocks a test.

| item | ready after | what the owner does |
|---|---|---|
| approve this spec | done, in halves, 2026-10-24 | R42 and R43 approved, with amendments 1 and 2 (§0, item 7). R42.1 records the date, the half and D81's acceptance for it |
| decide R44 and R45's scope | **decided 2026-10-25** | the owner, 2026-10-25: the second half, R44 to R47, is approved as specced, and Checkov stays through 1.x, since replacing it would change the rule IDs of IaC Findings and so break Suppressions, which the 1.0 promise keeps matching through 1.x. R47.1 to R47.3 are pulled forward into 1.6.0; they grant no power to merge, tag or release. R47.4 and R47.5 stay with R44 to R46. Gitleaks is built from its source with a current Go. R43 (#244) lands before 1.6.0 is released. Start the rest of the second half with §0's prompt |
| land the lock fix, then release 1.5.4 | R42.2 | the fix landed as #235 on 2026-10-24, and Dependabot's alerts #5 to #12 closed with it. Release as `docs/RELEASING.md` says, with a rehearsal, since the lock is machinery. #234 closes after the `SELF_PIN` move or R43.2 |
| close #231 and #232 | done | Dependabot closed them itself on 2026-10-24 and opened #236 and #237, the same re-lock with auto-merge on; those were closed with `@dependabot close` the same day (R42.3's baseline). Another may come with Dependabot's next weekly run, until R42.3 lands |
| make the lock check required, optional | R42.4 landed | add `lock.yml`'s check to `main`'s required checks. The heal's policy runs the same comparison regardless |
| create the GitHub App `valvur-heal` | before R44.8 | Settings → Developer settings → GitHub Apps → New. No webhook. Repository permissions: Contents read and write, Pull requests read and write, Metadata read, nothing else. Install it on `MaverickHQ/valvur` only. Then create the environment `heal`, deployable from `main` alone, with the secrets `HEAL_APP_ID` and `HEAL_APP_KEY` |
| the heal's tag-signing key | before R45.3's behaviour 5 | `ssh-keygen -t ed25519 -C valvur-heal -f valvur-heal -N ''`. Put the private key in `heal` as `HEAL_TAG_KEY`, give the session the `.pub` line, and delete both local files |
| the environment `release-security` | before R45.5 | Settings → Environments → New: wait timer 720 minutes, no required reviewers, deployments from tags `v*` and branches `release/*` |
| PyPI's trusted publisher | before the first real security release | if valvur's publisher on pypi.org names the `release` environment, add a second publisher for `release-security` |
| a tag ruleset, if there is one | R44.1 says | if `v*` tags are restricted, add the App as a bypass actor for tags alone |
| accept ADR-0032 | R45.1 | or choose D81h's fallback: the owner as required reviewer on `release-security` |
| the owner-session tasks | when reached, if auto mode refused | R44.6, R45.3 and R45.4, in a session in manual approve mode, from each task's STATUS |
| the first live heal | R44 landed and the App created | nothing: the schedule runs it. Or dispatch `heal` on `main` with `dry_run=true` first |
| approve `SECURITY.md`'s sentence | R46.2 | read it in R46's pull request |
| accept the image's unfixed findings | R43.4's behaviour 1 | write each into `.github/image-accepted.yaml`, with an expiry, as `.security-scan.toml`'s Suppressions are written. ecdsa's CVE-2024-23342, accepted for the tree since 2026-09-14, is the first. Nothing automated writes the file |
| make the image check required, optional | R43.4 landed | add its two checks to `main`'s required checks |
| allow `hub.docker.com` for the build | **allowed 2026-10-25** | the owner, 2026-10-25: the build may read `hub.docker.com`. The product still names neither it nor any other new host |
| R47's workflow | when reached, if auto mode refused | R47.4, in a session in manual approve mode, from its STATUS |

---

## 4. What this does not change

- **`CLAUDE.md` §3, §4 and §10 hold.** No product feature writes to a Workspace or remediates
  one. The heal changes valvur's own repository, under a policy, as R28.2's auto-merge does.
  The product gains one field (R43.1).
- **No Suppression, override, scan configuration or image acceptance is ever written by
  automation.** Tests hold that (R44.5, R43.4).
- **Every release gate stays:** CI's verdict, the self-scan gate on the tree and the artifact
  (N2.5), the Score (N4.3), and the signature and attestations. Only who presses the brake
  changes, and only for one class of release (ADR-0032).
- **The owner's own releases keep the `release` environment and its reviewer.**
- **The constraint suite stays at 54 tests.** New tests go in new files.
