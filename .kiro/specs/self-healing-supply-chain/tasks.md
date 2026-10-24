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

- [ ] **R42.2** **The lock fix lands** (#234). Behaviours:
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

  _Requirements: none here. It closes the incident the requirements answer._

- [ ] **R42.3** **Dependabot stays out of the Checkov lock** (D81p). Behaviours:
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

  _Requirements: 4.1, 4.2_

- [ ] **R42.4** **The lock is what its recipe writes**. Behaviours:
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

- [ ] **R42.5** **A watchdog over the scheduled workflows** (D81s, amendment 1). Behaviours:
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

### Phase R43: the nightly judges valvur, not the calendar

- [ ] **R43.1** **An advisory's publication date on its Finding** (D81o). Behaviours:
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

- [ ] **R43.2** **`6-self` is the latest release** (D81c). Behaviours:
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

- [ ] **R43.3** **The healing window** (D81b). Behaviours, on Results Folders written by the
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

- [ ] **R43.4** **The image, scanned as it ships** (D81t, amendment 2). Behaviours:
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

- [ ] **R47.1** **Measure first** (D81v, amendment 4). Behaviour: the STATUS records each of
  these:
  1. every place each Scanner's version is pinned today: the Dockerfile's stage,
     `scripts/scanner_pins.py`'s sources, the adapters, the golden fixtures, the documents.
     Say why #229 and #230 have been red since 2026-10-17, and #238 since 2026-10-24;
  2. for each Scanner, whether recapturing its fixtures twice, as `docs/MAINTENANCE.md`
     describes, gives the same bytes;
  3. for each Scanner's newest release, its Go toolchain, read from the binary's build
     information. A `go.mod` line is a minimum, not the toolchain.

- [ ] **R47.2** **Every pin moves with the Dockerfile's.** Behaviours:
  1. `scripts/scanner_upgrade.py`, given a Scanner and its old and new versions, updates
     every other pin R47.1 lists. It is tested on a copy of the tree with #238's change, and
     the tests that kept #238 red pass.
  2. A Scanner it does not know, or a change to more than one Scanner, is left for the owner,
     naming why.

  _Requirements: 18.1_

- [ ] **R47.3** **The fixtures, recaptured, and the Score.** Behaviours:
  1. It recaptures the Scanner's fixtures twice and refuses a recapture that differs.
  2. It runs `scripts/eval.py --compare tests/eval/baseline.json` and writes each track's
     delta into the pull request's body.
  3. It writes the new binary's Go toolchain into the body.

  _Requirements: 18.2, 18.3, 18.4_

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
| decide R44 and R45's scope | R43's phase commit | weigh R44 and R45's standing merge, tag and release power against fewer packages in Checkov's tree, or none (§0, item 7; ADR-0019's reopening). Change any D81 row first, with `/grilling` if you like. Then start the second half with §0's prompt |
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
| allow `hub.docker.com` for the build | before R44.9 | the base heal reads Docker Hub's tag API, which neither `egress.py` nor ADR-0027 names (the main list's stop condition 5). Say yes, or choose another source |
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
