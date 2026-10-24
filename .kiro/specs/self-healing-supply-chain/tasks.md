# The self-healing supply chain: tasks

**Written 2026-10-21, after the nightly `acceptance` run failed on 2026-10-20 and
2026-10-21 (#234).** The owner asked how the build could check and update itself when this
happens, without them in the loop and without another incident like it. This spec is the
answer: [requirements.md](requirements.md) says what, and [design.md](design.md) says how,
including the decisions D81a to D81r with their fallbacks. It is proposed. The owner approves
it by starting the build with §0's prompt, and R42.1 records the date.

**IDs.** Phases R42 to R46 continue [the main list](../valvur/tasks.md). Tasks are
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
Six things differ:

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

**Signed commits.** The executor signs its commits with the owner's SSH key on this Mac
(`commit.gpgsign`), or in a cloud session as D61 (g) says. `698b21e` was made unsigned in a
scratch clone; R42.2 carried it as a signed cherry-pick.

---

## 1. Order

```
R42 the incident closed, one writer for the lock ─► R43 the nightly judges valvur
                                                          │
R46 time to heal, the documents ◄── R45 security patches release ◄── R44 the lock heals itself
```

- **R42 first:** it closes #234's cause and stops the two Dependabot updaters writing a lock
  that the heal will own.
- **R43 before R44:** the heal plans from `advisory_published` (R43.1), and the healing window
  (R43.3) is what makes a heal in progress green rather than an incident.
- **R44 before R45:** a release needs a healed `main`.
- **R45 needs three owner settings** (§3), so the work that needs none comes first.
- **R46 last:** it measures and documents what exists.

---

## 2. The phases

### Phase R42: the incident closed, and one writer for the Checkov lock

- [ ] **R42.1** **This spec on the build's rails** (D81). Behaviours:
  1. `build_status.position` reads the main list, then each other `.kiro/specs/*/tasks.md` in
     name order, and returns this spec's first unchecked task when the main list has none.
     A spec missing on a ref reads as an empty list, not an error.
  2. `shape_errors` checks each list.
  3. `acceptance.ticked` reads every spec's list, so an `until` naming a task here resolves.
  4. The main `tasks.md` gains:
     - an amendment paragraph in its header: approved on the date of the start prompt, at the
       owner's word, with Phases R42 to R46 here;
     - D81's row in §5, pointing to design.md;
     - R42 to R46 in §6;
     - a §8 row pointing to §3 here.

     `CLAUDE.md` §9's *Spec-driven* line names `.kiro/specs/*/`.

  _Requirements: 14.1, 14.2, 14.3_

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

  **Exit:** the acceptance set on both lanes, with the column.

  _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

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

---

## 3. The owner queue for this spec

R42.1 adds one row to the main list's §8 that points here. Nothing here blocks a test.

| item | ready after | what the owner does |
|---|---|---|
| approve this spec | now | start the build with §0's prompt. R42.1 records the date and D81's acceptance. Change any D81 row first with `/grill-with-docs` if you disagree |
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

---

## 4. What this does not change

- **`CLAUDE.md` §3, §4 and §10 hold.** No product feature writes to a Workspace or remediates
  one. The heal changes valvur's own repository, under a policy, as R28.2's auto-merge does.
  The product gains one field (R43.1).
- **No Suppression, override or scan configuration is ever written by automation.** A test
  holds that (R44.5).
- **Every release gate stays:** CI's verdict, the self-scan gate on the tree and the artifact
  (N2.5), the Score (N4.3), and the signature and attestations. Only who presses the brake
  changes, and only for one class of release (ADR-0032).
- **The owner's own releases keep the `release` environment and its reviewer.**
- **The constraint suite stays at 54 tests.** New tests go in new files.
