# Signal and adoption: tasks

**Written 2026-11-21,** after the owner approved [requirements.md](requirements.md) at
checkpoint A. [design.md](design.md) says how, with the decisions D82a to D82s and their
fallbacks. The owner accepted ADR-0033 to ADR-0037 as proposed on 2026-11-22 (checkpoint B).
The test-driven pass was made over this list the same day (§2 says how each task is
written, and marks what the pass changed), and **the owner approved it that day
(checkpoint C).**

**IDs.** Phases R48 to R52 continue [the main list](../valvur/tasks.md) and
[the self-healing list](../self-healing-supply-chain/tasks.md). Tasks are `R<phase>.<n>`, in
the main list's format, which `scripts/build_status.py` reads. Each task names the criteria
it builds, as `_Requirements:_`.

**Contents:** 0 starting the build · 1 order · 2 the phases · 3 the owner queue · 4 what this
does not change

---

## 0. Starting the build

**The start prompt, verbatim:**

> Build the spec in .kiro/specs/signal-and-adoption/ in /Users/maverick/security-scanner.
> Read CLAUDE.md, then that spec's tasks.md §0, and work unattended as
> .kiro/specs/valvur/tasks.md §1 to §4 say, starting at R48.1 on a branch cut from origin/main.

**The main list's §1 to §4 apply unchanged:** one executor, test-driven slices, phase commits,
phases stacked, never a push to `main` or of a tag, the stop conditions, and the build caches.
Five things differ:

1. **`build_status.py` reads the self-healing list before this one,** by name, and that list
   has open tasks that wait for the owner's settings. So this build is started with the
   prompt above and does not wait for them.
2. **All four checkpoints are passed.** The requirements were approved on 2026-11-21 (A),
   and the ADRs (B), this list (C) and the run plan, D82t (D), on 2026-11-22. The build
   starts once this spec has landed on `main`.
3. **Where each step runs** (D82t, design.md's *How the build runs*). Edits, the unit gate,
   signing and pushes are on the owner's Mac. The image, `-m e2e`, the acceptance set and
   the Score are on the dev machine, through `~/dev-machine/bin/dev run`, on the pushed
   branch or with the slice's diff sent in the command. **No token and no key ever goes on
   the machine.** When it cannot start, the step goes to GitHub's lanes and §3 gains a row.
   Each phase has a budget in hours there, and stops when it passes it.
4. **Tasks marked 👤 need the owner:** an edit to `release.yml` (R52.3), three accounts
   (R51.9), a person (R52.6). For an edit to `release.yml` the executor shows the diff first
   and never routes around a refusal, as the self-healing list's §0 item 4 says.
5. **Two releases fall inside this list.** `1.7.0` after R49 and `1.8.0` after R51, each as
   `docs/RELEASING.md` says, with the tag and the brake the owner's.

---

## 1. Order

```
R48 the measurement ─► R49 the bar ─► 1.7.0
                            │
                            └─► R50 an existing codebase ─► R51 the tools around it ─► 1.8.0
                                                                   │
                                                                   └─► R52 the evidence
```

- **R48 first** (D82s): R49's table is filled from R48's counts, and the three hygiene tasks
  stop the measurements moving while R49 reads them.
- **R49 before R50:** a gate on new Findings is worth switching on once a Finding is likely
  true.
- **R50 before R51:** both add optional fields to `findings.json` and the reply (`paths`,
  then `owasp`), so the two are reviewed against the `fp_version` promise in one release.
- **R52 last:** it publishes what the others measured, and its Health record reads
  `heal_report.py` if the self-healing list's R46.1 has built it.
- **Beside the self-healing list.** Nothing here needs the heal App or its environments.
  R52.2 and R52.3 read the image gate's verdict, which exists (R43.4).

---

## 2. The phases

**How each task is written** (the test-driven pass of 2026-11-22, over the main list's §3):

- **Seam:** the public interface the task's tests drive, and what they read back. Every seam
  here is one the main list's §3 names, or a script's `main()` or exported function that an
  existing test file already drives. No test reaches past it.
- **Numbered behaviours are in test order.** Each is one red-to-green slice and one commit.
  The first after any Guard is the tracer: the thinnest slice through the whole seam.
- **Guard:** a test of what must not move. It is written before the slices that could break
  it and is green when written, so it is seen red once against a break made by hand and not
  committed, and its STATUS says which break. Where existing tests already are the guard,
  the task names them and writes none.
- **Record:** a measurement or a document, with no test seam. It names the **check** that
  shows it was done.
- **Proof:** a live run, named by its run ID in the STATUS.
- **A golden or a snapshot moves in the commit that changes what it holds,** never later, so
  every commit is green.

### Phase R48: the measurement, for every rule and every Scanner

- [x] **R48.1** **Measure first, and this spec on the build's rails** (D82a, D82b, D82s).
  No test seam. Behaviours:
  1. **Record.** From one run of the eighth track on `main`:
     - Checkov's and zizmor's Findings on the corpus by rule, and how many labels D82b's
       rule of 25 asks for;
     - which of the 172 labels matched no judged Finding;
     - the track's time on the owner's Mac and on the dev machine.
     *Check:* the STATUS gives the three, with the image's digest and the data's dates.
  2. **Record.** The main `tasks.md` gains D82's row in §5, pointing to design.md; R48 to R52
     in §6; and a §8 row pointing to §3 here. `CLAUDE.md` §6 gains the rows of ADR-0033 to
     ADR-0037, its Next line names this spec, and the file stays under 200 lines.
     *Check:* `scripts/build_status.py` names R48.2 as this list's next task once this one
     is ticked; `scripts/check_traceability.py` holds; the link check passes.

  **STATUS 2026-11-22:** ✅ 1 and 2. The track was run on the dev machine at `f6882b2`, R46's
  head, on `valvur:dev` `sha256:72606c26ab3b` and the day's data: 2.3, with 3 true and 168
  false, in 499 s. On the owner's Mac it took 574 s on 2026-11-21.
  - **Checkov:** 74 Findings in 10 rules, none over 25: CKV_DOCKER_2 14, CKV_DOCKER_3 14,
    CKV_AWS_394 12, CKV2_AWS_12 12, CKV_AWS_338 8, CKV_TF_1 4, CKV2_AWS_5 4, CKV_DOCKER_4 2,
    CKV_AWS_148 2, CKV_DOCKER_7 2. All 74 are labelled.
  - **zizmor:** 702 Findings in 12 rules, four of them over 25: unpinned-uses 318,
    excessive-permissions 207, artipacked 76, dependabot-cooldown 34, template-injection
    20, cache-poisoning 19, dangerous-triggers 12, unpinned-images 7, secrets-inherit 5,
    archived-uses 2, bot-conditions 1, github-env 1. D82b's rule asks for 167 labels.
  - **So R48.3 writes 241 labels.** The two Scanners give 776 Findings together, over D82b's
    fallback of 300, so the sample of 25 a rule stands.
  - **The other Scanners there:** Trivy 1,240 and OSV-Scanner 1,254, counted and not
    judged; Gitleaks 98 and Opengrep 115, judged by the track today.
  - **One of the 172 labels matched no Finding:** `ripgrep`, `valvur.licence.mismatch` at
    `Cargo.toml`. That is the 172 against the 171 judged. It is left as it is: R48.3's
    guard is on a verdict that changes, not on a label with nothing to judge.
  - **The rails:** the main list's §5, §6 and §8 hold D82's row, R48 to R52 and this list's
    queue, and `CLAUDE.md` lists ADR-0033 to ADR-0037, at 200 lines (`21f42ed`).
    `build_status.py` still names R44.6, the owner's, ahead of this list: R48 was cut from
    R46's branch, since the phases stack, and not from `main` as §0 said.

- [x] **R48.2** **Counts for every judged rule, and for every Scanner** (D82a).
  **Seam:** `eval.run(["real-code-precision"], …, scan=, corpus=)` with a scan that writes
  canned Findings, as `tests/test_eval_run.py` drives it; the report it returns, and
  `eval.compare`. Behaviours:
  1. **Guard.** On the canned corpus the track's `score`, `tp` and `fp` are literals written
     in the test, from the formula worked by hand.
  2. `by_rule` holds each rule with a judged Finding: its Scanner and its true and false
     counts. A Gitleaks rule is there.
  3. `by_scanner` holds each Scanner's Findings and how many were judged. A dependency
     Scanner's are counted, with none judged.
  4. A baseline written before these keys existed still compares, with nothing reported.
  5. With `--jobs 4` the corpus's projects are scanned four at a time, and the report is the
     one `--jobs 1` gives, key for key. The default is 1.
  6. A project whose scan fails under `--jobs 4` leaves the track incomplete and is named,
     as it is one at a time.

  **Added 2026-11-22, after checkpoint C, at the owner's word:** 5 and 6. On the dev machine
  the track's 48 scans take 302 s four at a time and 477 s one at a time (design.md, *How
  the build runs*).

  *Closes with:* the track on the real corpus, at 2.3 with 3 true and 168 false, at both
  job counts, with each one's time in the STATUS.

  _Requirements: 1.1_

  **STATUS 2026-11-22:** ✅ 1 to 6 (`7f9e994`), 6 tests in `tests/test_eval_by_rule.py`.
  - **On the real corpus,** on the dev machine at `7f9e994`: 2.3, with 3 true and 168
    false, at both job counts. **272 s with `--jobs 4`, 467 s with `--jobs 1`,** and the
    two reports the same but for their seconds.
  - **`by_rule` holds 15 rules.** Gitleaks: private-key 0 true and 35 false, jwt 0 and 29,
    generic-api-key 0 and 26, curl-auth-header 0 and 6, pkcs12-file 0 and 1,
    slack-webhook-url 0 and 1. Opengrep: `python_random_rule-random` 0 and 23,
    `valvur.python.weak-hash` 0 and 21, insecure-cookie 0 and 8, open-redirect 0 and 7,
    path-traversal 0 and 6, `valvur.javascript.ssrf` 0 and 2,
    `javascript_eval_rule-eval-with-expression` 2 and 1, `valvur.pinning.mutable-git-ref`
    1 and 1. And `valvur.dependency.near-miss` 0 and 1.
  - **`by_scanner`:** Gitleaks 98, all judged; Opengrep 72, all judged; Trivy 1,216,
    zizmor 702, Checkov 74 and OSV-Scanner 64, none judged until R48.3. A Finding is
    counted under the first Scanner that reported it.
  - **A project is also named in `incomplete`** when its Scan Run was not complete, and not
    only when its scan failed, in one list at any job count.

- [x] **R48.3** **Checkov and zizmor, judged in their own table** (D82a, D82b).
  **Seam:** as R48.2, with the labels read from a path the test gives; `eval.compare`;
  `eval.update_baseline`. Behaviours:
  1. A Checkov Finding with a label in the hygiene file is counted under `hygiene`, by rule.
     The track's own `tp` and `fp` do not move.
  2. Of a rule's 26 Findings, the 25 with the lowest Fingerprints are judged, the rule is
     marked `sampled`, and the 26th needs no label.
  3. A dependency Scanner's Finding is never looked up: a label written for one is not read.
  4. **Record.** The labels: every Finding behaviour 2's rule selects on the real corpus,
     judged by reading the file at the project's pinned commit, each with its reason.
     *Check:* the STATUS gives the count by rule, and behaviour 5 passes on the real corpus.
  5. A judged Finding with no label fails `compare`, naming its project, rule and
     Fingerprint.
  6. `update_baseline` records each label's verdict in the baseline.
  7. A label whose verdict differs from the one the baseline records, with no `changed`
     reason, fails a test that reads the two committed files. With the reason it passes.

  **Changed by the pass:** design.md had this test read the labels *at the baseline's
  commit*. The baseline names no commit, and most CI jobs check out one commit. The baseline
  records the verdicts instead, so the test needs no history.

  _Requirements: 1.2, 1.4, 5.2_

  **STATUS 2026-11-22:** ✅ 1 to 7, 10 tests in `tests/test_eval_hygiene.py`.
  - **The run,** on the dev machine at `82738cf`, `valvur:dev` `sha256:913257ee79d7`, with
    `--jobs 4 --compare`: the Score 74.1 and every track where its baseline is, no judged
    Finding without a label in either table, in 327 s for the nine tracks.
  - **The baseline records 413 verdicts,** 172 of the track's and 241 of these, written by
    that run's `--update-baseline`. No track moved. `recorded_on` now names that image and
    that day's data. The guard reads the two committed files, and a second test bends one
    committed verdict in a copy and sees it named.
  - **241 labels** in `tests/eval/labels/hygiene.toml`, each read against its file at the
    project's pinned commit: **153 true and 88 false.**

    | Scanner | rule | Findings | judged | true | false |
    |---|---|---|---|---|---|
    | Checkov | CKV2_AWS_12 | 12 | 12 | 0 | 12 |
    | Checkov | CKV2_AWS_5 | 4 | 4 | 0 | 4 |
    | Checkov | CKV_AWS_148 | 2 | 2 | 0 | 2 |
    | Checkov | CKV_AWS_338 | 8 | 8 | 7 | 1 |
    | Checkov | CKV_AWS_394 | 12 | 12 | 12 | 0 |
    | Checkov | CKV_DOCKER_2 | 14 | 14 | 7 | 7 |
    | Checkov | CKV_DOCKER_3 | 14 | 14 | 7 | 7 |
    | Checkov | CKV_DOCKER_4 | 2 | 2 | 2 | 0 |
    | Checkov | CKV_DOCKER_7 | 2 | 2 | 2 | 0 |
    | Checkov | CKV_TF_1 | 4 | 4 | 0 | 4 |
    | zizmor | archived-uses | 2 | 2 | 2 | 0 |
    | zizmor | artipacked | 76 | 25, sampled | 25 | 0 |
    | zizmor | bot-conditions | 1 | 1 | 1 | 0 |
    | zizmor | cache-poisoning | 19 | 19 | 8 | 11 |
    | zizmor | dangerous-triggers | 12 | 12 | 5 | 7 |
    | zizmor | dependabot-cooldown | 34 | 25, sampled | 18 | 7 |
    | zizmor | excessive-permissions | 207 | 25, sampled | 20 | 5 |
    | zizmor | github-env | 1 | 1 | 0 | 1 |
    | zizmor | secrets-inherit | 5 | 5 | 5 | 0 |
    | zizmor | template-injection | 20 | 20 | 0 | 20 |
    | zizmor | unpinned-images | 7 | 7 | 7 | 0 |
    | zizmor | unpinned-uses | 318 | 25, sampled | 25 | 0 |

  - **Checkov: 37 true, 37 false.** All 42 Terraform Findings are in one project, a
    reusable VPC module. Twenty-three of them are wrong by reading: the module does
    restrict the default security group by default, does attach the endpoints' group,
    provisions no default VPC unless asked, keeps one log group for ever by default, and
    its examples use registry modules, which cannot carry a commit hash. Checkov does not
    follow a count or an expression.
  - **zizmor: 116 true, 51 false.** The rules that state a fact about a line are true every
    time: unpinned-uses, artipacked, unpinned-images, secrets-inherit, archived-uses.
    **template-injection is false 20 times of 20:** every value expanded is set only by
    someone with write access (a dispatch or called-workflow input, a pushed tag) or is
    GitHub's own in a fixed form. cache-poisoning is false 11 times of 19: `setup-node`
    with no cache configured, and caches in test jobs of a workflow that also publishes.
  - **Three readings are applied the same way throughout,** and are written at the head of
    the file for the owner to overrule: a Dockerfile's missing HEALTHCHECK or USER is true
    for an image that serves; a dangerous trigger is true where the privileged run consumes
    what a contributor controls or trusts a spoofable check; a template expansion is false
    where only someone with write access sets the value.
  - **The sample is of the lowest Fingerprints,** which is a draw across Findings and not
    across projects: a project with many workflows has more of a rule's 25. It is the rule
    D82b chose because a reader can repeat it, and the page says *sampled* beside each.

- [x] **R48.4** **`docs/RULES.md` lists every rule that fired, with its two measurements**
  (D82a). **Seam:** `eval.rules_measured(report, path)` and `rules_doc.render(measured)`, as
  `tests/test_rules_doc.py` drives them; `rules_doc.main(["--check"])`. Behaviours:
  1. From a canned report, `rules-measured.json` holds a Gitleaks rule's corpus counts apart
     from its planted counts.
  2. The page gives the two in separate columns.
  3. A rule with fewer than 5 judged Findings on the corpus reads *unmeasured there*.
  4. A sampled rule of Checkov's is on the page, marked *sampled*.
  5. The page says that four places are summed for ADR-0029's bar. The sentence is the
     contract.
  6. **Record.** `rules-measured.json` and the page, regenerated from R48.3's run.
     *Check:* the existing test that the page is current with the measurement.

  _Requirements: 1.3, 2.3_

  **STATUS 2026-11-22:** ✅ 1 to 6 (`ab0574f` and the record), 7 tests in
  `tests/test_rules_doc_others.py`.
  - **The page's second table has 29 rows:** 10 of Checkov's, 12 of zizmor's, 6 of
    Gitleaks' and one of valvur's Checks, regenerated from R48.3's run. Four are marked
    *sampled*. Eleven read *unmeasured there*, with fewer than five judged Findings.
  - **A planted count is a rule's own.** Gitleaks' `private-key` and `generic-api-key` are
    2 true each on the planted cases; the secrets track's other planted secrets are caught
    by nine provider rules, 2 each, that never fired on the corpus, so they have no row.
  - **The first table changed in one way:** a corpus cell with fewer than five judged
    Findings says so. No count in it moved.
  - **Corrected on the page:** it said the bar is *over the three* places. It has been four
    since track 9 (R41), and `rule_precision.PLACES` already summed four.

- [x] **R48.5** **A mutant of an annotation alone is not counted.**
  **Seam:** `mutation_check.code_changed(before, after)`, as the comments-and-docstrings
  test drives it. Behaviours:
  1. **Guard.** A change to an annotation and to a value is a code change.
  2. A change to an argument's annotation alone is not.
  3. Nor is one to a return's annotation alone.
  4. Nor is one to the annotation of an annotated assignment, its value unchanged.
  5. **Record.** The mutation baseline, recorded again if the score moved, with both numbers.
     *Check:* `tests/test_mutation_ratchet.py`, and the phase's pull request's mutation job.

  _Requirements: 15.1_

  **STATUS 2026-11-22:** ✅ 1 to 4, in `scripts/mutation_check.py`, 12 tests in
  `tests/test_mutation_annotations.py`. 5 is the weekly job's: the baseline, 83.8, is one
  week's score and may only rise, and the next Wednesday's run is the first to leave
  annotation-only hunks out. Nothing is recorded by hand before it.
  - **Added: an annotation a dataclass reads is still a code change.** `ClassVar`, `InitVar`
    and `KW_ONLY` decide what the class is, so a hunk that changes one of those is counted.
  - A removed return annotation and a bare declaration (`seen: dict`) are no code change
    either, with the three cases the task names.

- [x] **R48.6** **No test compares against a moving target.**
  **Seam:** a guard over the tree, in `tests/test_no_moving_target.py`, whose finder takes a
  root so that it can be driven on a tree made in `tmp_path`. Behaviours:
  1. In a made tree whose Dockerfile pins `name:tag@sha256:…`, a file that names `name:tag`
     alone is reported with its line. One that names the digest is not.
  2. A line on the list of exceptions is not reported. An exception with no reason is
     refused.
  3. On the repository the guard is red, naming `scripts/check_image_licences.py` and
     `tests/test_licences.py`. Both then read the base, digest included, from the
     Dockerfile, and `tests/test_licences.py` passes unchanged in what it asserts.
  4. What is left on the list is `:latest` of valvur's own image where the nightly and the
     watchdog read it on purpose, each with its reason.

  _Requirements: 15.2_

  **STATUS 2026-11-22:** ✅ 1 to 4, 7 tests in `tests/test_no_moving_target.py`.
  - **Red first on the repository:** it named `scripts/check_image_licences.py`,
    `tests/test_licences.py`, `ci.yml` and `release.yml`. The script now reads the final
    stage's base from the Dockerfile, digest included, and refuses a Dockerfile whose final
    stage has none. The test and CI's step pass no base.
  - **Proof,** on the dev machine at `a00fa01` with this slice, `valvur:dev`
    `sha256:913257ee79d7`: 1,296 components added over the base named with its digest, no
    GPL or AGPL one, in 10 s; `tests/test_licences.py`'s e2e test passes.
  - **Added: an action.** Requirement 15.2 names one: a workflow that names by tag an
    action another workflow pins by commit is reported. None does today.
  - **`:latest` is refused for valvur's own image alone.** Other `:latest` strings under
    `tests/` are the text of fakes and fixtures, and none is pulled.
  - **The list holds five.** Four are `ghcr.io/maverickhq/valvur:latest`: the nightly and
    the watchdog, which judge the image users pull today, and the two tests that assert
    they do. **The fifth is the owner's:** `release.yml` line 157 still passes the base's
    tag, and the diff is in §3. Until then the release's licence check diffs against the
    tag as Docker Hub serves it, as it always has.
  - **The base tag heal follows** (`scripts/base_heal.py`, R44.12): it rewrites the
    Dockerfile and `release.yml`, no longer five files, and writes only a file that names
    the old tag. Once the owner's edit is in, a base tag move changes the Dockerfile and
    the CHANGELOG alone, which bears on the question R44.12 left for the owner: such a move
    then touches no workflow.

- [x] **R48.7** **The hostile fixtures are stored under names no agent loads.**
  **Seam:** `scripts/fixtures.py`'s `copy`, which the tests reach as `copy_fixture`, and the
  stored tree as `git ls-files` gives it. Behaviours:
  1. **Guard, existing.** `tests/test_scan_goldens.py` and the AI-artifact tests, which read
     a copy. They pass unchanged after every slice below.
  2. In a made tree, `copy` gives a stored `.mcp.json.fixture` and a stored directory
     `.claude.fixture/` their real names.
  3. A test finds `AGENTS.md`, `CLAUDE.md`, `.mcp.json` and `.claude/` in the stored tree,
     and is red. The four are renamed, and it is green.
  4. A test finds no reader of the stored tree in `scripts/`, `.github/` or `tests/` other
     than through `copy`. `scanner_upgrade.RECIPES` and `ci.yml`'s `published` job already
     go through it, so this is a **Guard**, seen red against a hand-made reader.
  5. **Record.** *Check:* `git diff --stat` over `tests/fixtures/golden/` is empty for the
     task.

  _Requirements: 15.3_

  **STATUS 2026-11-22:** ✅ 1 to 5 (`2ddae45`), 5 tests in
  `tests/test_hostile_fixture_names.py`.
  - **Stored now:** `AGENTS.md.fixture`, `CLAUDE.md.fixture`, `.mcp.json.fixture` and
    `.claude.fixture/settings.json`. No other fixture held a name an agent client loads;
    the guard's list also names `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
    `copilot-instructions.md` and the `.cursor/`, `.kiro/`, `.codex/` and `.windsurf/`
    directories.
  - **`copy` renames the deepest first,** so a stored file inside a stored directory gets
    its real name too. It raised before.
  - **One reader went round the copier:** `tests/test_applicability.py` read the stored
    tree for its Terraform. It reads a copy. Three files name the stored tree and read
    nothing an agent would load, each listed with its reason.
  - **Proof,** on the dev machine at `6b3e9cd` with the slice, `valvur:dev`
    `sha256:913257ee79d7`: the container tests, 89 passed and 8 skipped in 439 s; the
    acceptance set passed in 280 s with its generation; **no file under
    `tests/fixtures/golden/` changed.**

**Exit:** the Score unchanged on every track, on both lanes; `docs/RULES.md` lists every rule
that fired on the corpus; the three hygiene tests hold.

**STATUS 2026-11-22:** ✅ the exit is measured, in [`docs/acceptance/r48.md`](../../../docs/acceptance/r48.md).
- **The Score is 74.1 on both lanes, and no track moved:** the dev machine at `82738cf`
  (arm64, 327 s with `--jobs 4`) and the pull request's check at `5f2e952` (amd64, eval run
  45063635361, 622 s). The Mac ran the unit gate; the Score's second lane is the dev
  machine, as D82t says.
- **`docs/RULES.md`** lists 25 of Opengrep's rules and 29 others, and is held current.
- **The three hygiene tests hold,** and every check of #307 passed at `5f2e952`.
- **Left for the owner:** one line of `release.yml` (§3), and the 241 verdicts to read.

### Phase R49: the bar on maintained code

- [x] **R49.1** **Measure first** (D82e, D82f, D82g). No test seam. **Record,** each in the
  STATUS, and design.md's first table completed from it:
  1. for `insecure-cookie`, `open-redirect`, `path-traversal` and `ssrf`, the pattern their
     false Findings share, read from the labelled files, and one cut-down example of each,
     which R49.5 uses as its failing case;
  2. for each rule under D82d's bar, each track's score with that rule made inventory. **If
     the Python track falls more than 8 points with `weak-hash` and `random` demoted, the
     phase stops here and the owner is asked again** (D82g's fallback);
  3. for each directory name D82f proposes, the Findings it moves on the corpus and the
     cases it moves on every track;
  4. for each of Gitleaks' rules that fired on the corpus, whether it matches a shape or a
     provider's format, from its definition in the Gitleaks version the image ships.

  *Check:* design.md's table has no cell marked *to measure*.

  _Requirements: 4.1_

  **STATUS 2026-11-22:** ✅ 1 to 4, measured on the dev machine at `f2aca7b` from R48.3's
  run (`valvur:dev` `sha256:913257ee79d7`), by re-scoring each track's Results Folder with
  a rule's Findings left out. Re-scored with nothing left out, every track is its run's.
  **The Python track falls 6.3 points, 40.9 to 34.6, with `weak-hash` and `random` demoted:
  inside D82g's 8, so the phase goes on.** design.md said about 34.7.

  **1. What the false Findings share, and a cut-down example of each.**
  - **`valvur.python.insecure-cookie`, 8:** the path, and nothing in the code. All eight
    are in test files that set `secure=False` on purpose, as
    `resp.set_cookie('foo', 'bar', secure=False)`. That is the vulnerable form itself, so
    no narrower pattern separates them. R49.5's slice 4 applies: a row, for test material.
  - **`valvur.python.open-redirect`, 7:** five redirect to a URL the router builds,
    `redirect(url_for("display", uid=uid))` and Sanic's
    `redirect(request.app.url_for("page", path=path))`. One redirects to a path an example
    builds, `redirect(f"/{short_id}+")`, and one is a test's own URL.
  - **`valvur.python.path-traversal`, 6:** three take a path's name, suffix or absoluteness
    and open nothing: `Path(filename).is_absolute()`, `Path(request.url).suffix`,
    `Path(request.url).name`. Two read pytest's `request.param`, which is no web request:
    `Path(request.param[0])`. One is a crawler's `file://` handler, which reads the path it
    was told to.
  - **`valvur.javascript.ssrf`, 2:** both are HTTP client libraries sending the request
    their caller asked for: `https.request(options, callback)` and
    `fetch(new Request(locationURL, requestOptions))`. With 2 judged it is unmeasured on
    the corpus, and under no bar.

  **2. Each rule under D82d's bar, and what demoting it everywhere costs.** Thirteen rules
  have 5 or more judged Findings and fewer than half true.

  | Scanner | rule | true / false | tracks that move |
  |---|---|---|---|
  | Opengrep | `valvur.python.weak-hash` | 0 / 21 | Python 40.9 to 37.1 |
  | Opengrep | `python_random_rule-random` | 0 / 23 | Python 40.9 to 38.3 |
  | Opengrep | `valvur.python.insecure-cookie` | 0 / 8 | Python 40.9 to 33.7 |
  | Opengrep | `valvur.python.open-redirect` | 0 / 7 | Python 40.9 to 36.6 |
  | Opengrep | `valvur.python.path-traversal` | 0 / 6 | Python 40.9 to 38.4 |
  | Gitleaks | `private-key` | 0 / 35 | secrets 100.0 to 90.0 |
  | Gitleaks | `generic-api-key` | 0 / 26 | JavaScript 55.0 to 45.0 |
  | Gitleaks | `jwt` | 0 / 29 | none |
  | Gitleaks | `curl-auth-header` | 0 / 6 | none |
  | Checkov | `CKV2_AWS_12` | 0 / 12 | none |
  | zizmor | `cache-poisoning` | 8 / 11 | none |
  | zizmor | `dangerous-triggers` | 5 / 7 | infrastructure 95.0 to 90.0 |
  | zizmor | `template-injection` | 0 / 20 | infrastructure 95.0 to 90.0 |

  - **All thirteen demoted everywhere:** Python 20.7, JavaScript 45.0, secrets 90.0,
    infrastructure 85.0, and the Score 72.3 from 74.1, with the eighth track at 36.4 on 3
    true and 7 false. That is the cost the tier table's `test material` and R49.5's
    narrowing exist to avoid: no secrets rule is demoted everywhere, two of Opengrep's
    five are narrowed first, and `insecure-cookie` is demoted in test material alone.
  - **D82d's fallback, listed for the owner and left active:** Checkov's `CKV2_AWS_5` and
    `CKV_TF_1`, each 0 true of 4.
  - **New, and the owner's to decide (Requirement 2.5).** R48's labels put four rules of
    Checkov's and zizmor's under the bar, which the design did not foresee. `CKV2_AWS_12`
    and `cache-poisoning` move no track and take a row in R49.2's table. **Demoting
    `dangerous-triggers` or `template-injection` takes 5 points from the infrastructure
    track, past the ratchet, and they are not valvur's rules to narrow.** Until the owner
    decides they stay active, and R49.8's check names them. The choices: re-base the
    infrastructure track as D82g re-bases Python (95.0 to 85.0 for both); leave them
    active as measured noise; or overrule the labels, which are the executor's
    (`dangerous-triggers` is 5 true of 12 on one reading of *handled*).

  **3. The directory names D82f proposes.** None moves a case on any track.
  - `docs_src`: 7 judged Findings on the corpus, all false, classed `source` today.
  - `guide`: 11, all false, classed `source` today, in one project.
  - `doc` and `guides`: no Finding on the corpus. Safe by the measurement, and without
    evidence of use.

  **4. Gitleaks' six rules that fired on the corpus,** from `config/gitleaks.toml` at
  v8.30.1, the version the image ships. Five match a shape: `private-key` (a PEM header and
  footer), `jwt` (three base64 segments), `generic-api-key` (a keyword beside a string of
  entropy 3.5 or more), `curl-auth-header` (a header in a `curl` command) and `pkcs12-file`
  (a file name). One matches a provider's format: `slack-webhook-url`.

- [x] **R49.2** **The tier table, and its first row** (D82c, D82d, D82e).
  **Seam:** `api.scan` over `LocalRuntime` with canned Scanner output; `findings.json`, the
  Status and `gate.evaluate` read back. For the table against the measurement:
  `rule_precision.tier_disagreements(rows, measured)`. Behaviours:
  1. **Guard, existing.** `tests/test_class_table.py` and `tests/test_sink_inventory.py`.
  2. A `valvur.python.weak-hash` Finding in a source path is `inventory` in `findings.json`.
     It is the only Finding, the Status is `clean`, and the gate passes. This slice adds
     the table, its reader and the row.
  3. Its title says it is listed for review because the rule is under the bar on maintained
     code. The sentence is the contract.
  4. A `.security-scan.toml` that names a tier is refused as an unknown key, and the Finding
     is still inventory.
  5. A rule named both in the table and by a rule file's `metadata.inventory` fails a test.
  6. On a canned measurement, `tier_disagreements` names a rule that is measured, under the
     bar and has no row.
  7. It names a row whose counts differ from the measurement.
  8. It names nothing for a rule with fewer than 5 judged Findings.

  **Changed by the pass:** the table could not be tested through a scan without a row, so
  `weak-hash`'s row moved here from R49.3. The check of the real table against the real
  measurement moved to R49.8: it is red until R49.5 has narrowed or demoted the last rule.

  *Closes with:* `--tracks sast-python,real-code-precision --compare`, each delta in the
  STATUS. The Python track is expected under its baseline until R49.8 re-bases it.

  _Requirements: 2.1, 2.2, 2.4, 3.4_

  **STATUS 2026-11-22:** ✅ 1 to 8 (`6425942`, `59b0d93`, `55c7484`), 9 tests in
  `tests/test_tier_table.py` and 5 in `tests/test_tier_disagreements.py`.
  - **The closing run,** on the dev machine at `59b0d93`, `valvur:dev`
    `sha256:5a7bf9c5bc35`:

    | track | baseline | with the three rows |
    |---|---|---|
    | Python | 40.9 | 37.1, as R49.1 measured; `--compare` fails on it, as expected |
    | infrastructure | 95.0 | 95.0 |
    | real code | 2.3, 3 true and 168 false | 2.6, 3 true and 147 false |

    The acceptance set passes, 8 of 8.
  - **Added: two rows of other Scanners,** which R49.1 found under the bar and which move
    no track: Checkov's `CKV2_AWS_12`, 0 true of 12, and zizmor's `cache-poisoning`, 8 of
    19. A row names its Scanner, so another Scanner's rule of the same name stays active.
  - **Added: `SUMMARY.md` counts a tiered Finding under *Listed for review*,** apart from
    *Sinks to review*, with one line that says why. `tests/test_contract.py`'s split of a
    Results Folder is restated: five parts, where it had four.
  - **Found by the closing run, and fixed (`55c7484`):** once a rule was listed, the
    track's `by_rule` and `hygiene` dropped its Findings, since they are no longer active,
    so the table could not be held to a measurement that had lost the rule. A listed
    Finding's label now counts for its rule, and not for the track's own numbers.
  - **Behaviour 4 is a guard at the schema:** a scan never read a `[[tier]]` key, and
    `project_schema.problem`, which `doctor` reports, refuses it.
  - **One test restated:** `tests/test_summary_order.py` showed its grouping on
    `CKV2_AWS_12`, which is inventory now; it uses a rule that is active.
  - `tier_disagreements` on the real table, after R49.3's row, names the nine rules still
    to place: R49.4's four, R49.5's three, and the two of zizmor's that wait for the owner.

- [x] **R49.3** **The vendored `random` rule's row, and one home for both rules** (D82e,
  D82g). **Seam:** as R49.2; `rules_doc.render`; the vendored rules' audit, as
  `tests/test_sast_rules_audit.py` drives it. Behaviours:
  1. **Guard, existing.** The audit holds the vendored file byte for byte.
  2. The vendored `random` rule's Finding in a source path is inventory.
  3. In a test path, both rules' Findings are in `findings.json` as inventory, where the
     class table removed them. Its row is gone, and the test in `tests/test_class_table.py`
     that held the removal is restated in this commit.
  4. `docs/RULES.md` shows each as *inventory: under the bar on maintained code*, with its
     counts.
  5. The vendored rule's manifest entry carries its corpus counts.

  *Closes with:* the same two tracks, each delta in the STATUS.

  _Requirements: 2.2, 4.4_

  **STATUS 2026-11-22:** ✅ 1 to 5 (`99e9130`), in `tests/test_tier_table.py`,
  `tests/test_class_table.py`, `tests/test_rules_doc_others.py` and
  `tests/test_vendored_tier_counts.py`.
  - **The closing run,** on the dev machine at `55c7484`, `valvur:dev`
    `sha256:b86a0b7335e8`:

    | track | baseline | with both rules listed |
    |---|---|---|
    | Python | 40.9 | 34.6, the 6.3 points R49.1 measured; `--compare` fails on it until R49.8 |
    | JavaScript | 55.0 | 55.0 |
    | infrastructure | 95.0 | 95.0 |
    | real code | 2.3, 3 true and 168 false | 3.1, 3 true and 124 false |

  - **The measurement kept both rules** after R49.2's fix: `by_rule` holds `weak-hash` at 0
    true and 21 false and `random` at 0 and 23, and `hygiene` holds `CKV2_AWS_12` at 12
    judged and `cache-poisoning` at 19.
  - **The class table removes nothing now.** Its removal action went with its one row;
    `run.json` keeps `removed_by_class`, empty, for whoever reads it.
  - **The 124 false Findings still active,** by rule: `private-key` 35, `jwt` 29,
    `generic-api-key` 26, `insecure-cookie` 8, `open-redirect` 7, `curl-auth-header` 6,
    `path-traversal` 6, `ssrf` 2, and one each of five rules.

- [x] **R49.4** **A secret in test material** (D82c, D82f).
  **Seam:** the secrets track's generator in `scripts/eval/twins.py` and
  `eval.run(["secrets"], …)`; `api.scan` over `LocalRuntime` with canned Gitleaks output;
  `pathclass.of`. Behaviours:
  1. **Guard.** The secrets track gains, for each provider format, a live-format secret
     under a test path and under a documentation path, assembled at runtime. Each is caught
     before any row exists, and the track is at 100.
  2. **Guard, existing.** A private key under `config/` is active and critical.
  3. A `private-key` Finding under `tests/` is inventory, and its title names the path that
     decided it.
  4. The same for each other shape rule R49.1 named, one row and one case each.
  5. A provider-format Finding under `tests/` is still active, as today.
  6. `pathclass.of` gives `docs` for each directory name R49.1 found safe, one name a slice.
  7. `docs/RULES.md` and the README say what is listed for review, and why.

  *Closes with:* `--tracks secrets,real-code-precision --compare`: the secrets track at 100
  with the new cases, and every secrets rule with a row over the bar or silent on the corpus.

  _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  **STATUS 2026-11-22:** ✅ 1 to 7 (`b74b154`, `51720db`), in `tests/test_tier_table.py`,
  `tests/test_eval_twins.py` and `tests/test_path_classes.py`.
  - **The closing run,** on the dev machine at `51720db`, `valvur:dev`
    `sha256:61934a8a9837`, with `--compare`, which passed:

    | track | baseline | this run |
    |---|---|---|
    | secrets | 100.0, 40 cases | **100.0, 58 cases** |
    | JavaScript | 55.0 | 55.0 |
    | agent configuration | 94.3 | 94.3 |
    | infrastructure | 95.0 | 95.0 |
    | real code | 2.3, 3 true and 168 false | **12.1, 3 true and 29 false** |

  - **Every planted secret in test material is caught and active:** the 18 new cases, nine
    provider formats under `tests/` and under `docs/`, are each reported at `low` by the
    provider's own rule, and none is inventory.
  - **Of the 98 false secrets on the corpus, three stay active,** the three design.md
    named: a `generic-api-key` in a `README`, the one `pkcs12-file`, and the one
    `slack-webhook-url`, which is a provider's format. So criterion 3.5 does not arise.
  - **Every secrets rule with a row is silent in test material and measured:** `by_rule`
    holds `private-key` 0 true of 35, `jwt` 0 of 29, `generic-api-key` 0 of 26 and
    `curl-auth-header` 0 of 6, as their rows say.
  - **All four directory names are in,** `docs_src`, `guide`, `doc` and `guides`, in one
    commit with one parametrized test and not four slices. `doc` and `guides` hold no
    Finding on the corpus: they are in on D82f's decision and R49.1's finding that they
    move no planted case, not on evidence of use.
  - **The JavaScript track does not move:** `generic-api-key` demoted everywhere would
    cost it 10 points (R49.1), and in test material alone it costs nothing.

- [x] **R49.5** **The rules that can be narrowed** (D82e).
  **Seam:** the rule run by Opengrep in `valvur:dev`, through `api.scan` with the container
  runtime, as `tests/test_python_web_rules.py` drives it (`-m e2e`); `eval.py --per-rule`
  for the two measurements. One rule at a time, in this order, each with these slices:
  1. **Guard, existing.** The rule's planted cases are caught.
  2. R49.1's cut-down false example is reported, so the test that it is not is red. The
     pattern is narrowed, and it is green.
  3. **Record.** The rule on the corpus and on its category. *Check:* both numbers in the
     STATUS, over D82d's bar and inside the ratchet.
  4. If either fails: the old pattern is restored, the rule takes a row, and slice 2's test
     is restated to hold the Finding as inventory.

  The rules: `valvur.python.insecure-cookie`, `valvur.python.open-redirect`,
  `valvur.python.path-traversal`, `valvur.javascript.ssrf`.

  _Requirements: 4.1, 4.2_

  **STATUS 2026-11-22:** ✅ (`0445cdc`), 4 container tests in
  `tests/test_narrowed_rules.py`, seen red on three of the four before the narrowing and
  green after, on the dev machine, with `tests/test_python_web_rules.py`'s planted twins.
  Measured by the whole Score at `0445cdc`, `valvur:dev` `sha256:f3995ce2a6ff`.

  | rule | on the corpus, before | after | its category on the Python or JavaScript track |
  |---|---|---|---|
  | `open-redirect` | 0 true, 7 false | 0 and 2 | `redirect` 9 of 13, unchanged |
  | `path-traversal` | 0 and 6 | 0 and 1 | `pathtraver` 27 of 65, unchanged |
  | `insecure-cookie` | 0 and 8 | 0 and 8, all listed | `securecookie` 24 of 24, unchanged |
  | `ssrf` | 0 and 2 | **0 and 2** | CWE-918 2 of 2, unchanged |

  - **`open-redirect`:** a URL the router builds, `url_for(…)`, is a sanitizer. Two false
    Findings are left, an example's own path and a test's own URL.
  - **`path-traversal`:** a path's `name`, `suffix`, `stem` or `is_absolute()` is no sink,
    and pytest's `request.param` is no source, for every Python taint rule that shares the
    sources. One is left, a crawler's `file://` handler.
  - **`insecure-cookie` was not narrowed, and took slice 4:** a row, for test material.
    Its eight false Findings are the vulnerable form itself. Demoted everywhere it would
    have cost the Python track 7.2 points; in test material it costs none.
  - **`ssrf`: the narrowing is real and did not reach the corpus.** A response's headers
    are no longer request data, which the made example showed red and then green. **The
    two Findings on the corpus are still reported:** both are HTTP client libraries whose
    own outgoing request is named `request`, which is what the rule names. No pattern
    tells a client library from a server by reading one file.
  - **A reading of the task, for the owner.** Slice 3 asks each narrowed rule to be *over
    D82d's bar*. `open-redirect`, `path-traversal` and `ssrf` are now *unmeasured there*,
    with 2, 1 and 2 judged Findings, none true. That is read here as not under the bar:
    Requirement 2.3 leaves an unmeasured rule as ADR-0029 has it, and D82h says a rule
    judged on one label is not measured. The other reading restores the old patterns and
    lists all three everywhere, which costs the Python track 4.3 and 2.5 points for five
    Findings.
  - **The whole Score at this point is 76.1, from 74.1.** The real-code track is 26.7 on 3
    true and 11 false. `--compare` fails on the Python track alone, 34.6, until R49.8.
  - **Eleven labels now match no Finding:** the ten narrowed away, and R48.1's one. They
    are left in the file, as that one was.

- [x] **R49.6** **Two rules the tracks lacked** (D82i).
  **Seam:** the generators in `scripts/eval/twins.py`, as `tests/test_eval_twins.py` drives
  them; the rules as R49.5 runs them; `eval.run` for the tracks. Behaviours:
  1. The JavaScript track's generator gives vulnerable and safe cases for CWE-295.
  2. `valvur.javascript.tls-verification-off` catches the vulnerable ones and no safe one.
  3. The generator gives both kinds for CWE-614.
  4. `valvur.javascript.insecure-cookie` catches the vulnerable ones and no safe one.
  5. The Python track reports generated cases as a category apart from the Benchmark's.
  6. `valvur.python.tls-verification-off` catches its cases and no safe one.
  7. **Record.** Each rule's Findings on the corpus, labelled. *Check:* each is over
     ADR-0029's bar and D82d's, or it is not shipped and the STATUS says so.

  _Requirements: 4.3_

  **STATUS 2026-11-22:** ✅ 1 to 7, with one rule of the three **not shipped**, as D82i's
  fallback says. Tests: `tests/test_added_rules.py` (through Opengrep in the image, seen red
  for each rule before it existed), `tests/test_eval_twins.py`, `tests/test_eval_run.py`.

  | rule | its planted cases | on the corpus | |
  |---|---|---|---|
  | `valvur.javascript.insecure-cookie` | 2 of 2, no safe one | silent | **shipped** |
  | `valvur.python.tls-verification-off` | 3 of 3, no safe one | 1 true, 1 false | **shipped,** narrowed first |
  | `valvur.javascript.tls-verification-off` | 2 of 2, no safe one | **0 true of 307** | **not shipped** |

  - **The JavaScript TLS rule is under ADR-0029's bar** by any count: 2 true on its cases
    and 307 false on maintained code. 299 are in the tests of HTTP libraries, which talk to
    servers with self-signed certificates (`got` 126, `undici` 126, `axios` 22, `ws` 11),
    and 8 in two projects' benchmark scripts. It is out of the rule file, and a test holds
    it out. **Its two cases stay on the JavaScript track, uncaught,** so the Score shows
    the gap: Requirement 4.3 is open for JavaScript's CWE-295.
  - **For the owner:** the rule is right in an application and wrong in a library's tests.
    It could ship listed in test material if `benchmark/` and `benchmarks/` were test
    material too; that widening is not in D82f, so it is not made here.
  - **The Python TLS rule as first written was 1 true of 12.** Five of its six Findings
    outside tests were `context.verify_mode = ssl.CERT_NONE` in a client library that is
    honouring its own caller's option (`httpx`, `aiohttp`, `tornado`, `scrapy` twice). The
    pattern is dropped: the rule names the calls an application writes, `verify=False` on
    `requests` and `httpx`, and `ssl._create_unverified_context`. design.md also listed
    `ssl.CERT_NONE`.
  - **Its one true Finding is the phase's only new one on maintained code:** `httpie`
    fetches its update notice with `requests.get(…, verify=False)`. Both Findings are
    labelled in `corpus.toml`.
  - **The Python track's generated cases** are written beside the Benchmark, never into
    it, scanned in a second Scan Run and reported as `tls-verification (generated)`: three
    vulnerable and three safe.
  - **The acceptance set caught the rule on valvur itself.** `6-self` failed with one
    blocking Finding: `src/valvur/oci.py` reads
    `ssl._create_unverified_context() if insecure else None`, an operator's opt-in for an
    internal mirror. That is the same case as the libraries': verification off only when
    a caller asks. The rule now passes over a call chosen by a conditional expression,
    with a made case seen reported and then not, and the set passes, 8 of 8.
  - **Measured** on the dev machine at `db5cf3e` with this task's slice, `valvur:dev`
    `sha256:eeb6ce895340`, the whole Score with `--compare`, which passed, at **76.8**:

    | track | baseline | this run |
    |---|---|---|
    | Python | 40.9, 14 categories | 39.0, 15 categories: the new one at 3 of 3 |
    | JavaScript | 55.0, 10 categories | 54.2, 12 categories: CWE-614 at 2 of 2, CWE-295 at 0 of 2 |
    | real code | 2.3, 3 true and 168 false | 29.4, 4 true and 12 false |

    Both static-analysis tracks are inside the ratchet again, so `--compare` passes.

- [x] **R49.7** **Model output crossing a function** (D82j).
  **Seam:** for the measurement, none. For the note: `api.scan` over `LocalRuntime`;
  `SUMMARY.md` and the Status read back. Behaviours:
  1. **Record.** Opengrep's `--taint-intrafile`, at the image's version, on the five
     advisories, the generated cases, the corpus and the acceptance set's time.
     *Check:* the STATUS gives the four, and says which of 2 and 3 follows.
  2. *If it catches one of the five with no new false Finding:* the four `valvur.llm.*`
     rules run with it. A test in `tests/test_llm_output_track.py`'s form holds the
     advisory it catches, and the ninth track's baseline rises in R49.8.
  3. *Otherwise:* a Scan Run with a model call and a sink, and no `valvur.llm.*` Finding
     joining them, has the note in `SUMMARY.md`. Its Status is what it was without the note.
  4. A Scan Run with no model call has no note.
  5. No document says the rules follow a flow between files. The test is seen red against a
     sentence planted in a copy.

  _Requirements: 6.1, 6.2, 6.3, 6.4_

  **STATUS 2026-11-22:** ✅ 1, then 3 to 5: the flag is **not adopted**, and the note is in.
  - **The measurement,** Opengrep's `--taint-intrafile` at the image's version, through
    valvur's own scan with the flag added to the adapter, on the dev machine at `db5cf3e`
    with R49.6's slice:

    | | without the flag | with it |
    |---|---|---|
    | the five advisories | 0 of 5 | **0 of 5** |
    | the generated cases | 30 of 34, no safe one flagged | 34 of 34, no safe one flagged |
    | the ninth track | 79.0 | 89.8 |
    | the Python and JavaScript tracks | 39.0 and 54.2 | 39.0 and 54.2 |
    | Findings on the corpus | 16 judged | 5 new and unjudged, 3 of the 16 gone |
    | the acceptance set | 132 s | 133 s |

  - **It catches none of the five, so Requirement 6.2's condition is not met** and nothing
    in the rules changes. The five new Findings on the corpus are of four request-data
    rules, not of the model-output rules: the flag is per run, and cannot be given to four
    rules alone.
  - **For the owner:** it does catch the four generated flows valvur misses, at no cost
    in time. Adopting it would raise the ninth track by 10.8 points and needs the five new
    Findings judged first. The design's condition was the five advisories, so it is left.
  - **The note** (`src/valvur/model_output.py`, a stage after `merged`): one rule,
    `valvur.llm.model-call`, marks where a model is called, with the sources the three
    Python rules share, by reference. Its marks never reach `findings.json`. A Scan Run
    with a mark, a sink to review and no model-output Finding gains one Finding of
    `valvur.llm.output-not-followed`, shown under *What valvur could not read*. It is in
    `NOTE_RULES` and not in `DOUBT_RULES`: the Status is what it was.
  - **Narrower than design.md in three ways, each said here.** The note is per Scan Run
    and not per function: a Finding carries a line and no function. The mark is Python's
    alone, since the sinks valvur names for review are Python's. And the mark needs the
    file to import a model SDK, so the count is *at least N files*.
  - **Found on the corpus, and fixed before it was committed:** with the shared sources
    alone the note told Flask and Litestar that they call a model. `$X.invoke(…)` is
    Click's test runner too, and `$X.messages.create(…)` is Twilio's. The taint rules can
    be loose there, since they also need a sink; a statement cannot. A made case with
    both was seen noted, and then not. On the corpus the note is now in two projects,
    `llm` and `smolagents`, which do call a model.
  - **Measured with the note in,** on the dev machine at `756c8fe` with the slice,
    `valvur:dev` `sha256:f4ec1791eb70`: the whole Score 76.8 with `--compare` passing, no
    track moved, no mark in any `findings.json`, the acceptance set 8 of 8 in 129 s.
  - **Slice 5:** no document claims a flow followed across functions or files, in the
    README, `docs/` or the rule files, and a claim planted in a copy is seen.
    `docs/HOW-IT-WORKS.md` says what the note is.

- [ ] **R49.8** **The target, the baseline and the README** (D82g, D82h).
  **Seam:** the committed `tests/eval/baseline.json` and `rules-measured.json`, read as
  `tests/test_eval_rebased.py` and `tests/test_rules_doc.py` read them; `eval.scorecard`.
  Behaviours:
  1. **Record.** The whole Score on both lanes, in `docs/acceptance/r49.md`, with each
     track's old and new number. *Check:* the file names both runs.
  2. The scorecard prints the count of false active Findings beside the eighth track.
  3. A test that the Python and JavaScript tracks are re-based with both numbers on both
     lanes, and a reason that names ADR-0033, is red. The baseline is written, once.
  4. A test that the baseline's eighth track is 33 or more with at most 8 false active
     Findings.
  5. `tier_disagreements` on the real table and the real measurement names nothing.
  6. The README states the track's number with what it counts, and how many Findings are in
     the inventory on the corpus. `tests/test_readme_claims.py` holds both to the baseline.

  **If 4 or 5 is red on what was measured,** nothing is bent to pass it: the phase reports
  what it reached, with the rule of each false Finding left, and the owner decides (D82h).

  _Requirements: 2.4, 2.5, 5.1, 5.3, 5.4_

  **STATUS 2026-11-22:** ⏸ 1 and 2 are done. **4 and 5 are red on what was measured, so the
  phase stops here and reports,** in [`docs/acceptance/r49.md`](../../../docs/acceptance/r49.md).
  - **4 is red:** the real-code track is 29.4 with 12 false active Findings, against 33
    and 8. It was 2.3 with 168. The twelve are named in the record, each from a rule with
    one or two Findings on the corpus.
  - **5 is red:** `tier_disagreements` names zizmor's `dangerous-triggers` and
    `template-injection`, which wait for the owner (R49.1).
  - **3 and 6 are held, not written twice.** Either decision can move a track, so the one
    re-base and the README wait for them. The committed baseline is R48's; `--compare`
    passes against it, with the Score at 76.8 on the dev machine.
  - **2:** the scorecard prints *On maintained code: N false active Findings and M true*.
  - **The order to finish in,** once the owner has answered: rows or not for the two
    zizmor rules; the re-base test and the baseline, once, on both lanes; the target's
    test at whatever the owner sets; the README and `docs/HOW-IT-WORKS.md`; the exit, the
    phase commit and the pull request out of draft.

**Exit:** the eighth track at its target on both lanes; no measured rule under the bar is
active; no track more than 2 points under its new baseline; the acceptance set passes.

### Phase R50: an existing codebase adopts the gate

- [x] **R50.1** **Measure first** (D82k, D82m). No test seam. **Record,** in the STATUS:
  1. the time to read the largest acceptance repository's tree with `git cat-file --batch`,
     against a Snapshot from disk;
  2. what `actions/checkout` leaves of the base branch at its default depth;
  3. whether OpenVEX's documents or tools name a conventional path, and the current
     specification's required fields.

  **STATUS 2026-11-23:** ✅ 1 to 3. R50 is on its own branch, stacked on R49's: it needs
  nothing R49.8 will change.

  **1. Reading a tree by git's plumbing is as fast as reading it from disk.** On the dev
  machine, the median of three, each way into a tar in memory:

  | repository | files | a Snapshot from disk | `ls-tree` and `cat-file --batch` | `git archive` |
  |---|---|---|---|---|
  | the acceptance set's `1-gate-shaped` | 303 | 0.08 s | 0.02 s | 0.01 s |
  | valvur itself | 867 | 0.12 s | 0.10 s | 0.06 s |
  | the largest corpus checkout, `fastapi` | 3,181 | 0.31 s | 0.30 s | 0.18 s |

  - **So D82k stands and its fallback is not needed:** `cat-file --batch`, which honours
    no `export-ignore` and so reads the tree a scan of the working tree would.
  - The acceptance set's own largest git repository has 303 files, too few to say much,
    so two larger trees are measured beside it. Three of the set's eight are not git
    repositories where it keeps them.

  **2. At its default depth `actions/checkout` leaves nothing of the base.** From valvur's
  own run 45066261498, a pull request's job with `fetch-depth: 1`: one fetch,
  `--depth=1 origin +<sha>:refs/remotes/pull/307/merge`, and a detached checkout of it.
  No `origin/<base>` ref exists, and the merge commit's parents are not in the object
  store. A job with `fetch-depth: 0` fetches every branch and tag. So `--new-since
  origin/main` needs `fetch-depth: 0`, or a fetch of the base ref, and R50.3's behaviour 5
  says so in the gate's own line.

  **3. OpenVEX names no path, and its required fields are few.** From the specification,
  v0.2.0 (`@context` `https://openvex.dev/ns/v0.2.0`), and `vexctl`'s README, read
  2026-11-23:
  - **No conventional path.** Neither names where a project keeps its documents.
    `vexctl`'s README uses `.openvex/*.json` in one example command, and says no more. So
    D82m stands: a document is read only where a `[[vex]]` entry names it.
  - **A document requires** `@context`, `@id`, `author`, `timestamp`, `version` and
    `statements`. `role`, `last_updated` and `tooling` are optional.
  - **A statement requires** `vulnerability` (its `name`; `@id` and `aliases` optional)
    and `status`, one of `not_affected`, `affected`, `fixed`, `under_investigation`, and
    must identify a product: `products`, each with an `@id` or `identifiers` such as a
    purl, and optional `subcomponents`. Products and the timestamp may be inherited from
    the document.
  - **`not_affected` must carry a justification or an impact statement.** The five
    justifications: `component_not_present`, `vulnerable_code_not_present`,
    `vulnerable_code_not_in_execute_path`,
    `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.
    The specification's table and its prose differ on whether a justification alone is
    required; R50.5's behaviour 5 takes either, as the statement table says.

- [x] **R50.2** **`scan --ref`: a commit's tree** (D82k).
  **Seam:** `cli.main(["scan", …, "--ref", …, "--out", …])` over `LocalRuntime`, on a git
  repository made in `tmp_path`; the result's `findings.json` and `run.json`, and the
  repository afterwards. Behaviours:
  1. A file that exists only in the ref is scanned, and a file that exists only in the
     working tree is not.
  2. Afterwards nothing under `.git` has changed, and the Workspace holds no Results Folder.
  3. `--ref` without `--out` is refused at the call. So is an `--out` that is the
     Workspace's own Results Folder.
  4. A ref that does not resolve is an error that names it.
  5. `run.json` names the ref and its commit.
  6. The ref's own `.security-scan.toml` gives the excludes.
  7. It gives the Suppressions too.
  8. A secret deleted before the ref is found by the history pass. One added after it is
     not.
  9. The CLI's help golden moves here. The MCP `scan` tool takes no ref, and
     `tests/test_cli_parity.py` says why.
  10. Once against `valvur:dev`, with `-m e2e`.

  _Requirements: 7.1, 7.3_

  **STATUS 2026-11-23:** ✅ 1 to 10 (`f8f20cf` and the container test), 14 tests in
  `tests/test_scan_ref.py` and one in `tests/test_cli_parity.py`.
  - **How it is built:** `src/valvur/reftree.py` resolves the ref and writes the commit's
    files, read by `ls-tree` and `cat-file --batch`, into a temporary directory outside
    the repository. That directory is scanned as any Workspace is, into `--out`, and is
    gone when the scan returns. design.md had the Snapshot built from the blobs in
    memory; a directory lets every host-side stage read the commit's own files, the
    project file among them, with no second code path. It is not in the repository, so
    behaviour 2 holds as written.
  - **The history pass** reads `git log <commit>` of the repository the tree came from,
    through `ScanContext.tree`, which also puts `tree: {ref, commit}` in `run.json`.
  - **Slices 5 to 8 were green as soon as 1 was:** the project file, the excludes and the
    Suppressions come with the commit's files. The history test was seen red against a
    hand-made break, reading every ref's history.
  - **Added:** a ref that begins with a dash is refused unread, so it can never be an
    option to git; and an `--out` *inside* the Workspace's Results Folder is refused too.
  - **A submodule** is named by the commit and not written, as the working tree's is not
    entered. A symbolic link is written as a link, and the File Set's own rule on links
    that leave the tree applies to it.
  - **Proof,** on the dev machine at `f8f20cf` with the test, `valvur:dev`
    `sha256:3584f7d0b651`: a commit's file and a secret deleted before it are found
    through the Scan Container, an untracked file is not, the Scan Run is complete, and
    nothing under `.git` changed.

- [x] **R50.3** **`gate --new-since`** (D82k, D82l).
  **Seam:** `cli.main(["gate", …, "--new-since", …])` over `LocalRuntime`, on a repository
  made in `tmp_path` and scanned first; the exit code and the lines printed. Behaviours:
  1. **Guard, existing.** `tests/test_gate_cache.py`'s gate tests: without the option, the
     output and the exit codes are what they were.
  2. A Finding whose Fingerprint is in the base passes the gate. One that is not fails it.
  3. A Finding suppressed in the base and active now counts as already there.
  4. The output names the base, its commit, and how many Findings were not gated on.
  5. A ref that does not resolve fails the gate with the reason, and the line names
     `fetch-depth: 0`.
  6. An incomplete Scan Run of the base fails it.
  7. A lapsed Suppression in the working tree fails it, though every Finding is old.
  8. A base Scan Run that differs from the working tree's in image, Profile or data fails
     it, naming which.
  9. A second gate on the same base runs no Scanner for it.
  10. A dataset that changed between the two makes the base scan run again.
  11. Under GitHub Actions, only the new Findings are annotations.
  12. The help golden moves here. Then once against `valvur:dev`, with `-m e2e`.

  _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  **STATUS 2026-11-23:** ✅ 1 to 12 (`ede8491` and this commit), 19 tests in
  `tests/test_gate_new_since.py`.
  - **Where each part lives.** `gate.evaluate` still reads and scans nothing: it takes a
    `Base`, the base's Results Folder, and compares. `service.base_scan` resolves the
    ref, finds or makes that result in `<cache>/base/<root commit>/<commit>/`, and the
    CLI joins the two. Behaviours 6 to 8 are tested at the reader, on a base result
    doctored by hand, since a scan cannot be made to differ on purpose.
  - **`run.json` gains `data_built`,** the instant each dataset's age is measured from,
    in seconds. An age drifts between two Scan Runs of one copy and the instant does
    not. It is beside the `data` block and not in it: the MCP reply shows that block, and
    its goldens did not move. Two instants within 5 s are one copy.
  - **The reuse rule is the comparison itself:** a base result is used when it is
    complete and does not differ from the working tree's in image, Profile or data.
    Otherwise the base is scanned again, and if the two still differ the gate fails and
    says to scan the working tree again.
  - **Added: with no git, the line says so.** Inside the image there is none (ADR-0005),
    and *names no commit* would send a reader to check a branch that exists. `scan --ref`
    and the gate both say git is not on PATH, and the gate does not then blame the
    checkout's depth. **So the gate on new Findings runs from the host shim, not from
    the image as a step:** R50.4's example and `docs/CI.md` say it.
  - **Proof,** on the dev machine at `ede8491` with this commit's slice, `valvur:dev`
    `sha256:13e7f037ff2f`: through the Scan Container a secret added after the base
    fails the gate and one the base holds does not; against `HEAD` it passes. The whole
    container suite: 100 passed and 8 skipped, and this test.
  - **The container test first failed, and the test was wrong:** its second key held a
    `9`, which is no AWS key's alphabet, so the real Gitleaks rightly reported one
    secret. The fake tool had matched it. `tests/test_scan_ref.py`'s untracked key had
    the same flaw, which made its absence prove nothing; both are valid shapes now.

- [x] **R50.4** **Shown where a team would copy it.**
  **Seam:** `docs/examples/github-actions.yml`, as `tests/test_pipeline_example.py` runs it.
  Behaviours:
  1. The example gates a pull request on new Findings, with the checkout depth it needs.
  2. `docs/CI.md` states the two limits design.md §6 states. The link check reads it.
  3. **Record.** The action's change, as a pull request in `MaverickHQ/valvur-action` (§3).
     *Check:* its number in the STATUS.
  4. **Proof.** A pull request of valvur's own, gated so, with its run.

  _Requirements: 7.7_

  **STATUS 2026-11-23:** ✅ 1 to 4 (`914c2ac`, `20e9302`).
  - **The example has a second job, and it is not the image as a step.** The gate reads
    the base with git, and the image carries none (ADR-0005). So `new-findings` checks out
    with `fetch-depth: 0`, installs valvur on the runner with `pipx`, at the version of
    the image the example already names, scans, and runs
    `valvur gate . --new-since "origin/$GITHUB_BASE_REF"`. One pin serves both jobs, so
    `prepare_release.py` is unchanged.
  - **Its two blocks are run by a container test,** in a clone whose `origin/main` is the
    base, with this tree's valvur and image: a pull request that adds nothing passes
    though the base has a key, and one that adds a key fails, naming it alone. On the dev
    machine at `8c4bfa3` with the slice, `valvur:dev` `sha256:13e7f037ff2f`.
  - **`docs/CI.md`** has a section on the gate and its two limits: a renamed file or a
    changed match counts as new; and it needs git and the base's commits, so not the
    image as a step.
  - **The action's change is MaverickHQ/valvur-action#1,** a draft for the owner: the input
    `new-since`, passed through, and the README. It is to land once 1.7.0 is published.
    It has no self-test of the input, since no published valvur has the option yet.
  - **Proof: valvur's own pull request #309, run 45095008959.** The self-scan job gained a
    step for pull requests that fetches the base branch's tip and runs the gate. Its line:
    *"gate: 0 new finding(s) at or above any since
    origin/build/r49-the-bar-on-maintained-code (4778e37); 0 were already there and were
    not gated on; 0 below the threshold; 12 suppressed"*, and *gate: passed*. It fetches
    one commit and not the history, which the gate's own message also offers.

- [x] **R50.5** **A project's own VEX** (D82m).
  **Seam:** `api.scan` over `LocalRuntime` with canned Trivy output, on a Workspace whose
  `.security-scan.toml` names an OpenVEX document; `findings.json`, `SUMMARY.md` and
  `gate.evaluate` read back. Behaviours:
  1. A `not_affected` statement for the Finding's vulnerability and its package at its
     version suppresses it. It is under *Suppressed* with the justification, the document's
     author and its timestamp.
  2. A `fixed` statement does the same.
  3. `affected` and `under_investigation` change nothing.
  4. A statement with no version is not honoured, and is reported.
  5. So is one with neither a justification nor an impact statement.
  6. A statement cannot suppress a Finding that is not a dependency vulnerability.
  7. An entry past its `expires` is reported as an expired Suppression is, and the gate
     fails at every threshold.
  8. A statement that matches nothing is listed at `low`, and the gate passes at `high`.
  9. A document that no entry names is never read: the Finding it would cover stays active.
  10. A `path` that leaves the Workspace, or follows a link out of it, is refused at the
      call.
  11. A document that is not OpenVEX is an input error that names it. The Scan Run does not
      go on without it.
  12. `valvur doctor` and the JSON Schema know `[[vex]]`.
  13. No tool and no command writes or prints a VEX statement. The test is the one that
      holds `scan_and_fix`'s absence, widened.
  14. The skill's rule on Suppressions names `[[vex]]`, in every copy `sync_skill.py` writes.

  **Added by the pass:** 6, 10 and 11. Each is a way a document could lower a Finding it
  should not, or fail in silence.

  _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  **STATUS 2026-11-23:** ✅ 1 to 14 (`0702bdf`), 28 tests in `tests/test_vex.py`.
  - **`src/valvur/vex.py`** reads each document a `[[vex]]` entry names and applies its
    statements in the `suppress` stage, after the Suppressions: a Finding accepted both
    ways keeps the Suppression's reason, which a person wrote for this project.
  - **Refused before any Scanner runs:** a path outside the project, absolute, or through
    a link that leaves it; a file that is not JSON, or has no `@context` under
    `https://openvex.dev/ns`, or no `statements`; and an entry with no `expires`. The
    last was added: the schema asks for the date, and a scan does not read the schema.
  - **Products are compared as package URLs,** without qualifiers, and a PyPI name in
    its normal form. A statement for another version of the package is another product:
    it is neither honoured nor reported, and counts as matching nothing.
  - **Two rules of valvur's own,** both at `low` and both active:
    `valvur.vex.not-honoured`, for a statement that would apply and names no version or
    gives no reason, and `valvur.vex.unused`, one Finding a document, counting its
    statements that match nothing. A statement that matches and says `affected` is not
    counted so. A lapsed entry is `valvur.suppression.expired`, which the gate already
    fails on at every threshold.
  - **Narrower than design.md in one way:** the unused count is a Finding in the list, not
    a line under *Suppressed* in `SUMMARY.md`. It is in `findings.json`, where a gate and
    an agent read it.
  - **An alias counts:** a statement that names the Finding's GHSA ID applies to its CVE.
  - **Behaviour 13 widens the forbidden tool names** with `vex`, and holds that no command
    is named for it and that `valvur suppress` prints no VEX.
  - **Not yet run through the container:** the seam is canned Trivy output, as the task
    writes it. Trivy's own package URLs reach `Dependency.purl` today; the phase's exit
    runs the whole container suite.

- [x] **R50.6** **Ranking reads a declaration** (D82n).
  **Seam:** `api.scan` over `LocalRuntime`, on a Workspace whose `.security-scan.toml` holds
  `[[context]]`; the order of `findings.json` and of `REMEDIATION.md`. Behaviours:
  1. **Guard, existing.** `tests/test_ranking.py`: with no declaration, every order is what
     it was.
  2. Of two Findings in one tier, the one under a declared path ranks first.
  3. A Finding in a higher tier still outranks a declared one in a lower tier.
  4. A declaration that names every path gives the order of no declaration.
  5. The raised item says which declaration raised it, in the word *declaration*. The
     sentence is the contract.
  6. An `exposure` or `data` value outside the two is refused by `doctor` and the schema.
  7. No output calls the raise analysis or reachability. Seen red against a planted word.

  _Requirements: 11.1, 11.2, 11.3_

  **STATUS 2026-11-23:** ✅ 1 to 7 (`db5853d`), 14 tests in `tests/test_declared_context.py`.
  - **One key in the sort, after the tier:** a Finding whose path is under a declared
    path, by whole segments, sorts first. `tests/test_ranking.py` passes unchanged.
  - **The Finding carries what the project said,** as `declaration` in `findings.json`,
    present only when set: "`services/api/` is internet-facing" or "… holds sensitive
    data". Its item in `REMEDIATION.md` ends *Ranked ahead in its tier, raised by this
    project's declaration: … (`.security-scan.toml`)*.
  - **A scan passes over an entry that says anything else;** `doctor` and the schema name
    it. A wrong declaration can only fail to raise, so it is not a refusal.

- [x] **R50.7** **One dependency Finding lists its lockfiles** (D82n).
  **Seam:** `api.scan` over `LocalRuntime` with canned Trivy output for two lockfiles;
  `findings.json`, `results.sarif` and the MCP reply. Behaviours:
  1. An advisory found through two lockfiles is one Finding with both in `paths`, sorted.
     Its Fingerprint is the literal the test holds from before the change.
  2. `path` is what it was.
  3. SARIF carries a location for each.
  4. The reply carries `paths`, its snapshot moves in this commit, and its schema is 2.

  _Requirements: 11.4_

  **STATUS 2026-11-23:** ✅ 1 to 4, 5 tests in `tests/test_lockfile_paths.py`.
  - **`Dependency.paths`,** set where Findings of one Fingerprint are merged, and only when
    they name more than one lockfile: a Finding through one has no such key, so no
    golden of a scan moved. Sorted; the Finding's own `path` is the first reported, as
    before, and the Fingerprint is the literal written down before the change.
  - **SARIF** gives the Finding's path first and then each other lockfile as a location.
  - **The reply that carries it is `findings`'s,** which lists Findings; `scan`'s reply
    lists none. The entry gains `paths`, the tools snapshot
    (`tests/fixtures/mcp/tools-list.json`) moves by that one property, and the reply
    schema is 2 as it was: the change is additive.

**Exit:** the acceptance set passes; the Score unchanged; the proof in R50.4 recorded.

**STATUS 2026-11-23:** ✅ the exit is measured, in [`docs/acceptance/r50.md`](../../../docs/acceptance/r50.md).
- **On the dev machine at `9990f8e`:** the acceptance set 8 of 8; the Score 76.8 with
  `--compare` passing, every track where R49 left it; the whole container suite, 102
  passed and 8 skipped.
- **The proof:** valvur's own pull request #309, run 45095008959.
- **Left for the owner:** MaverickHQ/valvur-action#1, and R49.8 on #308.

### Phase R51: the tools around it

- [x] **R51.1** **Measure first** (D82o). No test seam. **Record,** in the STATUS:
  1. the current edition of each OWASP list, read from OWASP's own pages, with the date;
  2. every source of a rule ID, and which can be listed from this repository;
  3. whether Trivy's and OSV-Scanner's output carries a CWE for an advisory.

  **STATUS 2026-11-23:** ✅ 1 to 3. R51 is on its own branch, stacked on R50's.

  **1. The editions, each read from OWASP's own pages on 2026-11-23.**

  | list | edition | read from |
  |---|---|---|
  | OWASP Top 10 | **2025**, released; 2021 is the previous one | `owasp.org/www-project-top-ten/`, then `top10.owasp.org/2025` |
  | OWASP Top 10 for LLM Applications | **2025**, dated 2024-11-17 | `genai.owasp.org/llm-top-10/` |
  | OWASP Top 10 for Agentic Applications | **2026**, dated December 2025 | `genai.owasp.org`, its PDF |
  | Agentic AI: Threats and Mitigations | **version 1.1**, December 2025 | `genai.owasp.org`, its PDF |

  - **Top 10:2025:** A01 Broken Access Control, A02 Security Misconfiguration, A03
    Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06
    Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures,
    A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions.
    **It is not the list design.md was written against:** injection was A03 in 2021 and is
    A05 now, and supply chain is a category of its own.
  - **LLM 2025:** LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03
    Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06
    Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses,
    LLM09 Misinformation, LLM10 Unbounded Consumption.
  - **Agentic 2026:** ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03
    Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05
    Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure
    Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust
    Exploitation, ASI10 Rogue Agents.
  - **Threats and Mitigations 1.1** numbers its threats T1 to T17. Sixteen names were read
    from the PDF and T14's was not. **The mapping uses the Agentic Top 10 and not this
    one:** it is the list OWASP publishes to be cited, both are of December 2025, and a
    mapping to a list with one name unread would not be honest. It is named in the file
    as read and not mapped to.
  - The two PDFs were read on the dev machine with `pypdf`: this Mac has no PDF reader.

  **2. Seven sources of a rule ID, three of them listable here.**
  - **Listable:** valvur's Opengrep rules, 24 IDs in `rules/*.yaml`; the vendored rules,
    4, in `rules/vendor/gitlab/manifest.json`; and the IDs valvur's own code gives its
    Checks and notes, 36 `valvur.*` strings in `src/valvur`.
  - **Not listable:** Gitleaks' rules, 222 in its own configuration at v8.30.1; Checkov's
    checks; zizmor's audits; and Trivy's and OSV-Scanner's advisory IDs, which have no end.
    Each of these Scanners gets one entry, as design.md says.

  **3. Both dependency Scanners carry a CWE, and no adapter reads it today.** In the
  committed goldens: Trivy gives `CweIDs` for 75 of 75 advisories; OSV-Scanner gives
  `database_specific.cwe_ids` for 88 of 149. So R51.2's behaviour 6 holds for both, where
  the advisory has one.

- [x] **R51.2** **One mapping, four levels** (D82o).
  **Seam:** `identifiers.of(scanner, rule, finding_class)`, the new module's one function;
  the adapters' parse of canned output, for the advisory's CWE. Behaviours:
  1. A rule's own entry is found.
  2. With none, its prefix's is. With neither, its Scanner's. With none of the three, its
     class's. One slice each.
  3. An entry of `none` without a reason is refused when the file is read.
  4. Each list in the file names its edition and the date it was read.
  5. A test that every rule and Check valvur writes, and every vendored rule, has an entry
     by ID is red, naming each. The file is filled, and it is green.
  6. A dependency Finding takes its advisory's CWE where R51.1 found the Scanner gives one.

  **STATUS 2026-11-23:** ✅ 1 to 6, in `tests/test_identifiers.py`, 16 tests.
  - **The file** is `src/valvur/data/identifiers.toml`, read by `src/valvur/identifiers.py`
    (layer `core`). 59 entries by ID: the 28 rules in `rules/` and the 31 IDs valvur's own
    code gives its Checks and notes. Three by prefix, six by Scanner, six by Finding Class.
    A file with a `none` and no reason, a category in no list, a list with no edition or no
    date, or a CWE not written `CWE-n` is refused whole when it is read.
  - **A rule with a CWE sits in the Top 10 category whose own list holds that CWE.** The
    24 CWEs the file names were looked up on OWASP's ten category pages for 2025, twice:
    read by the fetching agent, then counted in the pages' raw HTML on the dev machine.
    The two agree on all 24. CWE-1321 is in none of the ten lists, so an advisory that
    names it alone takes its Scanner's category. A test holds every entry to that table,
    and another holds an entry's CWE to the one its rule file gives Opengrep.
  - **The LLM and agentic categories are the executor's reading,** for the owner to
    overrule: neither list publishes a CWE mapping to look them up in. No CWE is given to
    a Check where none names the thing without stretching one.
  - **21 entries say `none`, each with its reason:** 17 by ID (the notes about what
    valvur read, the licence Checks, the Suppression and VEX notes, the model-call mark),
    the licence prefix, Syft, and the licence and static-analysis classes.
  - **The advisory's CWE:** `adapters.base.cwes` reads Trivy's `CweIDs` and OSV-Scanner's
    `database_specific.cwe_ids`. From the goldens: 75 of 75 and 88 of 149, as measured.
    No Fingerprint moves, which a test holds for Trivy's 75.
  - Nothing reads `identifiers.of` yet: R51.3 puts it in the outputs.

  _Requirements: 8.1, 8.2_

- [x] **R51.3** **The identifiers in every output.**
  **Seam:** `api.scan` over `LocalRuntime`; `findings.json`, `results.sarif`, `SUMMARY.md`;
  the MCP server over stdio; `cli.main(["findings", …])`. Behaviours:
  1. **Guard, existing.** `tests/test_identity.py` and the goldens: every Fingerprint is
     what it was, and `fp_version` is 1.
  2. An Opengrep Finding in `findings.json` carries `owasp` beside `cwe`. The schema is 1.
  3. A Gitleaks Finding carries its Scanner's entry.
  4. SARIF carries the taxonomies and each rule's relationships, and validates against the
     vendored 2.1.0 schema.
  5. SARIF carries the tags.
  6. The reply carries them, its snapshot moves in this commit, and its schema is 2.
  7. `SUMMARY.md` has the table, and it is bounded: a made run with every category still
     fits the file's limit.
  8. `findings --owasp` filters, in the CLI and in the tool.

  *Closes with:* the Score, unchanged.

  **STATUS 2026-11-23:** ✅ 1 to 8, in `tests/test_identifiers_in_outputs.py`, 17 tests.
  - **Where it is applied:** a pipeline stage, `identifiers`, after `suppress` (the last
    stage that adds a Finding) and so after `merged`, which folds two rules on one line by
    the CWE their Scanner gave: a mapped CWE folds nothing. A CWE a Scanner reported is
    kept. `Finding.owasp` is new, and no Fingerprint is read or written.
  - **`findings.json`:** `owasp` beside `cwe`, each absent when empty. Schema 1.
  - **SARIF:** `run.taxonomies` for CWE and for each OWASP list the run is mapped to, with
    the edition as the taxonomy's version and only the taxa the run uses; each rule's
    `relationships`; the tags `external/cwe/cwe-89` and `external/owasp/a05:2025`. It
    validates against the vendored 2.1.0 schema.
  - **The reply:** `cwe` and `owasp` on each entry, and one Finding in full says *mapped
    to* with each category's name, list and edition. Its schema is 2.
  - **`findings --owasp`**, in the CLI and the tool. A category in no list is refused with
    the editions it could be: `A03:2021` matching nothing would read as *no injection here*.
  - **`SUMMARY.md`, changed from the design:** the table is one row per list, so it is
    three rows at most, and it is written when it sorts something: two categories or more,
    or more active Findings than *Most urgent* shows. The design said *whenever there are
    active Findings*. Measured, that took a two-Finding repository's summary from 45 lines
    to 53, past R5.2's one screen, to say *Injection 1* under the one entry it counted.
    **The owner may overrule this.**
  - **A dependency Finding** keeps its advisory's CWE and takes its Scanner's category,
    A03:2025, as the design says: the fix is an upgrade, whatever the weakness.
  - **Moved with it:** the tools snapshot, `findings --help`, one reply golden, the
    deferred-import list, the pipeline's pinned order, the skill's tools reference.
  - **The Score is unchanged:** 76.8 on the dev machine at `1c442cb`, `valvur:dev`
    `sha256:9fe8d10ba15a`, every track where it was, `--compare` passing, 401 s. The
    acceptance set passes, 8 of 8 in 133 s.
  - **The container suite:** 103 passed and 8 skipped at `93b9a46`, 526 s. At `1c442cb` two
    failed, and not on the change: the dev machine's Docker volume was 96% full of this
    session's build cache and Syft could not save the image. 24 GB pruned; both pass.

  _Requirements: 8.3, 8.6, 8.7_

- [x] **R51.4** **The mapping as a page, and the wording.**
  **Seam:** `generate_docs.py`'s `main`, as `tests/test_generated_docs.py` drives it; a
  wording test over the documents and over one scan's outputs. Behaviours:
  1. The page lists every rule with its identifiers.
  2. It lists each list's categories that nothing maps to.
  3. `--check` fails on a page that is not current.
  4. *covers*, *complies* and *certified* beside a list's name are refused, in a document
     and in an output. Seen red against a planted sentence in each.

  **STATUS 2026-11-23:** ✅ 1 to 4, in `tests/test_owasp_mapping_page.py`.
  - **The page** is `docs/OWASP-MAPPING.md`, three generated blocks in
    `scripts/generate_docs.py`: the lists with their editions and the day read, every
    entry at each of the four levels (59 by ID), and each list's categories that no entry
    is mapped to. Those are 3 of the Top 10's, 4 of the LLM list's and 5 of the agentic
    list's. It is linked from the README's and `docs/`'s indexes.
  - **`--check`:** `main` takes the files it reads, so the test gives it a copy of the page
    with one cell changed and it names the block and exits 1.
  - **The wording** is `tests/wording.py`'s `claims`: each sentence that names a list or
    one of its IDs beside a word of coverage, compliance or certification. A word set in
    emphasis or in code is a mention, which is how a document states the rule, and
    valvur's own *coverage note* is not a claim. It runs over 24 documents, the tools
    snapshot and the mapping file, and over one scan's `SUMMARY.md`, `REMEDIATION.md`,
    `findings.json`, `results.sarif` and reply.
  - **Seen red, and not only on the planted sentences:** R51.3 had written *"A mapping is
    not coverage"* into SARIF's taxonomy description. A denial that names the thing is
    one edit from a claim, so it, the tool's description and the mapping file's comment
    now say what a mapping is and leave the word out.

  _Requirements: 8.4, 8.5_

- [x] **R51.5** **The imports, measured** (D82p).
  **Seam:** `imports.yml` as a file, read as `tests/test_eval_workflow.py` reads its own.
  Behaviours:
  1. Its only trigger is dispatch, it holds no secret and no grant beyond reading the
     repository, and both tools are pinned by digest.
  2. **Proof.** A dispatched run imports a scan of the fixture into DefectDojo and
     Dependency-Track. `docs/acceptance/r51.md` records what arrived and what was lost.

  **STATUS 2026-11-23:** ✅ 1, in `tests/test_imports_workflow.py`. ✅ 2 as a measurement,
  **on the dev machine and not by a dispatched run** (D82p's fallback, for another reason).
  - **Why not dispatched:** GitHub dispatches a workflow only once it is on the default
    branch, and a phase lands by the owner's fast-forward. The measurement ran the
    workflow's own compose files and script on the dev machine, arm64. **Its first
    dispatched run, on amd64, is owed after the landing,** and the tracker says so.
  - **The pieces:** `.github/workflows/imports.yml`; `.github/imports/*.compose.yml`, four
    images for DefectDojo 3.5.202 and two for Dependency-Track 5.2.2, each pinned by
    digest and listening on localhost alone; `scripts/imports_measure.py`, standard library
    alone. DefectDojo's two keys and Dependency-Track's admin password are made in the
    job for that run: no key is written in the repository.
  - **The fixture gains, in the job's copy,** a Suppression and a `.trivyignore` entry:
    what a real project sends and the fixture lacked.
  - **What arrived,** in `docs/acceptance/r51.md`: DefectDojo keeps severity, CWE, the
    OWASP tags, file and line on all 149 findings. **One live Finding arrived hidden,** as
    an inactive false positive: the one a `.trivyignore` named and valvur did not accept.
    26 arrive without the Fingerprint. Deduplication is off as installed, so a second
    import doubles the findings and a re-import does not. Dependency-Track loses nothing.
  - Both importers' sources were read at their release tags for what they take, before
    anything was started: the hidden Finding was predicted from DefectDojo's parser and
    then measured.

  _Requirements: 9.1_

- [x] **R51.6** **CycloneDX, validated.**
  **Seam:** `api.scan` with the SBOM asked for, as `tests/test_sbom_opt_in.py` drives it.
  Behaviours:
  1. A document with a required field removed fails validation against the vendored schema
     of the version it declares.
  2. **Guard.** The scan's `sbom.cdx.json` validates. Then once against `valvur:dev`, with
     Syft itself (`-m e2e`).

  **STATUS 2026-11-23:** ✅ 1 and 2, in `tests/test_sbom_schema.py`.
  - **The schema** is CycloneDX 1.7's, the version Syft 1.57.1 writes, with the three it
    refers to (SPDX's licence list, JSF, the cryptography definitions), vendored as
    published from the specification's tag `1.7.2`, Apache-2.0, under
    `tests/fixtures/schema/cyclonedx-1.7/`, about 410 KB.
  - **`tests/cyclonedx.py`** validates a document against the schema of its own
    `specVersion` and refuses, by name, a version with none vendored: a Syft upgrade that
    writes 1.8 fails here.
  - **It bites three ways:** a removed `bomFormat`, a component with no name, and a licence
    that is no SPDX ID each fail. The last shows the reference to SPDX's list resolves.
  - **The guard:** the SBOM a scan writes from Syft's committed golden validates, and so
    does what Syft itself writes in `valvur:dev` for a two-package workspace (the container
    test, passed on the dev machine at `93b9a46`).

  _Requirements: 9.3_

- [x] **R51.7** **The corrections and the guides.**
  **Seam:** as R51.3. Behaviours:
  1. One slice for each field R51.5 found lost: it is carried inside SARIF or CycloneDX,
     where the importing tool reads it.
  2. **Record.** `docs/DEFECTDOJO.md` and `docs/DEPENDENCY-TRACK.md`, each showing the
     user's own step. *Check:* the link check, and R51.8.
  3. **Guard, existing.** The constraint tests on egress. *Check:* `egress.py` and
     `verify-offline.py` have no diff in the phase.

  **STATUS 2026-11-23:** ✅ 1 to 3.
  - **One field was lost that a user needs, and it is corrected:** whether a Finding is
    live. A project's own ignore that valvur did not accept was a SARIF suppression with
    `status: rejected`, and DefectDojo filed the Finding as an inactive false positive. It
    is now `properties.ignoredBy` on the result, and a `suppressions` entry means an
    accepted risk, always. `tests/test_sarif_for_importers.py`, seen red, and
    `tests/test_ignored_by.py` restated. This amends D77c's form, not its decision:
    the ignore is still named and still not accepted. `findings.json` is unchanged.
  - **Not corrected, each with its reason, and each in the guide:**
    - *The Fingerprint is missing on a Finding found through two lockfiles.* SARIF says a
      result has several locations when each needs the change, which is the case. One
      location and the rest as related ones would keep the id and lose the second
      lockfile in DefectDojo, which is the worse loss. A re-import matches without it.
    - *An accepted risk arrives marked a false positive.* That is DefectDojo's reading of
      SARIF's own field for a suppression, and there is no other field to say it in.
    - *A second import doubles the findings.* DefectDojo installs with deduplication off.
      The guide's step is a re-import.
    - *A dependency's package and version have no field.* DefectDojo's SARIF import has
      none to put them in. They are in the title.
  - **Dependency-Track lost nothing,** so `sbom.cdx.json` is unchanged.
  - **The guides:** `docs/DEFECTDOJO.md` and `docs/DEPENDENCY-TRACK.md`, each with the
    user's own `curl` step and token, and each step the one the measurement ran: a token
    for DefectDojo, an API key on the *Automation* team for Dependency-Track, which as
    installed lacks the permission to create a project. Statements that were not
    measured were taken out before the commit.
  - **Egress:** `git diff 815943c -- src/valvur/egress.py scripts/verify-offline.py` is
    empty, and the constraint tests pass in the gate.

  _Requirements: 9.2, 9.4_

- [x] **R51.8** **Measured again.** **Proof:** the dispatched workflow imports both again. A
  test holds each number in the two guides to `docs/acceptance/r51.md`.

  **STATUS 2026-11-23:** ✅, measured on the dev machine as R51.5 was, on fresh instances
  of both tools, with the script as it is committed. **The dispatched run is still owed
  after the landing.**
  - **DefectDojo:** 148 live Findings sent and 148 arrive active, where the first
    measurement had 147: the one a `.trivyignore` names arrives active. Every other
    number is as it was: 149 findings, severity and file on all, CWE on 123, the OWASP
    tags on 146, a line on 53, the Fingerprint on 123. A re-import adds none.
  - **Dependency-Track:** as it was, 15 components from 16, the 11 distinct packages each
    with its package URL. This time uploaded with an API key on the *Automation* team, as
    a pipeline does. As installed that team lacks `PROJECT_CREATION_UPLOAD`, which the
    guide says.
  - **The test:** `tests/test_import_guides.py`. Each guide's table is the record's own,
    byte for byte, between the same markers, and no count stands in a guide's prose that
    the record's table does not hold. Seen red on the empty tables.

  _Requirements: 9.5_

- [ ] **R51.9** 👤 **Each agent client, run or said not to be.**
  **Seam:** `valvur doctor --client`, as `tests/test_doctor_clients.py` drives it, for a
  snippet that proved wrong. The rest are records. Behaviours:
  1. **Record.** Codex, Cursor and VS Code each scan the fixture through valvur, with the
     client's version and the date.
  2. **Record.** Each other client is run, or marked *not run* with the reason, dated.
     *Check:* a test that every client `docs/AGENTS.md` documents has one of the two.
  3. A snippet that proved wrong: a failing case first, then the correction, in the commit
     that records the run.

  _Requirements: 12.1, 12.2, 12.3, 12.4_

**Exit:** every rule mapped or marked `none`; both imports measured twice; the Score
unchanged on both lanes.

**STATUS 2026-11-23:** measured, and **the phase stays open at R51.9,** the owner's. On the
dev machine at `3c00bee`: 59 entries by ID, 17 of them `none` with a reason; both imports
measured twice; the Score 76.8 on every track with `--compare` passing; the acceptance set
8 of 8; the container suite 103 passed and 8 skipped. The amd64 lane is #310's checks. The
record is `docs/acceptance/r51.md`. The first dispatched run of `imports.yml` is owed after
the landing.

### Phase R52: the evidence an adopter asks for

- [x] **R52.1** **Measure first** (D82q, D82r). No test seam. **Record,** in the STATUS:
  1. each requirement of SLSA's Build track at v1.0, with the release's evidence for it or
     its absence;
  2. the OpenVEX fields a consumer's tool requires, read from the specification;
  3. what GitHub's API gives for each number the Health record shows, and for how long.

  **STATUS 2026-11-23:** ✅ 1 to 3. R52 is on its own branch, stacked on R51's.

  **1. SLSA's Build track, read from `slsa.dev` on 2026-11-23.** The current specification
  is **1.2**, and 1.0 and 1.1 are marked retired. The Build track's requirements are the
  same rows: 1.1 changed attestation formats and 1.2 added a Source track. So
  `SECURITY.md` names the level by the current version, and the design's *at v1.0* is
  amended to *as 1.0 defined it and 1.2 keeps it*. The rows, with `release.yml`'s evidence:

  | requirement | levels | the release's evidence |
  |---|---|---|
  | Choose an appropriate build platform | 1 to 3 | GitHub Actions, on GitHub's own runners |
  | Follow a consistent build process | 1 to 3 | one workflow, `release.yml`, for every release (ADR-0020) |
  | Distribute provenance | 1 to 3 | in the registry beside the image (`push-to-registry`), attached to the release as two `.intoto.jsonl` files, and on PyPI for the distributions |
  | Provenance exists | 1 to 3 | `actions/attest-build-provenance`, predicate `https://slsa.dev/provenance/v1`, on the image's digest and on the wheel and sdist |
  | Provenance is authentic | 2, 3 | signed through Sigstore with the workflow's own identity; `artifact` verifies it with `gh attestation verify` before anything is promoted |
  | Hosted | 2, 3 | every job is on `ubuntu-26.04` or `ubuntu-26.04-arm`; none is self-hosted |
  | Provenance is unforgeable | 3 | **absent.** `stage` holds `id-token: write` beside its own build steps, so the signing identity is within reach of steps the workflow defines |
  | Isolated | 3 | **absent.** The build is steps of the calling workflow, with a shared build cache (`type=gha`), not a builder run apart from it |

  **So the level is Build L2,** as the design expected, and L3 needs a builder isolated
  from the workflow that calls it, which D66 left for 2.0.

  **2. OpenVEX, read from `github.com/openvex/spec` on 2026-11-23.** Version 0.2.0,
  `@context` `https://openvex.dev/ns/v0.2.0`, with a JSON schema at the repository's root.
  - **A document must have** `@context`, `@id`, `author`, `timestamp`, `version` (an
    integer from 1) and at least one statement.
  - **A statement must have** `vulnerability`, whose one required field is `name`, and
    `status`. The schema does not require `products`; the specification's text does, so
    every statement names one.
  - **Status:** `not_affected` needs a `justification` or an `impact_statement`;
    `affected` needs an `action_statement`; `fixed` and `under_investigation` need nothing.
  - **Justifications:** `component_not_present`, `vulnerable_code_not_present`,
    `vulnerable_code_not_in_execute_path`,
    `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.
  - **A product** is an `@id` or `identifiers` (`purl`, `cpe22`, `cpe23`), with optional
    `hashes` and `subcomponents`. **The specification does not say how an image by digest
    is written.** `pkg:oci/…@sha256:…` is the package-URL type for one; R52.2 uses it
    and says so.
  - **`statements` must hold at least one,** so R52.2's behaviour 5, *a document with no
    statements*, is not a valid document. **R52.2 amends it:** verdicts with nothing to
    say give no document, and the release says there is none to attach.
  - **The specification defines no matching algorithm** for a consumer.

  **3. What GitHub's API keeps, read on 2026-11-23.** The repository keeps artifacts and
  logs 90 days, its maximum.

  | number | where it is recorded | kept | read with |
  |---|---|---|---|
  | the Score by track | the artifact `eval-report`, from `eval.yml` | 90 days; 7 runs on `main` held, the oldest of 2026-10-05 | a list anyone may read; **the download needs a token** (401 without) |
  | the image's verdict by day | the artifact `image-gate-published`, from the nightly | **30 days,** by the workflow's own setting; 29 held | the same |
  | the mutation score | **nowhere but the run's log**: `mutation.yml` prints it and uploads nothing | 90 days, as a log | **nothing a script should parse** |
  | time to heal | pull requests, commits and releases | for good | `heal_report.py`, which is on R46's branch below this one |

  - **So R52.5 adds an artifact to `mutation.yml`,** one small JSON file, before it can
    show the score. That is a slice of its own, first.
  - **`health.yml` is given `actions: read` beside `issues: write`.** A download without
    a token is refused, 401. Whether a job's token with no `actions` grant may download
    from a public repository could not be measured from here, since a workflow runs only
    once it has landed. Behaviour 8 said *`issues: write` and nothing more*, and is
    amended to those two grants, which are the watchdog's and are known to work.
  - **The image's verdict by day reaches back 30 days,** and the record says so.

- [x] **R52.2** **The release's OpenVEX document** (D82q).
  **Seam:** `scripts/image_vex.py`'s `main`, over verdict files as `image_gate.py` writes
  them, as `tests/test_release_notes_image.py` drives its script. Every slice's document is
  validated against OpenVEX's schema, vendored. Behaviours:
  1. One verdict with one entry that has no fixed version gives one statement,
     `under_investigation`, for the image by digest.
  2. An accepted entry is `affected`, with the acceptance's reason and expiry.
  3. An accepted entry whose acceptance gives one of OpenVEX's justifications is
     `not_affected`.
  4. Two architectures' verdicts give one document. An entry on one alone names it.
  5. Verdicts with nothing to say give a document with no statements.
  6. The same verdicts and the same timestamp give the same bytes.
  7. A verdict that cannot be read exits 2 and writes nothing.

  **STATUS 2026-11-23:** ✅ 1 to 7, with 5 amended, in `tests/test_image_vex.py`, 9 tests,
  every document validated against OpenVEX 0.2.0's schema, vendored (CC0-1.0).
  - **`scripts/image_vex.py`,** standard library alone, takes the verdicts as
    `release_notes_image.py` does, and `--image`, `--digest`, `--release`, `--timestamp`.
    It reads `.github/image-accepted.yaml` for an acceptance's reason and writes nothing
    there.
  - **The product** is the image by digest as `pkg:oci/valvur@sha256%3A…?repository_url=…`,
    the package-URL form, since OpenVEX names none. The package is its subcomponent, by
    Trivy's kind: `pkg:apk/alpine/…`, `pkg:pypi/…`, `pkg:golang/…`.
  - **An entry on one architecture alone** has the image for that architecture as its
    product, `&arch=arm64`, and its notes say *On arm64 alone*.
  - **5, amended as R52.1 found:** OpenVEX requires at least one statement, so verdicts
    with nothing to say give **no document**. The run exits 0, writes nothing and says so.
    1.6.1's image has nothing accepted, so whether a release has a document depends on
    whether its image has a vulnerability with no fix.
  - **`not_affected` is the owner's alone.** It needs a `justification` field in the
    owner's entry, one of OpenVEX's five. Any other word is refused, exit 2, nothing
    written. The gate reads that file line by line and already passes the field through.
    **For the owner:** the field is new to `.github/image-accepted.yaml`, whose header
    this executor does not edit; R52.3's diff says so.
  - **Deterministic:** statements are sorted by advisory, package and version, so the
    order of the arguments and of a verdict's entries changes no byte.
  - The tests for 2 to 7 were written after the script, so each was checked to bite: five
    deliberate breaks of the script, each caught by at least one test.

  _Requirements: 14.1_

- [ ] **R52.3** 👤 **Attached and attested** (D82q).
  **Seam:** `release.yml` as a file, read as the release constraint tests read it.
  Behaviours:
  1. **The diff is shown to the owner first** (§0, item 4). Nothing below starts without it.
  2. The constraint tests are restated for the new steps and their grants, and are red.
  3. `notes` writes the document and `promote` attaches it.
  4. The document and the four SBOMs are attested on the image's digest, and `artifact`
     verifies each.
  5. zizmor finds nothing, at the auditor persona too.
  6. **Proof.** A rehearsal, cancelled at the brake, shows the five attestations.

  _Requirements: 14.1_

- [ ] **R52.4** **The level, and who can release.**
  **Seam:** the documents, read as `tests/test_best_practices.py` reads its own. Behaviours:
  1. `SECURITY.md` states the SLSA Build level R52.1 found, with each requirement's
     evidence. A test refuses a higher level's name, seen red against a planted one.
  2. **Record.** `MAINTAINERS.md` says who can release today and what continues without
     them. *Check:* the link check.
  3. `docs/BEST-PRACTICES.md` is current with the tree, and the form is in §3.

  _Requirements: 14.2, 14.3, 14.5_

- [ ] **R52.5** **The Health record** (D82r).
  **Seam:** `scripts/health.py`'s `main`, with GitHub faked through `tests/fake_github.py`;
  the issue it leaves there. `health.yml` as a file. Behaviours:
  1. The issue's body gives the Score by track, from the recorded runs.
  2. It gives the published image's verdict by day.
  3. It gives the mutation score.
  4. A number that could not be read keeps its last value and date, and says so.
  5. Time to heal is marked absent until `heal_report.py` exists.
  6. A second run rewrites the one issue and opens no other.
  7. An issue of the same title that the workflow's own account did not open is neither read
     nor written.
  8. `health.yml` runs daily, holds `issues: write` and nothing more, pins its actions, and
     the watchdog reads its schedule.
  9. The README links to the issue.

  **Added by the pass:** 7. The repository is public, and behaviour 4 reads the issue's
  last values back.

  _Requirements: 14.4_

- [ ] **R52.6** 👤 **A first use, watched.** No test seam. **Record:**
  1. `docs/history/usability-gate.md` holds Gate 2: each stop, question and guess, timed.
  2. Each is fixed, by a task with its own failing test first, or recorded as accepted with
     the reason.
  3. `docs/CLI.md`'s first-run time and sizes are the ones measured on that run.

  _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

**Exit:** a release carries its VEX document and five attestations; `SECURITY.md` states the
level; the Health record has run for a week; Gate 2 is recorded.

---

## 3. The owner queue for this spec

R48.1 adds one row to the main list's §8 that points here. Nothing here blocks a test.

| item | ready after | what the owner does |
|---|---|---|
| three accounts | before R51.9 | sign in to Codex, Cursor and VS Code's agent mode on the Mac, or say which are not to be run |
| the action's pull request | R50.4 | land it in `MaverickHQ/valvur-action`, and tag it |
| the edit to `release.yml` | R52.3 | approve the diff, shown first |
| the target of the real-code track | R49.8 | 33 with at most 8 false was set (D82h); 29.4 with 12 is reached, each of the 12 from a rule with one or two Findings. Accept it, set another, or say which single Findings to act on. `docs/acceptance/r49.md` lists them |
| the JavaScript TLS rule | R49.6 | not shipped, 0 true of 307 on maintained code. Say whether `benchmark/` and `benchmarks/` are test material, with which it could ship listed in tests |
| `--taint-intrafile` | R49.7 | not adopted by Requirement 6.2's condition. It catches all 34 generated flows; say whether that is worth five Findings to judge |
| two of zizmor's rules under the bar | R49.1 | decide `dangerous-triggers` and `template-injection`: re-base the infrastructure track (95.0 to 85.0), leave them active, or overrule the labels. R49.1's STATUS has the numbers |
| one line of `release.yml` | R48.6 | line 157 drops its second argument, `python:3.12-alpine3.24`, as `ci.yml`'s step did; then the entry leaves `tests/test_no_moving_target.py`'s list, which fails until it does |
| pin the Health issue | R52.5 | pin it in the repository, once |
| the OpenSSF form | R52.4 | paste `docs/BEST-PRACTICES.md` into bestpractices.dev; the badge is added once it passes |
| a person who has not used valvur | before R52.6 | find one, and an hour |
| a second maintainer | any time | `MAINTAINERS.md`'s five steps |
| releases 1.7.0 and 1.8.0 | R49 and R51 landed | the tag and the brake, as always |

---

## 4. What this does not change

- **`CLAUDE.md` §3, §4 and §10 hold.** Nothing new is fetched in the `offline` Profile.
  valvur uploads nothing. No tool writes to a Workspace, a Suppression or a VEX statement.
- **No rule is deleted.** A demoted rule's Findings are still in `findings.json`, one flag
  away.
- **`fp_version` stays 1,** `findings.json` schema 1, the reply schema 2 and the protocol 2.
  Every field added is optional.
- **A gate without `--new-since` behaves as it does today.**
- **The corpus keeps its 48 projects at their pins.**
- **The constraint suite stays at 54 tests.** New tests go in new files.
