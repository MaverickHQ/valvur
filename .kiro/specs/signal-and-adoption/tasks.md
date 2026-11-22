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

- [ ] **R48.3** **Checkov and zizmor, judged in their own table** (D82a, D82b).
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

- [ ] **R48.4** **`docs/RULES.md` lists every rule that fired, with its two measurements**
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

- [ ] **R48.7** **The hostile fixtures are stored under names no agent loads.**
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

**Exit:** the Score unchanged on every track, on both lanes; `docs/RULES.md` lists every rule
that fired on the corpus; the three hygiene tests hold.

### Phase R49: the bar on maintained code

- [ ] **R49.1** **Measure first** (D82e, D82f, D82g). No test seam. **Record,** each in the
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

- [ ] **R49.2** **The tier table, and its first row** (D82c, D82d, D82e).
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

- [ ] **R49.3** **The vendored `random` rule's row, and one home for both rules** (D82e,
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

- [ ] **R49.4** **A secret in test material** (D82c, D82f).
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

- [ ] **R49.5** **The rules that can be narrowed** (D82e).
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

- [ ] **R49.6** **Two rules the tracks lacked** (D82i).
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

- [ ] **R49.7** **Model output crossing a function** (D82j).
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

**Exit:** the eighth track at its target on both lanes; no measured rule under the bar is
active; no track more than 2 points under its new baseline; the acceptance set passes.

### Phase R50: an existing codebase adopts the gate

- [ ] **R50.1** **Measure first** (D82k, D82m). No test seam. **Record,** in the STATUS:
  1. the time to read the largest acceptance repository's tree with `git cat-file --batch`,
     against a Snapshot from disk;
  2. what `actions/checkout` leaves of the base branch at its default depth;
  3. whether OpenVEX's documents or tools name a conventional path, and the current
     specification's required fields.

- [ ] **R50.2** **`scan --ref`: a commit's tree** (D82k).
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

- [ ] **R50.3** **`gate --new-since`** (D82k, D82l).
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

- [ ] **R50.4** **Shown where a team would copy it.**
  **Seam:** `docs/examples/github-actions.yml`, as `tests/test_pipeline_example.py` runs it.
  Behaviours:
  1. The example gates a pull request on new Findings, with the checkout depth it needs.
  2. `docs/CI.md` states the two limits design.md §6 states. The link check reads it.
  3. **Record.** The action's change, as a pull request in `MaverickHQ/valvur-action` (§3).
     *Check:* its number in the STATUS.
  4. **Proof.** A pull request of valvur's own, gated so, with its run.

  _Requirements: 7.7_

- [ ] **R50.5** **A project's own VEX** (D82m).
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

- [ ] **R50.6** **Ranking reads a declaration** (D82n).
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

- [ ] **R50.7** **One dependency Finding lists its lockfiles** (D82n).
  **Seam:** `api.scan` over `LocalRuntime` with canned Trivy output for two lockfiles;
  `findings.json`, `results.sarif` and the MCP reply. Behaviours:
  1. An advisory found through two lockfiles is one Finding with both in `paths`, sorted.
     Its Fingerprint is the literal the test holds from before the change.
  2. `path` is what it was.
  3. SARIF carries a location for each.
  4. The reply carries `paths`, its snapshot moves in this commit, and its schema is 2.

  _Requirements: 11.4_

**Exit:** the acceptance set passes; the Score unchanged; the proof in R50.4 recorded.

### Phase R51: the tools around it

- [ ] **R51.1** **Measure first** (D82o). No test seam. **Record,** in the STATUS:
  1. the current edition of each OWASP list, read from OWASP's own pages, with the date;
  2. every source of a rule ID, and which can be listed from this repository;
  3. whether Trivy's and OSV-Scanner's output carries a CWE for an advisory.

- [ ] **R51.2** **One mapping, four levels** (D82o).
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

  _Requirements: 8.1, 8.2_

- [ ] **R51.3** **The identifiers in every output.**
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

  _Requirements: 8.3, 8.6, 8.7_

- [ ] **R51.4** **The mapping as a page, and the wording.**
  **Seam:** `generate_docs.py`'s `main`, as `tests/test_generated_docs.py` drives it; a
  wording test over the documents and over one scan's outputs. Behaviours:
  1. The page lists every rule with its identifiers.
  2. It lists each list's categories that nothing maps to.
  3. `--check` fails on a page that is not current.
  4. *covers*, *complies* and *certified* beside a list's name are refused, in a document
     and in an output. Seen red against a planted sentence in each.

  _Requirements: 8.4, 8.5_

- [ ] **R51.5** **The imports, measured** (D82p).
  **Seam:** `imports.yml` as a file, read as `tests/test_eval_workflow.py` reads its own.
  Behaviours:
  1. Its only trigger is dispatch, it holds no secret and no grant beyond reading the
     repository, and both tools are pinned by digest.
  2. **Proof.** A dispatched run imports a scan of the fixture into DefectDojo and
     Dependency-Track. `docs/acceptance/r51.md` records what arrived and what was lost.

  _Requirements: 9.1_

- [ ] **R51.6** **CycloneDX, validated.**
  **Seam:** `api.scan` with the SBOM asked for, as `tests/test_sbom_opt_in.py` drives it.
  Behaviours:
  1. A document with a required field removed fails validation against the vendored schema
     of the version it declares.
  2. **Guard.** The scan's `sbom.cdx.json` validates. Then once against `valvur:dev`, with
     Syft itself (`-m e2e`).

  _Requirements: 9.3_

- [ ] **R51.7** **The corrections and the guides.**
  **Seam:** as R51.3. Behaviours:
  1. One slice for each field R51.5 found lost: it is carried inside SARIF or CycloneDX,
     where the importing tool reads it.
  2. **Record.** `docs/DEFECTDOJO.md` and `docs/DEPENDENCY-TRACK.md`, each showing the
     user's own step. *Check:* the link check, and R51.8.
  3. **Guard, existing.** The constraint tests on egress. *Check:* `egress.py` and
     `verify-offline.py` have no diff in the phase.

  _Requirements: 9.2, 9.4_

- [ ] **R51.8** **Measured again.** **Proof:** the dispatched workflow imports both again. A
  test holds each number in the two guides to `docs/acceptance/r51.md`.

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

### Phase R52: the evidence an adopter asks for

- [ ] **R52.1** **Measure first** (D82q, D82r). No test seam. **Record,** in the STATUS:
  1. each requirement of SLSA's Build track at v1.0, with the release's evidence for it or
     its absence;
  2. the OpenVEX fields a consumer's tool requires, read from the specification;
  3. what GitHub's API gives for each number the Health record shows, and for how long.

- [ ] **R52.2** **The release's OpenVEX document** (D82q).
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
