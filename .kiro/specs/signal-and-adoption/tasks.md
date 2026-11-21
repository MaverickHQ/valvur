# Signal and adoption: tasks

**Written 2026-11-21,** after the owner approved [requirements.md](requirements.md) at
checkpoint A. [design.md](design.md) says how, with the decisions D82a to D82s and their
fallbacks. This list is proposed for checkpoint C, after the ADRs are accepted at
checkpoint B and the test-driven pass has been made over it.

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
2. **Not before checkpoint C.** The ADRs (0033 to 0037) are accepted, changed or rejected at
   checkpoint B, and a rejected one changes its D82 row here before any task starts.
3. **The Score is run on the dev machine** where the plan of wave 1's item 1.7 says so. The
   eighth track takes about ten minutes of the Score's eleven on the owner's Mac.
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
- **R50 before R51:** R51's one schema addition is shared with R50's (`paths`, the VEX
  wording), so the reply's snapshot moves once.
- **R52 last:** it publishes what the others measured, and its Health record reads
  `heal_report.py` if the self-healing list's R46.1 has built it.
- **Beside the self-healing list.** Nothing here needs the heal App or its environments.
  R52.2 and R52.3 read the image gate's verdict, which exists (R43.4).

---

## 2. The phases

### Phase R48: the measurement, for every rule and every Scanner

- [ ] **R48.1** **Measure first, and this spec on the build's rails** (D82a, D82b, D82s).
  Behaviours:
  1. The STATUS records, from one run of the eighth track on `main`:
     - Checkov's and zizmor's Findings on the corpus by rule, and how many labels D82b's
       rule of 25 asks for;
     - which of the 172 labels matched no judged Finding;
     - the track's time on the owner's Mac and on the dev machine.
  2. The main `tasks.md` gains D82's row in §5, pointing to design.md; R48 to R52 in §6; and
     a §8 row pointing to §3 here. `CLAUDE.md`'s Next line names this spec, and the file
     stays under 200 lines.
  3. `requirements.md`'s status line records checkpoints B and C with their dates.

- [ ] **R48.2** **Counts for every judged rule, and for every Scanner** (D82a). Behaviours:
  1. `tracks.real-code-precision.by_rule` in `score.json` holds, for each rule with a judged
     Finding, its Scanner and its true and false counts. Gitleaks' rules are there.
  2. `by_scanner` holds each Scanner's Findings on the corpus, and how many were judged.
  3. The track's `score`, `tp` and `fp` are what they were: the population has not moved.

  _Requirements: 1.1_

- [ ] **R48.3** **Checkov and zizmor, judged in their own table** (D82a, D82b). Behaviours:
  1. A Finding of Checkov's or zizmor's on the corpus is looked up in
     `tests/eval/labels/hygiene.toml`, and counted under `hygiene` in the report, by rule.
  2. For a rule with more than 25 Findings, the 25 with the lowest Fingerprints are judged,
     and the rule is marked `sampled`.
  3. A judged Finding with no label fails `--compare`, naming it.
  4. A dependency Scanner's Findings are counted and never looked up.
  5. A label whose verdict differs from the file at the baseline's commit, without a
     `changed` reason, fails a test.
  6. The labels themselves: every Finding R48.1 counted, labelled by reading the file.

  _Requirements: 1.2, 1.4, 5.2_

- [ ] **R48.4** **`docs/RULES.md` lists every rule that fired, with its two measurements**
  (D82a). Behaviours:
  1. `rules-measured.json` carries each rule's corpus counts apart from its planted counts,
     for every Scanner.
  2. `scripts/rules_doc.py` renders both columns, and *unmeasured there* for a rule with
     fewer than 5 judged Findings on the corpus.
  3. The page says four places are summed for ADR-0029's bar, which the code does and the
     page does not say today.

  _Requirements: 1.3, 2.3_

- [ ] **R48.5** **A mutant of an annotation alone is not counted.** Behaviours:
  1. A hunk that changes only an argument's or a return's annotation is *no code change*.
  2. So is one that changes only the annotation of an annotated assignment.
  3. A hunk that changes an annotation and a value is still counted.
  4. The mutation baseline is recorded again if the score moved, with both numbers.

  _Requirements: 15.1_

- [ ] **R48.6** **No test compares against a moving target.** Behaviours:
  1. A test refuses an image named by tag in `tests/`, `scripts/` or `.github/` when the
     Dockerfile pins that tag by digest, unless the reference is on its list of exceptions,
     each with a reason.
  2. `scripts/check_image_licences.py` and `tests/test_licences.py` read the base, digest
     included, from the Dockerfile.

  _Requirements: 15.2_

- [ ] **R48.7** **The hostile fixtures are stored under names no agent loads.** Behaviours:
  1. A test finds no `AGENTS.md`, `CLAUDE.md`, `.mcp.json` or `.claude/` in any stored
     fixture tree.
  2. A copy made by `scripts/fixtures.py` has the four real names, and the tests that read
     them pass unchanged.
  3. `scanner_upgrade.RECIPES`, `ci.yml`'s `published` job, the acceptance generator and the
     probes read a copy. A test finds no reader of the stored tree.
  4. Every golden is byte for byte what it was.

  _Requirements: 15.3_

**Exit:** the Score unchanged on every track, on both lanes; `docs/RULES.md` lists every rule
that fired on the corpus; the three hygiene tests hold.

### Phase R49: the bar on maintained code

- [ ] **R49.1** **Measure first** (D82e, D82f, D82g). Behaviour: the STATUS records each of
  these, and design.md's first table is completed from it:
  1. for `insecure-cookie`, `open-redirect`, `path-traversal` and `ssrf`, the pattern their
     false Findings share, read from the labelled files;
  2. for each rule under D82d's bar, each track's score with that rule made inventory;
  3. for each directory name D82f proposes, the Findings it moves on the corpus and the
     cases it moves on every track;
  4. for each of Gitleaks' rules that fired on the corpus, whether it matches a shape or a
     provider's format, from its definition in the Gitleaks version the image ships.

  _Requirements: 4.1_

- [ ] **R49.2** **The tier table** (D82c, D82d). Behaviours:
  1. A Finding of a rule with a row `everywhere` is `inventory`, from any Scanner.
  2. A Finding of a rule with a row `test material` is `inventory` in the path classes test,
     fixture, docs and example, and active in `source`.
  3. Its title says why, with the path that decided it.
  4. A rule named both in the table and by `metadata.inventory` fails a test.
  5. A rule that `rules-measured.json` puts under the bar, with no row, fails a test. So
     does a row whose counts differ from the measurement.
  6. A project file cannot change a tier: the table is read from the package alone.

  _Requirements: 2.1, 2.2, 2.4, 3.4_

- [ ] **R49.3** **The first rows: `weak-hash` and the vendored `random` rule** (D82e, D82g).
  Behaviours:
  1. Both rules' Findings are inventory everywhere. The class table's row that removed them
     in test material is gone, since the inventory now holds them.
  2. `docs/RULES.md` shows each as *inventory: under the bar on maintained code*, with its
     counts.
  3. The vendored rule's file is byte for byte what it was, and its manifest entry gains the
     corpus counts.

  _Requirements: 2.2, 4.4_

- [ ] **R49.4** **A secret in test material** (D82c, D82f). Behaviours:
  1. The secrets track gains a live-format secret under a test path and under a
     documentation path for each provider format, assembled at runtime. Each is caught
     before any row is added.
  2. Rows for the shape rules R49.1 names, `test material`. The new cases are still caught,
     and the track keeps 100.
  3. A private key under `config/` is active and critical, as today.
  4. The docs class gains each name R49.1 found safe.
  5. On the corpus, every secrets rule with a row is now over the bar or silent.
  6. `docs/RULES.md` and the README say what is listed for review and why.

  _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] **R49.5** **The rules that can be narrowed** (D82e). Behaviours, one rule at a time,
  each measured on the corpus and on its category before the next:
  1. `valvur.python.insecure-cookie`;
  2. `valvur.python.open-redirect`;
  3. `valvur.python.path-traversal`;
  4. `valvur.javascript.ssrf`;
  5. a rule whose narrowing fails either measurement keeps its old pattern and takes a row.

  _Requirements: 4.1, 4.2_

- [ ] **R49.6** **Two rules the tracks lacked** (D82i). Behaviours:
  1. The JavaScript track gains the categories CWE-295 and CWE-614, each with vulnerable and
     safe cases, and fails on them.
  2. `valvur.javascript.tls-verification-off` and `valvur.javascript.insecure-cookie` catch
     them and flag no safe case.
  3. The Python track reports generated cases as a category apart from the Benchmark's, and
     `valvur.python.tls-verification-off` catches its cases.
  4. Each rule's Findings on the corpus are labelled, and the rule ships only over
     ADR-0029's bar and D82d's.

  _Requirements: 4.3_

- [ ] **R49.7** **Model output crossing a function** (D82j). Behaviours:
  1. The STATUS records Opengrep's `--taint-intrafile`, at the image's version, on the five
     advisories, the generated cases, the corpus and the acceptance set's time.
  2. Either: the four `valvur.llm.*` rules run with it, and the ninth track's baseline rises
     with the measurement.
  3. Or: `SUMMARY.md` carries the note when a Scan Run has a model call and a sink with no
     `valvur.llm.*` Finding joining them, and the verdict is unchanged by it.
  4. No document says the rules follow a flow between files. A test holds the wording.

  _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] **R49.8** **The target, the baseline and the README** (D82g, D82h). Behaviours:
  1. The whole Score on both lanes, written to `docs/acceptance/r49.md` with each track's
     old and new number.
  2. The baseline is raised once. The Python and JavaScript tracks are re-based with both
     numbers and the reason, as ADR-0033 allows.
  3. The eighth track meets the target ADR-0033 records, and the count of false active
     Findings is in the report.
  4. The README states the track's number with what it counts, and how many Findings are in
     the inventory on the corpus.

  _Requirements: 2.5, 5.1, 5.3, 5.4_

**Exit:** the eighth track at its target on both lanes; no measured rule under the bar is
active; no track more than 2 points under its new baseline; the acceptance set passes.

### Phase R50: an existing codebase adopts the gate

- [ ] **R50.1** **Measure first** (D82k, D82m). Behaviour: the STATUS records:
  1. the time to read the largest acceptance repository's tree with `git cat-file --batch`,
     against a Snapshot from disk;
  2. what `actions/checkout` leaves of the base branch at its default depth;
  3. whether OpenVEX's documents or tools name a conventional path, and the current
     specification's required fields.

- [ ] **R50.2** **`scan --ref`: a commit's tree** (D82k). Behaviours, each on a repository
  made in `tmp_path`:
  1. A file that exists only in the ref is scanned, and a file that exists only in the
     working tree is not.
  2. Nothing under `.git` changes, and nothing is written to the Workspace.
  3. `--ref` without `--out` is refused, and so is an `--out` that is the Workspace's own
     Results Folder.
  4. `run.json` names the ref and its commit.
  5. The ref's own `.security-scan.toml` gives the excludes and the Suppressions.
  6. A secret deleted before the ref is found by the history pass, and one added after it is
     not.
  7. A ref that does not resolve is an error that names it.

  _Requirements: 7.1, 7.3_

- [ ] **R50.3** **`gate --new-since`** (D82k, D82l). Behaviours:
  1. A Finding whose Fingerprint is in the base passes the gate, and one that is not fails it.
  2. A Finding suppressed in the base and active now counts as already there.
  3. The output names the base, its commit, and how many Findings were not gated on.
  4. An incomplete Scan Run of either tree fails the gate. So does a lapsed Suppression in
     the working tree.
  5. A base that cannot be read or scanned fails the gate with the reason, and never passes.
  6. A base result is reused only when the commit, the image, the Profile and every dataset
     are the same.
  7. Without the option, the gate's output and exit codes are byte for byte what they were.

  _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [ ] **R50.4** **Shown where a team would copy it.** Behaviours:
  1. `docs/CI.md` and `docs/examples/github-actions.yml` show a pull request gated on new
     Findings, with the checkout depth it needs and the two limits design.md §6 states.
  2. The action's change is prepared as a pull request in `MaverickHQ/valvur-action` (§3).
  3. The proof: a pull request of valvur's own, gated so, recorded with its run.

  _Requirements: 7.7_

- [ ] **R50.5** **A project's own VEX** (D82m). Behaviours:
  1. A `not_affected` statement for a Finding's vulnerability and package version, in a
     document a `[[vex]]` entry names, suppresses the Finding, with the justification, the
     author and the timestamp shown.
  2. A `fixed` statement does the same. `affected` and `under_investigation` do nothing.
  3. A statement with no version, or with neither a justification nor an impact statement,
     is not honoured and is reported.
  4. An entry past its `expires` is reported as an expired Suppression is, and fails the gate.
  5. A statement that matches nothing is listed, at `low`.
  6. A document no entry names is never read.
  7. No tool or command writes a VEX statement. A test holds that, as one holds
     `scan_and_fix`'s absence.
  8. `valvur doctor` and the JSON Schema know `[[vex]]`.

  _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] **R50.6** **Ranking reads a declaration** (D82n). Behaviours:
  1. With no `[[context]]`, the order of every existing ranking test is unchanged.
  2. Of two Findings in one tier, the one under a declared path ranks first.
  3. A Finding in a higher tier still outranks a declared one in a lower tier.
  4. The raised item says which declaration raised it, in the word *declaration*.

  _Requirements: 11.1, 11.2, 11.3_

- [ ] **R50.7** **One dependency Finding lists its lockfiles** (D82n). Behaviours:
  1. An advisory found through two lockfiles is one Finding with both in `paths`, and its
     Fingerprint is what it was.
  2. `findings.json` and SARIF carry every path. `path` is unchanged.

  _Requirements: 11.4_

**Exit:** the acceptance set passes; the Score unchanged; the proof in R50.4 recorded.

### Phase R51: the tools around it

- [ ] **R51.1** **Measure first** (D82o). Behaviour: the STATUS records:
  1. the current edition of each OWASP list, read from OWASP's own pages, with the date;
  2. every source of a rule ID, and which can be listed from this repository;
  3. whether Trivy's and OSV-Scanner's output carries a CWE for an advisory.

- [ ] **R51.2** **One mapping, four levels** (D82o). Behaviours:
  1. A rule's own entry is found before its prefix's, its Scanner's and its class's.
  2. Each of valvur's rules and Checks, and each vendored rule, has an entry by ID. A test
     refuses one with none.
  3. An entry of `none` needs a reason.
  4. A dependency Finding takes its advisory's CWE where the Scanner gave one.

  _Requirements: 8.1, 8.2_

- [ ] **R51.3** **The identifiers in every output.** Behaviours:
  1. `findings.json` carries `owasp` beside `cwe`, and its schema is still 1.
  2. SARIF carries the taxonomies, each rule's relationships and the tags, and validates
     against the 2.1.0 schema.
  3. The reply carries them, and its snapshot is updated once for the phase.
  4. `SUMMARY.md` has the bounded table, and `findings --owasp` filters.
  5. `fp_version` is 1, and the Score is unchanged.

  _Requirements: 8.3, 8.6, 8.7_

- [ ] **R51.4** **The mapping as a page, and the wording.** Behaviours:
  1. `docs/OWASP-MAPPING.md` is generated: every rule with its identifiers, then each
     list's categories nothing maps to. `generate_docs.py --check` holds it.
  2. A test refuses *covers*, *complies* and *certified* beside a list's name, in documents
     and in outputs.

  _Requirements: 8.4, 8.5_

- [ ] **R51.5** **The imports, measured** (D82p). Behaviour: `imports.yml`, on dispatch,
  imports a scan of the fixture into DefectDojo and Dependency-Track at pinned versions, and
  `docs/acceptance/r51.md` records what arrived and what was lost.

  _Requirements: 9.1_

- [ ] **R51.6** **CycloneDX, validated.** Behaviour: a test validates `sbom.cdx.json` against
  the vendored schema of the version it declares.

  _Requirements: 9.3_

- [ ] **R51.7** **The corrections and the guides.** Behaviours:
  1. Each field R51.5 found lost is carried inside SARIF or CycloneDX, each with its test.
  2. `docs/DEFECTDOJO.md` and `docs/DEPENDENCY-TRACK.md` show the user's own step.
  3. `egress.py` and `verify-offline.py` are unchanged, and a test names no new host.

  _Requirements: 9.2, 9.4_

- [ ] **R51.8** **Measured again.** Behaviour: the dispatched workflow imports both again, and
  the guides cite those numbers alone.

  _Requirements: 9.5_

- [ ] **R51.9** 👤 **Each agent client, run or said not to be.** Behaviours:
  1. Codex, Cursor and VS Code each scan the fixture through valvur, recorded with the
     client's version and the date.
  2. Each other client is run, or marked *not run* with the reason, dated.
  3. `valvur doctor --client` is run for each, and a snippet that proved wrong is corrected
     in the commit that records it.

  _Requirements: 12.1, 12.2, 12.3, 12.4_

**Exit:** every rule mapped or marked `none`; both imports measured twice; the Score
unchanged on both lanes.

### Phase R52: the evidence an adopter asks for

- [ ] **R52.1** **Measure first** (D82q, D82r). Behaviour: the STATUS records:
  1. each requirement of SLSA's Build track at v1.0, with the release's evidence for it or
     its absence;
  2. the OpenVEX fields a consumer's tool requires, read from the specification;
  3. what GitHub's API gives for each number the Health record shows, and for how long.

- [ ] **R52.2** **The release's OpenVEX document** (D82q). Behaviours:
  1. An entry with no fixed version is `under_investigation`, for the image by digest.
  2. An accepted entry is `affected` with the acceptance's reason and expiry, or
     `not_affected` when the acceptance gives one of OpenVEX's justifications.
  3. The two architectures' verdicts give one document. An entry on one alone names it.
  4. Verdicts with nothing to say give a valid document with no statements.
  5. The document validates against OpenVEX's schema, vendored.

  _Requirements: 14.1_

- [ ] **R52.3** 👤 **Attached and attested** (D82q). Behaviours:
  1. `release.yml` writes the document in `notes` and attaches it in `promote`.
  2. It attests the document and the four SBOMs on the image's digest, and `artifact`
     verifies each.
  3. The release constraint tests are restated for the new steps and their grants, and
     zizmor finds nothing.
  4. A rehearsal, cancelled at the brake, shows the five attestations.

  _Requirements: 14.1_

- [ ] **R52.4** **The level, and who can release.** Behaviours:
  1. `SECURITY.md` states the SLSA Build level R52.1 found, with each requirement's
     evidence, and a test refuses a higher level's name.
  2. `MAINTAINERS.md` says who can release today and what continues without them.
  3. `docs/BEST-PRACTICES.md` is current with the tree, and the form is in §3.

  _Requirements: 14.2, 14.3, 14.5_

- [ ] **R52.5** **The Health record** (D82r). Behaviours:
  1. `scripts/health.py` renders the Score by track, the published image's verdict by day
     and the mutation score from recorded runs, faked in the tests.
  2. A number it could not read keeps its last value and date, and says so.
  3. Time to heal appears once `heal_report.py` exists, and is marked absent until then.
  4. `health.yml` runs daily, writes one issue, holds `issues: write` and nothing more, and
     is on the watchdog's list.
  5. The README links to it.

  _Requirements: 14.4_

- [ ] **R52.6** 👤 **A first use, watched.** Behaviours:
  1. `docs/history/usability-gate.md` holds Gate 2: each stop, question and guess, timed.
  2. Each is fixed or recorded as accepted, with the reason.
  3. `docs/CLI.md`'s first-run time and sizes are the ones measured on that run.

  _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

**Exit:** a release carries its VEX document and five attestations; `SECURITY.md` states the
level; the Health record has run for a week; Gate 2 is recorded.

---

## 3. The owner queue for this spec

R48.1 adds one row to the main list's §8 that points here. Nothing here blocks a test.

| item | ready after | what the owner does |
|---|---|---|
| checkpoint B: the five ADRs | wave 1, item 1.3 | accept, change or reject ADR-0033 to ADR-0037 |
| the target, and the Python track's re-base | checkpoint B | D82h: 33 with at most 8 false active Findings, or keep 50. D82g: accept about 6 points off the Python track for the two demoted rules, or keep them active |
| two narrowed requirements | checkpoint B | D82b: Checkov and zizmor judged on a sample of 25 per rule. D82m: an unmatched VEX statement is reported and does not fail the gate |
| checkpoint C: this list | the test-driven pass | approve it, or change it |
| three accounts | before R51.9 | sign in to Codex, Cursor and VS Code's agent mode on the Mac, or say which are not to be run |
| the action's pull request | R50.4 | land it in `MaverickHQ/valvur-action`, and tag it |
| the edit to `release.yml` | R52.3 | approve the diff, shown first |
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
