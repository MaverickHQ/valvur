# Signal and adoption: requirements

**Status:** proposed 2026-11-21, for the owner's checkpoint A · **Phases:** R48 to R52, in
`tasks.md`, written after this file is approved · **Decisions:** D82, in `design.md`, the same

This spec extends [the main spec](../valvur/requirements.md) and uses
[CONTEXT.md](../../../CONTEXT.md)'s terms exactly. It covers what a user of valvur meets: how
much of a report is true, what it takes to switch valvur on in a project that already
exists, and what an adopter in a regulated industry asks before trusting it. How the
repository keeps itself patched is [the self-healing supply chain](../self-healing-supply-chain/requirements.md)'s,
amended on the same day. Nothing here lets valvur change a Workspace (`CLAUDE.md` §4,
ADR-0009), fetch anything new in the `offline` Profile, or claim a detection it does not have.

**IDs.** Requirements here are numbered 1 to 15, as Kiro numbers them, and their criteria
`1.1`, `1.2` and so on. `scripts/check_traceability.py` fails on a main-spec requirement ID
that the main spec does not define, so this file names none of its own. When a task builds
a criterion, it adds that criterion to `.kiro/specs/valvur/requirements.md` in the same
commit as the test that cites it, as the main `tasks.md` §3 requires, and writes that ID in
this file's last table.

---

## Introduction

### What a user meets today

Measured on 2026-11-21, on `main` at `f0e7150` (1.6.2):

- **On maintained code, 3 of 171 Findings are real.** The Score's eighth track runs valvur
  over 48 maintained projects, every Finding labelled by hand
  (`tests/eval/labels/corpus.toml`). Its score is 2.3.
- **Secrets are the larger half of the noise, and nearly all of it is test material.**
  Gitleaks' rules give 98 of the 168 false Findings and none of the 3 true ones:
  `private-key` 35, `jwt` 29, `generic-api-key` 26. Of those 90, 86 are under a path named for tests,
  fixtures, examples or documentation, and the other 4 in a tutorial's source. On the Score's
  secrets track, planted secrets in ten formats, the same rules score 100.
- **Static analysis gives the rest:** 69 false and 3 true. Two rules give 44 of the false
  ones, `python_random_rule-random` (0 true, 23 false) and `valvur.python.weak-hash`
  (0 true, 21 false). Both are active: ADR-0029's bar is taken over the corpus and the
  planted tracks together, and the planted cases carry them.
- **Three Scanners are not judged on maintained code at all.** Checkov's, zizmor's and the
  dependency Scanners' Findings on the 48 are counted and not labelled
  (`scripts/eval/precision.py`), and the counts are not recorded.
- **The rules for model output catch none of five published advisories** in LangChain,
  LlamaIndex and Vanna, whose flows each cross a function (README, *Measured, not claimed*).
- **The gate cannot be switched on in a project with a backlog.** `valvur gate` takes a
  severity threshold and `--no-inconclusive`, and fails on every active Finding at or above
  it. valvur already knows which Findings are `new` since the last Scan Run
  (`src/valvur/state.py`); the gate does not read it.
- **A Finding carries a CWE only when Opengrep reported it,** and no OWASP category from any
  Scanner. Nothing documents an import into DefectDojo or Dependency-Track, and valvur
  reads and writes no VEX.
- **Seven agent clients are documented and not run.** `docs/AGENTS.md` marks Claude Code and
  Kiro as measured, and Codex, Cursor, VS Code, Windsurf, Cline, Continue and Zed as
  *documented shape, not run here*.

### What this spec changes

The measure of success moves from what valvur can find in planted cases to what a user can
believe in a report on their own code. The mechanism for showing a Finding without
asserting it already exists: the **inventory** (D47a, `docs/RULES.md`), whose Findings are
reported for review and never count toward the verdict. This spec applies it by measurement
on maintained code, to every rule valvur ships.

### Not goals

- **No rule is deleted to raise a number.** A rule under the bar moves to the inventory,
  where its Findings are still reported. Recall on the planted tracks is held by the
  ratchet (ADR-0026).
- **No reachability, and no claim of it** (`CLAUDE.md` §2). Requirement 6 looks within one
  file at most, and says so.
- **No committed scan output** (ADR-0011). Requirement 7 gates on new Findings without it.
- **No upload by valvur.** Requirement 9's imports are made by the user's pipeline.
- **No new language, no add-on contract, no IDE extension.** Each widens the surface before
  the signal on what is already covered is good. They stay parked.

---

## Requirements

### Requirement 1: Precision on maintained code is measured for every rule and every Scanner

**User Story:** As a user deciding whether to believe a report, I want valvur's precision on
real code published for each rule and each Scanner, so that I know which Findings to read
first and which to doubt.

#### Acceptance Criteria

1. WHEN the eighth track runs THEN its report SHALL record, for each rule that fired on the
   corpus, its true and false counts, and for each Scanner the number of Findings it gave.
2. Checkov's and zizmor's Findings on the corpus SHALL be labelled and judged as the others
   are. The dependency Scanners' SHALL be counted and not judged: an advisory against a
   pinned version is true by its identity (`CLAUDE.md` §8).
3. `docs/RULES.md` SHALL give each rule's counts on maintained code apart from its counts on
   the planted tracks, and SHALL be generated from the measurement, as it is today.
4. A judged Finding with no label SHALL fail the track, as it does today.

### Requirement 2: One bar on maintained code decides what is active

**User Story:** As a user, I want a rule that is usually wrong on real code to stop
counting toward the verdict, so that a `findings` verdict means something was found.

#### Acceptance Criteria

1. The bar SHALL be a precision on the corpus and a least number of judged Findings below
   which a rule is *unmeasured there*. Both values SHALL be set by an ADR (0033) from
   Requirement 1's table, and SHALL apply to every rule valvur ships, Gitleaks' and
   Checkov's included.
2. WHEN a rule is measured on the corpus and under the bar THEN its Findings SHALL be
   inventory: reported for review, never active, never counted by the verdict or the gate.
3. A rule unmeasured on the corpus SHALL stay as ADR-0029 leaves it, and `docs/RULES.md`
   SHALL say it is unmeasured there.
4. A test SHALL refuse a rule that is active while its recorded counts put it under the bar.
5. No track of the Score SHALL fall more than 2 points under its baseline by this change
   (ADR-0026). IF demoting a rule would do that THEN the rule SHALL be repaired under
   Requirement 4 instead, or the conflict put to the owner.

### Requirement 3: A secret in test material is told apart from a secret

**User Story:** As a user, I want a private key in a test fixture reported differently from
one in my configuration, so that the secret that matters is not the ninety-first in a list.

#### Acceptance Criteria

1. On the corpus, the secrets rules SHALL meet Requirement 2's bar.
2. The Score's secrets track SHALL gain cases that hold a secret in a provider's live format
   under a test path and under a documentation path. valvur SHALL report each as active.
3. The secrets track SHALL keep its baseline.
4. WHEN a secret Finding is inventory by this requirement THEN the report SHALL say why, in
   words a reader can check against the file.
5. IF criteria 1 and 2 cannot both be met by a rule that reads only the file and its path
   THEN the design SHALL say so with the measurement, and the owner SHALL choose which gives
   way.

### Requirement 4: A rule under the bar is repaired where it can be

**User Story:** As a user, I want valvur's own rules narrowed to the cases that are
weaknesses, so that fewer true Findings sit in the inventory.

#### Acceptance Criteria

1. For each of valvur's own rules under the bar, the design SHALL record the pattern its
   false Findings share and whether a narrower rule keeps its planted cases.
2. A repaired rule SHALL be measured again on the corpus and the planted tracks, and SHALL
   become active only over the bar.
3. Two rules the tracks lack SHALL be added, each with its cases on the JavaScript and
   Python tracks and each subject to the bar: certificate validation turned off, and a
   JavaScript cookie set without `secure`.
4. A rule vendored from GitLab's `sast-rules` SHALL NOT be edited in place. It is kept,
   moved to the inventory, or replaced by a rule of valvur's own (ADR-0029).

### Requirement 5: The eighth track has a target, and the ratchet holds it

**User Story:** As the owner, I want a number that says the report on real code became
trustworthy, so that later changes cannot quietly undo it.

#### Acceptance Criteria

1. WHEN Requirements 2 to 4 are built THEN at least half of the active Findings on the
   corpus SHALL be true: a track score of 50 or more. The owner confirms or changes this
   number at checkpoint A.
2. The corpus SHALL keep its 48 projects, at the commits they are pinned to. Its labels
   SHALL NOT be changed to meet the target, and a test SHALL refuse a label whose verdict
   changed without a reason recorded beside it.
3. The baseline SHALL be raised once, at the end of the phase, to what was measured.
4. The README SHALL state the new number with what it counts: active Findings only, and how
   many Findings are in the inventory.

### Requirement 6: Model output crossing a function is caught, or the limit is where the user reads it

**User Story:** As a developer of an application that calls a model, I want to know whether
valvur follows model output through my own functions, so that a `clean` verdict does not
tell me more than it knows.

#### Acceptance Criteria

1. The design SHALL measure whether Opengrep, at the version the image ships, follows a
   tainted value across functions within one file, on the five advisories' code.
2. IF it catches at least one of the five with no new false Finding on the corpus THEN the
   rules SHALL use it, and the ninth track's baseline SHALL rise with the measurement.
3. IF it does not THEN nothing in the rules changes, and `SUMMARY.md` SHALL carry a coverage
   note when the Workspace calls a model and a sink is in another function than the call.
4. Either way, no document SHALL describe the rules as following flows between files.

### Requirement 7: The gate can fail on new Findings only

**User Story:** As a team with an existing codebase, I want the gate to fail on what a change
adds, so that I can switch it on today and work the backlog down afterwards.

#### Acceptance Criteria

1. `valvur gate` SHALL take an option that fails only on active Findings that are not
   present in a named base: a git ref of the same repository, scanned by the same valvur.
2. A Finding SHALL be the same Finding in both when its Fingerprint is equal (`CLAUDE.md` §8).
3. No scan output SHALL be committed, and none SHALL be read from a commit (ADR-0011).
4. The gate's output SHALL say how many active Findings were already in the base and were
   not gated on, and SHALL name the base.
5. An incomplete Scan Run of either tree, or a lapsed Suppression, SHALL fail the gate, as
   today.
6. WHEN the base cannot be scanned THEN the gate SHALL fail and say why. It SHALL NOT fall
   back to gating on nothing.
7. `docs/CI.md` and the action SHALL show the option on a pull request, with the base
   branch as the base.

### Requirement 8: Every Finding carries the standard identifiers its rule maps to

**User Story:** As a security engineer, I want each Finding to name its CWE and the OWASP
categories it maps to, so that valvur's output sorts into the taxonomies my tools and
auditors already use.

#### Acceptance Criteria

1. Every rule, Check and Finding class SHALL have an entry in one mapping file: its CWE
   where one applies, and its category in the OWASP Top 10, the OWASP Top 10 for LLM
   applications and OWASP's agentic lists where one applies.
2. A test SHALL refuse a rule with no entry. An entry MAY say that no identifier applies,
   with the reason.
3. `findings.json`, SARIF (as taxa and tags) and the MCP reply SHALL carry the identifiers.
   `SUMMARY.md` SHALL be able to group by them.
4. Every document and output SHALL word this as *mapped to*. None SHALL say valvur covers,
   complies with or is certified against a list.
5. A generated document SHALL list every rule beside its identifiers, and each list's
   categories that no rule maps to.
6. This SHALL be `findings.json`'s and the reply's one schema change of the phase, shared
   with Requirements 10 and 11. `fp_version` SHALL NOT change.
7. The Score SHALL be unchanged.

### Requirement 9: DefectDojo and Dependency-Track take valvur's output

**User Story:** As a team that tracks vulnerabilities in DefectDojo or Dependency-Track, I
want to import valvur's results as they are written, so that adopting valvur adds no
second dashboard.

#### Acceptance Criteria

1. The design SHALL record an import of valvur's SARIF into DefectDojo, and of its
   CycloneDX SBOM into Dependency-Track, each at a named version, with what arrived and
   what was lost.
2. WHEN an import loses a field a user needs THEN the artifact SHALL be corrected within its
   own standard. A second format SHALL be added only if the measurement shows no other way.
3. A test SHALL validate `sbom.cdx.json` against the CycloneDX schema of the version it
   declares.
4. valvur SHALL NOT upload. A guide for each tool SHALL show the user's own pipeline doing
   it, and `egress.py` SHALL be unchanged.
5. The imports SHALL be measured again after the corrections, and the guides SHALL cite
   those numbers only.

### Requirement 10: A project's own VEX statements are honoured

**User Story:** As a maintainer who has already assessed an advisory, I want valvur to read
my VEX statement, so that I record the assessment once, in the format my consumers read.

#### Acceptance Criteria

1. valvur SHALL read OpenVEX documents the project commits, offline, at a path the design
   names.
2. A statement of `not_affected` or `fixed` for a vulnerability and product valvur reports
   SHALL be treated as a Suppression is: the Finding is reported as accepted, named in
   `SUMMARY.md` with the statement's justification, and not active.
3. A statement SHALL need what a Suppression needs: an author and a date valvur can read,
   and an expiry. The design SHALL say how an OpenVEX document carries the expiry.
4. A statement that matches no Finding SHALL be reported, as an unused Suppression is.
5. valvur SHALL NOT write, generate or propose a VEX statement about the Workspace
   (`CLAUDE.md` §4).

### Requirement 11: Ranking reads what the project declares about itself

**User Story:** As a developer, I want to tell valvur which paths face the internet or
handle sensitive data, so that the top of `REMEDIATION.md` is the top of my risk.

#### Acceptance Criteria

1. `.security-scan.toml` SHALL take declarations of paths that are internet-facing or handle
   sensitive data. The ranking SHALL raise a Finding under a declared path within its class.
2. Every raised Finding SHALL say which declaration raised it. Every output SHALL call this
   a declaration, never analysis (`CLAUDE.md` §2).
3. A project with no declaration SHALL rank exactly as today.
4. WHERE the owner's ADR accepts it, one dependency Finding SHALL list every lockfile it
   appears in, without changing its Fingerprint.

### Requirement 12: Each agent client is run, or said not to be

**User Story:** As a developer who uses another agent than Claude Code or Kiro, I want to
know whether valvur's instructions for my client were ever run, so that I do not debug the
documentation.

#### Acceptance Criteria

1. For each client `docs/AGENTS.md` documents, the phase SHALL record one of: a scan run
   from that client, with its version and date; or that it was not run, and why.
2. At least Codex, Cursor and VS Code SHALL be run.
3. `valvur doctor --client` SHALL be run for each and its answer recorded.
4. A client whose documented shape proved wrong SHALL be corrected in the same commit as
   the record.

### Requirement 13: A person who has never used valvur gets a first report from the README

**User Story:** As the owner, I want first use watched once per release that changes it, so
that what stops a new user is found by us and not by them.

#### Acceptance Criteria

1. A person who has not used valvur SHALL install it and get a first report from the README
   alone, on their own machine, while observed, as `docs/history/usability-gate.md` runs it.
2. Each point where they stopped, asked or guessed SHALL be written down with its time.
3. Each such point SHALL be fixed or recorded as accepted, with the reason, before the phase
   closes.
4. The first Scan Run's time and download sizes in `docs/CLI.md` SHALL be measured again on
   that run and replaced if they moved.
5. This requirement closes only by the owner: it needs a person.

### Requirement 14: What a regulated adopter asks for is published

**User Story:** As an adopter in a regulated industry, I want valvur's own security posture
stated and checkable, so that I can approve it without interviewing its maintainer.

#### Acceptance Criteria

1. Each release SHALL carry an OpenVEX document for the image: every vulnerability the
   image gate reports with no fixed version, and every one the owner accepted, with its
   status. It SHALL be generated from the gate's verdict, attached to the release, and
   attested as the SBOMs are.
2. `SECURITY.md` SHALL state the SLSA build level the release reaches, with the evidence for
   each of that level's requirements, and no higher level.
3. The OpenSSF Best Practices form SHALL be submitted from `docs/BEST-PRACTICES.md` and its
   badge shown only once it passes. Submitting is the owner's.
4. One Health page SHALL show, from recorded runs only: the Score by track, the image
   gate's verdict by day, time to heal against its target, and the mutation score.
5. `MAINTAINERS.md` SHALL state who can release today, and what happens to releases and to
   the daily data if that person cannot. A second maintainer is the owner's to find.

### Requirement 15: The measurements judge behaviour, not the day they ran

**User Story:** As the owner, I want the evidence above to be stable, so that a number moves
only when valvur did.

#### Acceptance Criteria

1. The mutation score SHALL count a surviving mutant only when it changes behaviour. A
   mutant of a type hint alone SHALL NOT count.
2. A test SHALL refuse a test that compares against a moving target: an image or an action
   named by tag where a digest is pinned elsewhere in the tree.
3. The hostile fixtures under `tests/fixtures/broken-repo/` that an agent would load as its
   own instructions SHALL be stored under names no agent loads, and given their real names
   only inside the copy a test scans.

---

## Where each criterion is defined in the main spec

Filled by the task that builds each criterion (main `tasks.md` §3), in the commit whose test
cites it.

| criterion here | main spec ID | task |
|---|---|---|
