# valvur: tasks

**Written 2026-09-29, third version.** `1.1.0` shipped that day, and the owner accepted
every recommendation of [the review of 2026-09-29](../../../docs/history/REVIEW-2026-09-29.md)
and asked for a list that runs end to end without them, test-driven, and judged by a
score that can be re-run after every future change. Amended the same day, before the build
began, with a skill that runs the workflow, shipped as a Claude Code plugin and a Kiro
power (§5, D39 to D41). It is authoritative for what is open.

**Amended 2026-10-02, after `1.2.0` shipped**, at the owner's word, with Phases R17 to R19
(§5, D42 to D46): the three missed targets lowered to what is measured, a check that every
cited requirement ID is defined, a hook that asks before an install, and the runner move.
R17 and R18 run now; R19 is dated and starts on or after 2026-11-19.

**Amended again 2026-10-03, after `1.3.1`**, at the owner's word, with Phases R20 to R22
(§5, D47 to D49): the noise real projects draw, being findable, and the OpenSSF signals an
evaluator looks for. They run before R19, which stays last until its date.

**Amended a third time 2026-10-03**, after [the architecture review](../../../docs/history/REVIEW-2026-10-03.md)
of the same day, at the owner's word, with Phases R23 and R24 (§5, D50 to D55) and R20
reshaped around path classes (D56). R23 and R24 run first, then R20 to R22, then R19 at its
date. D57 records what a 2.0 would change; its phases are not written here. The same day,
the owner's first run on a new project added R21.3 and R21.4 (D58, D59), and the owner
brought back the rule-writing D42 had set aside, as Phase R25 after R20 (D60). D61 lets the
build run in a Claude Code cloud session, on the owner's promotional credit.

**IDs.** Tasks here are `R<phase>.<n>`, continuing from R8. R0 to R6 are closed and in
[their archive](../../../docs/history/tasks-phases-r0-r6.md), R7 and R8 in
[theirs](../../../docs/history/tasks-phases-r7-r8.md), with the decisions D1 to D20 that
build ran on. A bare ID such as `29.0.5` refers to
[the archive of Phases 0 to 30](../../../docs/history/tasks-phases-0-30.md). Requirement
IDs are never renumbered; a task that changes one amends it in `requirements.md`.

**Contents:** 1 unattended running · 2 resuming · 3 how a task is built · 4 how a phase
ends · 5 decisions · 6 order · 7 the phases · 8 the owner queue

---

## 1. How this list runs unattended

- **One executor.** A Claude Code session in auto mode, in this checkout on this Mac,
  works the phases in order. It does not end its turn between tasks or phases. It ends
  only when §8 is all that remains, or on a stop condition.
- **Nothing on the critical path waits for the owner.** Landing on `main`, the signed tag,
  the release approval, the gate with a person and anything that spends money outside
  D36 are collected in §8. The executor prepares everything up to them and moves on.
  **It never pushes to `main` or pushes a tag**; phases stack instead (§4).
- **Every choice has a recorded answer** (§5). A measurement that misses its threshold
  takes the recorded fallback. Nothing waits for a decision.
- **The only stop conditions:**
  1. a change would cross `CLAUDE.md` §10, beyond what §5 records as approved;
  2. an action would delete or overwrite something outside this repository and the
     build caches (`~/.cache/valvur-build`, Docker's build cache);
  3. a required check, or a phase exit's Score, fails three times for the same cause
     after fixes;
  4. the machine cannot run containers;
  5. a fetch would reach a host that neither `src/valvur/egress.py` nor ADR-0027 names.

  On a stop, the executor writes what happened and what it needs as a row in §8, commits
  it, pushes the branch, and ends its turn.
- **Cost cap.** Agent runs with `claude -p` are capped at $10 across R9 to R16 (D36), and
  at $5 across R17 to R19 (D46). R21.3's smoke run is capped at $2 (D58); R20 and R22 to
  R25 run no agent. Past a cap they are skipped and noted in §8.
- **In a cloud session** (D61), the build runs on the session's VM, and D61 says what
  changes there: the lanes, the gate, the caches, resuming, and what is left for a local run.
- **A dated phase waits for its date.** R19 starts on or after 2026-11-19. Until then the
  executor treats it as §8 does: it stops after R22 and leaves R19's row in §8.
- **Machine hygiene.** Builds, scans, e2e and the Score use `~/.cache/valvur-build` as
  `VALVUR_CACHE` and `VALVUR_IMAGE=valvur:dev`. Never touch `~/.cache/valvur`, pulled
  `ghcr.io/maverickhq/valvur:*` images, or containers the build did not start. The Score's
  external sources are fetched into `~/.cache/valvur-build/eval/`, never into the tree.
- **Safety in agent runs.** An agent run never has a shell: `claude -p` runs with
  `--disallowedTools Bash`, so no package named in a scenario, malicious ones included,
  is ever installed or executed on this machine.

## 2. Resuming

Two mechanisms, armed by R9.1.

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
   exists on origin, otherwise from `main`. Check out the branch, creating it from the
   previous phase's branch when that exists on origin, else from `main`. A phase finished
   on its branch waits for the owner to land (§8): the script steps over it to the branch
   stacked on it, listing it in `waiting_to_land`. When it says `land the phase`, the phase
   is finished and its PR open: never push to `main`; cut the next phase's branch from it
   and continue there.
3. **Leave nothing half-done.** The session that was building keeps its own changes and
   finishes its slice. A fresh session stashes any working-tree changes with
   `git stash push -u -m "resume <UTC time>: partial slice"` and redoes that slice from its
   last green commit, never trusting it. Either way, if the unit suite is red on HEAD, fix
   that first.
4. **Is the machine ready?** Docker answers `docker info`; if not, `open -a Docker` and wait
   up to five minutes, then stop condition 4. `valvur:dev` exists and was built from this
   branch's HEAD, else rebuild it. The Mac's acceptance set is always run with
   `--generate`: a set left on disk from an earlier phase is judged by old expectations
   (R9).
5. **Continue** with the first unchecked task, at its first behaviour without a passing test.
6. **Re-arm** the in-session schedule if `CronList` shows none.
7. **Finish.** When every task outside §8 and outside a dated phase is done, delete both
   schedules, write the build's summary into the last task's STATUS, and end the turn.

## 3. How every task is built: test-driven

- **Each task lists behaviours in test order.** Each behaviour is one red-to-green slice:
  1. write that one test;
  2. run it and see it fail for the expected reason;
  3. write the least code that passes;
  4. run `ruff`, `mypy` and the unit suite
     (`PYTHONDONTWRITEBYTECODE=1 uv run --extra dev pytest -q -p no:cacheprovider -m "not e2e and not timing"`,
     after clearing `__pycache__`). A slice that touches only `scripts/`, documents or a
     new test file runs its own tests and lint; the full suite runs at the end of every
     task and before every push. *The unit suite takes one to two minutes on this Mac; the
     whole suite, e2e included, took 12 minutes on 2026-09-29.*
  5. commit. The commit message follows the repository's Conventional Commits hook, scoped
     by task, and names the behaviour: `feat(r11.1): KEV's age is its catalog's date`.
- **Never write all the tests first. Never refactor while red.** A refactor is its own
  commit on green: `refactor(r11.1): …`.
- **Test through public interfaces:** `api.scan`, the MCP server over stdio, the CLI,
  `python -m valvur.engine`, `scripts/acceptance.py`, `scripts/eval.py`. **Fake only two
  boundaries:** the container runtime, through `LocalRuntime`, and the network, through
  `tests/fake_registry.py` and the conftest socket guard. `git`, files and processes are
  real.
- **Assert on fields, kinds and counts.** Assert on a sentence only where the sentence is the
  contract.
- **A behaviour that needs a container** is tested through `LocalRuntime` and again with
  `-m e2e` against `valvur:dev`.
- **Measure first.** A task whose value is a number records the before in its first commit
  and the after in its STATUS. **A task that changes detection, ranking, data or the reply**
  runs the Score's tracks it touches (`scripts/eval.py --tracks … --compare`) before its
  last commit, and its STATUS gives each track's delta.
- **Tick the task's checkbox** in the commit that turns its last behaviour green, so a
  resuming session can see where the build stands.
- **New tests go in new files.** The constraint suite stays at 54 tests unless a task
  restates a constraint.
- **Planted credentials are assembled at runtime.** Push protection is on for this
  repository, so no test, generator or Score track carries a credential as a literal.
- **A new requirement ID** is added by the task that builds it, in the same commit as the
  test that cites it, so `scripts/check_traceability.py` never records debt.

## 4. How every phase ends: the phase commit

1. Every task is ticked and carries a `**STATUS <date>:** ✅` note with its measured after.
2. **The exit is measured on both lanes** and written to `docs/acceptance/r<n>.md`:
   - *the acceptance set*: `scripts/acceptance.py` on this Mac; the `acceptance` check on
     the phase's PR for Linux;
   - *the Score*: `scripts/eval.py --compare tests/eval/baseline.json` on this Mac;
     `gh workflow run eval.yml --ref <branch>` for Linux (from R9.6 on). Every track, the
     Score, each gate, and the delta against the baseline. A track more than 2 points under
     its baseline, or a failed gate that is judged by then (D21), fails the exit: fix it
     before the phase commit. Then `--update-baseline` records every track that rose.
3. `CHANGELOG.md` `[Unreleased]` is updated, and so are the status and Next lines of
   `CLAUDE.md`.
4. **The phase commit:** `chore(r<n>): close phase R<n>, <title>, exit measured`.
5. **Push and open one PR** for the phase, base `main`. Wait for the required checks (the
   app's PR monitor where the session has one, else
   `gh pr checks <number> --watch --fail-fast`), and fix any failure with new commits.
   **Do not land it.** The next phase's branch is cut from this one, so the phases stack,
   and the owner lands the stack with one fast-forward (§8).
6. **A release rehearsal**, for R16 only, runs on R16's pushed branch
   (`gh workflow run release.yml --ref <branch>`). Wait for its validation, then cancel it
   at the brake so the `release` concurrency group is free. The run id and outcome go into
   R16.5's STATUS and §8.
7. Re-arm the in-session schedule and start the next phase from this phase's branch.

## 5. Decisions recorded before the build

The owner accepted all of these on 2026-09-29: D21 to D38 with the review, including the
network changes D24 and D25 under `CLAUDE.md` §10, and D39 to D41 the same day. R9.2 writes
the ADRs. D42 to D46 were accepted on 2026-10-02, with the explanation of each item that
asked for them: D42 is the owner's choice among three, and D44 the owner's approval of a
hook under `CLAUDE.md` §4. D47 to D49 were accepted on 2026-10-03, when the owner asked
for the three additions proposed with them. D50 to D57 were accepted on 2026-10-03 with
the architecture review of that day, when the owner asked for its 1.x steps as phases;
D56 amends D47. D58 and D59 were accepted the same day, after the owner's first run on
a new project, and D60, which amends D42, when the owner asked for the rule-writing back. D61 the
same day, when the owner chose to run the build in a cloud session.
The owner may revisit any
decision with `/grill-with-docs`; a change becomes a new task, and the executor does not
wait for it.

| # | decision | fallback when a measurement disagrees |
|---|---|---|
| D21 | **The Score** (ADR-0026). One command, `scripts/eval.py`, runs the image under test over eight **tracks** and scores each 0 to 100 with the OWASP Benchmark's formula: per category, true-positive rate minus false-positive rate, averaged. A **case** is a path with a category and a label, vulnerable or safe; it is flagged when an active finding of its category lands on it. The tracks: **1 SAST-Python**, the OWASP Benchmark for Python v0.1 (1,230 cases, 452 real, 14 categories; 530 in the first version of this list, a miscount read from a summary and corrected by R9.4 from the file), a git checkout at a pinned commit in the build cache, never vendored (GPL-3.0); **2 SAST-JS**, valvur's own vulnerable and safe twins, ten CWEs AI code gets wrong (89, 79, 78, 22, 918, 94, 1321, 601, 798, 327); **3 secrets**, real formats assembled at runtime against decoys (documented example keys, placeholders, environment lookups), in files and in history; **4 dependencies**, lockfiles in seven ecosystems pinned to versions with advisories published before 2025-09-29 against their fixed twins, and `MAL-` packages sampled from ossf/malicious-packages at a pinned commit; **5 package reality**, nonexistent, near-miss and malicious names against real popular, real long-tail and privately registered ones; **6 agent configuration**, planted directives, hidden Unicode, blanket approval, hooks and leaking local settings against benign twins and awesome-cursorrules' real files; **7 infrastructure and workflows**, Terraform, Kubernetes, Dockerfile and GitHub Actions faults against fixed twins; **8 real-code precision**, the 13-repository corpus, where every active finding of a valvur-owned rule or of Gitleaks is labelled `tp` or `fp` in `tests/eval/labels/corpus.toml` with a reason, and the track is precision × 100 (an unlabelled finding fails the track, named); *amended by R9.5, measured: smoothed precision, 100 × (tp + 1) / (tp + fp + 1), since the corpus's 24 judged findings held no true positive and plain precision could not tell one false alarm from forty, nor score a silent corpus*. **The Score** is the unweighted mean of the eight. **Gates**, pass or fail: *freshness*, every dataset's data age at scan time within D24; *honesty*, no scan reads `clean` while incomplete, and no safe twin draws a high or critical; *offline*, every scan's `what_left_the_machine` is `nothing`; *ranking*, the dependency track's known-exploited CVE ranks first over a development-only critical; *speed*, the median warm scan of the acceptance set within 110% of the baseline. A gate is judged from the phase that builds what it checks, and recorded before: offline from R9, honesty from R10, freshness and ranking from R11, speed from R14. **The ratchet:** `tests/eval/baseline.json` holds each track, the Score and what they were measured on; `--compare` fails when a track falls more than 2 points under it or a gate fails, naming each; the baseline is re-recorded only upward, at a phase commit, with the reason. **Replication:** external sources pinned by git commit, the generator seeded, the image named by digest, and every dataset's age recorded; Trivy publishes no database history, so dependency cases use only advisories over a year old. Why not an exploit gym: SecBench.js, BaxBench and CyberGym score exploits against running code, which is dynamic testing, and valvur refuses it (`CLAUDE.md` §2). | if the OWASP Benchmark cannot be fetched at its pin, or its track exceeds 10 minutes, track 1 is valvur's own Python twins over the same 14 categories, and every surface says so |
| D22 | **Targets for `1.2.0`**, per track: SAST-Python 25, SAST-JS 50, secrets 90, dependencies 90, package reality 95, agent configuration 90, infrastructure and workflows 70, real-code precision 80; every gate green. A target under R9's baseline is raised to the baseline, never lowered. *Amended 2026-10-02 by D42, the owner's decision: SAST-Python, SAST-JS and real-code precision lowered to what `1.2.0` measured, 11.1, 15.0 and 3.7, the gap accepted.* | a missed target is recorded in the exit and in §8 for the owner; the build continues |
| D23 | **Every dataset's age is its data's** (F6.12, extending F6.11): KEV from the catalog's `dateReleased`; EPSS from its file's `score_date`; each OSV database from the `Last-Modified` its fetch recorded in a sidecar; the index and the database as now. | where a source carries no date, the fetch time, labelled *fetched*, never *built*, on every surface |
| D24 | **Refresh thresholds** (amends D5 and ADR-0025, as ADR-0027). A scan refreshes, announces and records: the vulnerability database and OSV's databases past 7 days, as now; the Name Index and the malicious list past **2** days (was 30); KEV and EPSS past **2** days (a scan never refreshed them). The thresholds that make a verdict `inconclusive` are unchanged. `fetch = "never"` fetches none. A failed refresh keeps the old data and says so. | none needed |
| D25 | **EPSS from FIRST's daily file** (F6.13, amends F6.3 and F6.10): `epss_scores-current.csv.gz`, fetched by `valvur update` and by a stale scan into the host cache, mirrorable as `epss_url`, read on every Profile; `full` no longer sends CVE identifiers to FIRST's API. Approved under `CLAUDE.md` §10 as a recorded fetch of public data. | if the file is over 20 MB compressed, or its host is unreachable from GitHub's runners, F6.3's API stays on `full`, `offline` ranks as now, and the README's ranking example says `full` |
| D26 | **Known-malicious names, daily** (F3.14): `index.yml` also publishes, as the tags `malicious` and `malicious-<date>` of the existing public `valvur-index` package, signed and pulled back like the index, a sorted list per ecosystem of `MAL-` package names and affected versions from ossf/malicious-packages (Apache-2.0, in `NOTICE`), built from OSV's export or the repository, whichever measures faster. `1.1.0`'s client pulls `latest` and is untouched; `retention.yml` keeps these tags as it keeps the index's. `dependency-reality` reports a declared or locked package in it as `valvur.dependency.malicious`, critical; a version-scoped entry matches only a locked version it names. OSV-Scanner's finding for the same package merges into it: one finding, both Scanners named. Until `index.yml` runs from a landed `main`, the build's lanes build the list locally, as `--build-index` does. | if the list exceeds 10 MB compressed, names only, and a version-scoped entry is reported at high as *a version of this package was published as malicious* |
| D27 | **Private registries** (F3.15). Read from the File Set: `.npmrc` and `.yarnrc.yml` (scoped and whole registries); `--index-url` and `--extra-index-url` in requirements files, `pip.conf`, `[[tool.uv.index]]` with `[tool.uv.sources]`, `[[tool.poetry.source]]` and a `Pipfile`'s `[[source]]`. A name whose scope or source is a private registry is not looked up publicly and is listed as a coverage note. A name absent from the public index where a supplemental source (`--extra-index-url`, a supplemental uv or Poetry source) is configured is `valvur.dependency.confusion`, **high**: the resolver may take a public package registered under it. Absent where the public registry is replaced entirely: `valvur.dependency.not-public`, **low**, advising the name be reserved. No configuration: `nonexistent`, high, as now, its message naming the index's build date and saying an internal package should declare its registry in the project. | none needed |
| D28 | **`check_package`** (F3.16, F9.11; ADR-0028). The API `valvur.packages.check`, the CLI `valvur check <ecosystem> <name>[@version] …` (a ninth command; exit 0 when every package exists and is not flagged, 1 when any is, 2 on error; `--json`) and an MCP tool `check_package` (up to 50 packages, `readOnlyHint` true, `openWorldHint` false). Each answer is `exists`, `nonexistent`, `near-miss` with the name it is near, `malicious` with its `MAL-` ID, `confusion` or `not-public` by D27, or `unknown` where no index exists (JVM, Go), with the index's build date. Host-side, **no network, ever**: asking a registry about a hallucinated name tells the registry, and anyone watching it, what to register. Under a second. The handshake's instructions and `SUMMARY.md`'s agent block say: before adding a dependency, call `check_package`, and never add one it flags without the human. | none needed |
| D29 | **Static-analysis rules by licence and measurement** (F2.9, F5.10; ADR-0029; amends ADR-0004's consequences). Candidates: GitLab's `sast-rules` (MIT, Semgrep syntax) at a pinned commit, for Python, JavaScript and TypeScript, Go and Java. A rule is eligible only if the project it was translated from, named by its metadata, is MIT, Apache-2.0 or BSD: rules from flawfinder, find-sec-bugs, security-code-scan or Brakeman are excluded. `opengrep-rules` (archived, Commons Clause) and Semgrep's registry stay excluded. A rule **ships** when, over tracks 1 and 2 and the corpus, it has at least one true positive and precision of at least 0.5; *amended by R13.6, measured: at least one of its true positives must be at a line valvur's own rules do not already report, since a rule that only repeats one of valvur's makes a second finding for each flaw under another id, never merged (GitLab's `subprocess` shell rule matched exactly the 14 lines valvur's own does).* Shipped rules live in `rules/vendor/gitlab/` with the licence, the commit and a manifest of each rule's origin, and carry their CWE into `findings.json` and SARIF (an optional field). Opengrep's intra-file cross-function taint is adopted if the pinned Opengrep supports it and it raises tracks 1 and 2 without raising their false-positive rate. Opengrep's median time on the acceptance set may grow at most 30%; past that the slowest rules go first. | if no candidate is eligible, valvur writes its own rules (Apache-2.0) for track 2's CWEs and track 1's categories, measured the same way |
| D30 | **A failed Scanner with nothing found reads `inconclusive`** (F7.19), `status_reason` naming the Scanner. With findings, `findings` and *incomplete*, as now. The three Statuses are unchanged; a false `clean` is removed, which 1.x's contract allows as a fix. | none needed |
| D31 | **Checkov runs without its secrets framework** (`--skip-framework secrets`): Gitleaks owns secrets. | none needed |
| D32 | **Reuse what cannot have changed** (N1.5; ADR-0030). Trivy's and OSV-Scanner's raw output is kept in the host cache, keyed on the Scanner, its version, the Profile, the sha256 of every lockfile and manifest they read, and the database's built time, and reused when the key matches. `run.json` names each reused result and the run it came from; `--fresh` on the CLI and `fresh: true` on `scan` run everything. Source-reading Scanners are never reused. | if a warm rescan of acceptance repository 8 is not at least 30% faster, reuse ships off by default, recorded |
| D33 | **A release is prepared by one command** (N3.4): `scripts/prepare_release.py <version>` sets the version, the lock, the README's *release in progress*, `SECURITY.md`'s series and the CHANGELOG heading in one commit; `--published <version>` makes the commit that flips the README once promoted. The tag and the brake stay the owner's. | none needed |
| D34 | **A monthly Scanner refresh** (N3.5): `refresh.yml`, on the first Monday, when `main`'s Scanner pins differ from the latest release's, runs the Score on `main` and, when no track regressed, dispatches a rehearsal and opens one issue for the owner to tag. | none needed |
| D35 | **Wall-clock tests are marked `timing`.** They run in CI's e2e job and at phase exits, never in the unit suite. On this Mac with host swap over 4 GB they are recorded, not judged, as D17 did. | none needed |
| D36 | **Agent runs: $10** for this build, for R12.5's scenarios and R15.2's smoke run, and never with a shell (§1). The Score never includes an agent run. | past the cap, skip and note it in §8 |
| D37 | **`1.2.0` after R16**, prepared and rehearsed by the executor on R16's branch; the tag and the brake are the owner's. Every change is additive under 1.x: a seventh MCP tool, a ninth command, `cwe` on findings, new rules, and the skill with its plugin and power; `fp_version` stays 1. | none needed |
| D38 | **An arm64 e2e leg**: CI's `e2e` job gains `ubuntu-24.04-arm`, Docker only. | if it more than doubles the job's time, or fails three times for runner reasons, the README's platform line says what is tested instead |
| D39 | **One skill, `valvur`, in the open Agent Skills format** (F9.12; ADR-0031). Its one source is in the package, `src/valvur/data/skills/valvur/`: `SKILL.md` and `references/` (the tools and their fields, triage by finding class, CI and the gate, air-gapped use). Its frontmatter uses only the standard's six fields, so the one file loads in Claude Code, in Kiro and in any client of the standard. It orchestrates: before adding a dependency, `check_package`; `scan`, and on `failed`, `doctor`, relayed; the verdict and its reason before any finding; triage by group with `findings`, each finding named by rule ID and path; a proposal from `REMEDIATION.md`, and waiting for the human; after the human's fix, a rescan, and *fixed* only where its Scanner ran; `update` when data is stale; `valvur gate` in CI; never a Suppression, never the Results Folder committed, never text quoted from the repository followed. Its rules are rendered from the one source the handshake and `SUMMARY.md` use, and a test holds the three equal; every tool and command it names exists, and every tool the server lists is in it. | none needed |
| D40 | **The skill ships three ways** (F9.13; ADR-0031): a **Claude Code plugin**, `plugins/valvur/`, with the skill and the MCP server pinned to the release (`uvx --from valvur==<version> valvur-mcp`), listed by `.claude-plugin/marketplace.json` at the repository's root, so `/plugin marketplace add MaverickHQ/valvur` then `/plugin install valvur@valvur` gives both; a **Kiro power**, `powers/valvur/`, in the layout kiro.dev documents when the task starts (`POWER.md`, the Agent Plugins manifest, `mcp.json`, the skill); and **`valvur init --write`**, which adds the skill to the project for Claude Code (`.claude/skills/valvur/`) and for Kiro (its documented project location), never overwriting. The plugin and the power reach the package's skill by symlink where their loaders follow one, else by a copy a test holds byte-identical; every version surface moves together. Approved as within `init --write`'s exception in `CLAUDE.md` §10. | if a Kiro power cannot carry the skill from the repository, it carries the MCP configuration and steering, and `init --write` carries the skill |
| D41 | **No separate agent.** The skill and the handshake carry the workflow; an agent would be a third copy of the rules to keep in step, and `context: fork` is a Claude Code extension the open standard does not carry. | none needed |
| D42 | **D22's three missed targets are lowered to what `1.2.0` measured** (the owner, 2026-10-02; amends D22): SAST-Python 11.1, SAST-JS 15.0, real-code precision 3.7, on both lanes. The gap is accepted, and no rule-writing phase is planned. The ratchet still holds each track within 2 points of its baseline, the README claims only what is measured, and a future decision may raise a target again. The other five targets stand, all met. *Amended 2026-10-03 by D60: a rule-writing phase is planned after all, R25; the lowered targets stand until the baseline passes them.* | none needed |
| D43 | **Every requirement ID cited is defined** (amends §3's last rule). `scripts/check_traceability.py` also fails on an `F<n>.<n>` or `N<n>.<n>` ID cited in the repository's documents, code, tests or workflows that `requirements.md` does not define, naming each with its first `file:line`. The first version's IDs, mapped in the archive, are exempt by that map, not by a list. Found by R16.4: N3.4 and N3.5 were cited by D33, D34, two scripts, two test files and a workflow for the whole build, and defined nowhere. | if more than 20 cited IDs are undefined on the first run, they are recorded in the traceability baseline as debt and only new ones fail, as uncited requirements are |
| D44 | **A hook that asks before an install** (the owner, 2026-10-02, under `CLAUDE.md` §4; F3.16). A Claude Code `PreToolUse` hook on the `Bash` tool, shipped in the plugin and pinned with its server (`uvx --from valvur==<version> valvur hook pre-tool-use`). When a command installs named packages, it runs the same check as `valvur check`, offline, and when any package is flagged it answers `ask` with each verdict, so the human decides. The commands: `npm`, `pnpm`, `yarn` and `bun` add and install; `pip`, `uv pip`, `uv add` and `poetry add`; `cargo add`; `gem install`; `composer require`. Otherwise it says nothing. It never answers `deny`, never runs or edits anything, and opens no socket. When valvur cannot check, because the index is absent, it answers `ask` naming the cause and `valvur update`, so the check is never silently off. It is not written by `init --write`: a hook in a project's own settings would run for every contributor without their choosing it. | if Claude Code's hook contract cannot carry `ask` from a plugin, the hook prints its verdicts as context and the skill's rule stands alone, recorded; Kiro gets the hook only if its documented hooks can do the same |
| D45 | **The runner move** (28.3.8, O5). GitHub's `ubuntu-latest` became 26.04 on 2026-10-19. On or after 2026-11-19, every `runs-on` and matrix runner moves from `ubuntu-24.04` to `ubuntu-26.04`, and `-arm` likewise; the corpus, the acceptance set and the Score run on the move; N1.1 and N1.4 are measured against their 24.04 numbers and recorded in `requirements.md`. | if Podman or unprivileged user namespaces fail on 26.04 three times for runner reasons, the jobs that need them stay on 24.04, and the README's platform line says what is tested where |
| D46 | **Agent runs: $5** for R17 to R19, for R18's smoke run alone, which is the one agent run that needs a shell to reach the hook. It runs in an empty scratch directory with stub `npm` and `pip` first on `PATH`, which record their arguments and exit, so no package is ever installed; the names asked for are made up and never published. | past the cap, the smoke run is replaced by replaying recorded hook inputs through the plugin's command, and §8 says so |
| D47 | **The noise real projects draw** (F7; tracks 3 and 8; amends the verdict as D30 did, as a fix 1.x allows). On the 13-project corpus every one of 26 judged findings is a false alarm. Of them, 16 land in test, fixture or docs paths and 11 in source (R17's labels, measured 2026-10-03). Three changes, each measured before it ships. **(a) The sink inventory is inventory.** valvur's information-level sink rules (`dangerous-exec`, `dangerous-eval` and the rest of the inventory) stay in `findings.json`, marked `inventory`. `SUMMARY.md` counts them under *Sinks to review*. They no longer make a verdict `findings` by themselves, and a project whose only results are inventory reads `clean`. **(b) Secrets in fixtures and docs rank last.** Gitleaks findings whose path has a segment `tests`, `test`, `__tests__`, `spec`, `fixtures`, `testdata`, `examples` or `docs`, or a name `test_*` or `*_test.*`, become `low` and carry a `fixture` tag. They are still reported and still active, never suppressed. The match is on whole segments: the OWASP Benchmark's cases live in `testcode/`, and a substring rule would erase track 1. **(c) Non-security hashing and randomness.** `weak-hash` does not fire on `usedforsecurity=False`. `weak-hash` and the vendored `random` rule do not fire under the fixture paths of (b). *Amended 2026-10-03 by D56: (b) and (c)'s paths are path classes, decided once by the File Set; (b) and (c) are the first rows of one table that decides what a class changes; and (b)'s `fixture` tag is the finding's `context`.* | each change ships only if tracks 1 to 7 stay within the ratchet's 2 points; one that costs more is withdrawn and recorded, as D29 does for a rule |
| D48 | **Findable** (F10). **(a) A demo:** one CLI scan of acceptance repository 8, recorded by a script that regenerates it, committed under `docs/` as an animated SVG under 1 MB and shown in the README's first screen. No hosted service is used. *Pre-flight, 2026-10-03: the script renders the SVG itself from the CLI's captured output, with the standard library alone, so no recorder is installed during the unattended build.* **(b) Ready to list:** the README gains *Privacy*, valvur collects nothing, with the proof's link, and *Support*, the issue tracker. Kiro's catalog requires both. `docs/LISTING.md` holds the text each directory asks for, the plugin's and the power's, drawn from their manifests. Submitting stays the owner's (§8). | if the recorder cannot run headless on this Mac, the README shows a captured terminal transcript instead, as text, and §8 says so |
| D49 | **OpenSSF signals** (N3). **(a) Scorecard:** `scorecard.yml` runs `ossf/scorecard-action`, pinned by commit, weekly and on `main`, with `publish_results: true`. That uploads its results to the public OpenSSF API and earns the README badge; the result describes the repository, never a user's code. Permissions are the action's documented minimum (`security-events: write`, `id-token: write`) and nothing more. The first score and each check below 10 are recorded, and the cheap ones are fixed. *Pre-flight, 2026-10-03: Scorecard publishes only from the default branch, so `publish_results` is true on `main` alone. R22.1 measures on its branch with publishing off, and the published result and the badge's score arrive when the owner lands R22.* **(b) Best Practices:** `docs/BEST-PRACTICES.md` answers every *passing* criterion of the OpenSSF Best Practices badge with a link to its evidence. The form itself needs the owner's account (§8). | if a Scorecard check needs a setting only the owner can change (branch protection's review count, say), it is listed in §8, not worked around |
| D50 | **The host side in four layers** (the review of 2026-10-03, §3.1). `core` holds the Finding, identity, the verdict, ranking and path classes, with no I/O. `app` holds the scan service, the read models and the jobs. `infra` holds the runtimes, the datasets, the registries, git, the OCI client, the adapters, and the image's side, `engine` and `checks`. `surfaces` holds the CLI, the MCP server and the hook. Each layer imports only from the layers below it. `scripts/layers.toml` assigns every module under `src/valvur` to one layer. **Modules are not moved,** so every import path stays: the protocol's entry points (`python -m valvur.engine`, `python -m valvur.checks`) and the console scripts included. `scripts/check_layers.py` reads the AST with the standard library, as `check_traceability.py` does, and runs in `verify.sh`. It fails on an import that points upward, deferred imports included, and on a module in no layer. The upward imports found on its first run are a baseline that may only shrink, and R23's exit empties it. `valvur/__init__.py` exports `scan`, `ScanRun`, `ScannerFailed`, `Finding` and `__version__` lazily (PEP 562), so the public names stay, and importing a module no longer loads `api`: measured, `import valvur.hook` loads 52 of valvur's modules today. | if the baseline cannot be emptied without changing a contract, what remains is listed in R23's exit with each reason, and §8 holds it for the owner |
| D51 | **One scan service** (review §3.2). The CLI's `scan` and the MCP tool both run a scan through one function, `service.run_scan`. It owns the runner, the locks, the budget and cancellation. The MCP job wraps that call in its thread and adds nothing else. The CLI's text, the MCP reply's fields and its text render from one read model of the result, and their output is unchanged, held by goldens. `operations` and `reply` import nothing from `valvur.mcp`: what they need of a job is passed in. `Job.summary`, `operations._summarise`, `start_scan` and `_run_scan` are deleted, since nothing reads them. A `scan_cancel` that arrives before the scan's job exists is held for the scan about to start: the backlog row R6 left in §8, moved here. | none needed |
| D52 | **Each concept modelled once** (review §3.3). **(a) Datasets.** One table, `valvur.datasets`, holds each dataset's source setting, verifier, age reader, refresh threshold, `inconclusive` threshold and mirror. A scan, `update`, `doctor`, `run.json` and the reply all read it. The thresholds stay D24's. `update --if-stale` refreshes exactly what a scan would, KEV and EPSS included (a scan's refresh is already an approved fetch, ADR-0027). **(b) Active.** One predicate decides that a Finding counts, for the in-memory form and for `findings.json`'s records, and the six sites that decide it today call it. **(c) The network grant** is `Invocation.network` alone. The engine sets `VALVUR_NETWORK` for each granted tool in every runtime, the in-image runtime included. **(d) A scan context**, built once per scan, holds the File Set, the parsed `.security-scan.toml` and the settings, and is passed to the adapters, the pipeline and coverage. **(e) One function builds a container's flags,** for the Scan Container and for the database fetch. | none needed |
| D53 | **Typed messages inside** (review §3.4). The engine's events carry a `kind` and fields. Prose is rendered only at a surface, and the reply reads kinds, never a prefix. The text the MCP client and the CLI show is unchanged. The budget's state is a field of the outcome. `Runtime` and `ScannerAdapter` declare every member `app` uses, and no `getattr` is called on a runner or an adapter. `mypy --strict` holds `core`. | a `core` module that needs a behaviour change to pass `--strict` stays at the current level, listed in R23's exit |
| D54 | **The four lapses the review found, fixed** (review §3.5; fixes 1.x allows). **(a)** `/tmp` is `noexec` for every tool. Opengrep's core is unpacked at image build, so no tool needs an executable `/tmp`, and `allow_exec` goes. That also saves the 243 MB Opengrep unpacks on every scan. **(b)** On `full` in the image, dependency-reality asks the registry questions, through D52(c). **(c)** `VALVUR_CACHE`, then the `cache` setting, win over `XDG_CACHE_HOME`. **(d)** The Profiles share one Scanner list, since they run the same Scanners and differ in the network grant. `run.json` keeps `scanners_not_run` for its schema. The dead code and duplicated constants the review names go with these. | if Opengrep cannot run from an unpacked tree, `/tmp` stays executable for the Scan Container, and `invocation.py` and `PROTOCOL.md` say so truthfully; recorded |
| D55 | **The machinery made lighter** (review §4.3, §4.4). **(a) Generated, not compared.** `scripts/generate_docs.py` writes marked blocks, `<!-- generated: <name> -->` to `<!-- /generated -->`, from the code: the MCP tools and their fields, the protocol's paths and pins, the settings and their variables, and the CLI's commands. The blocks sit in the README, `PROTOCOL.md`, `AIR-GAPPED.md` and the skill's `references/tools.md`. One test regenerates every block and fails on a difference, naming the block. Each test that compared one of those facts with prose is deleted in the commit that adds its block. A test stays where the sentence is the contract, and the constraint suite keeps its 54. **(b) No test writes the repository.** `scripts/sync_skill.py` refreshes the plugin's and the power's copies of the skill, and `prepare_release.py` runs it. `UPDATE_SKILL` goes. **(c) One version source.** Workflows read the version through one composite action, and the issue-on-failure step is one composite action too. **(d) CI builds once.** Each architecture builds the image once per commit, and the e2e, the self-scan and the reproducibility comparison use that build. Only the second reproducibility build is made again, with no cache. The eight required checks keep their names, so landing needs no change to branch protection, which is the owner's (pre-flight, 2026-10-03). **(e) Planning IDs.** New tests are named for what they test. New comments in `src` cite ADRs and requirements, not tasks. Existing ones change only when they are touched. **(f) The archive is a record** (amends D43). `check_traceability.py` no longer reads `docs/history`. | if handing the image between jobs takes longer than building it, the jobs build their own as now, recorded |
| D56 | **Path classes** (review §5; amends D47, reshaping R20). The File Set gives every path one class: `source`, `test`, `fixture`, `docs`, `example`, `vendored` or `generated`. It matches whole segments, as D47(b) lists them. `vendor`, `third_party` and `node_modules` are `vendored`. A path `.gitattributes` marks `linguist-generated`, or whose first lines say it is generated and not to be edited, is `generated`; only paths a finding lands on are read. Each finding carries its path's class as `context`, in `findings.json` and in SARIF's `properties`. The field is additive, and identity and `fp_version` are unchanged. One table in `core` decides what a class changes, and D47's (b) and (c) are its first rows. A secret in `test`, `fixture`, `docs` or `example` ranks `low` and stays active. `weak-hash` and the vendored `random` rule are not reported in those classes, and `run.json` counts what the table removed, by class and rule, so nothing disappears without a number. A class with no row changes nothing. D47(a) and the `usedforsecurity=False` half of D47(c) concern rules, not paths, and stand as written. | a row that costs tracks 1 to 7 more than 2 points is withdrawn and recorded, as D47 says |
| D57 | **2.0 is scoped here, not planned** (review §4.1, §4.2, §5). **Three artifacts, versioned apart:** the host side on PyPI; the Scanner image, versioned by protocol and rebuildable for an advisory without a host release; and the rules and Check data, a signed OCI artifact tagged only when the Score holds. The host accepts a compatible range and records each digest in `run.json`. **Protocol 3:** the engine emits normalised findings, which the host validates against the schema and still neutralises. **Reuse by declared inputs:** ADR-0030 generalised to every Scanner that declares what it reads. **One settings model:** two files, the project's and the machine's, with environment variables only as overrides. Its phases are written when the owner asks, after R24's exit, each part with its ADR. Until then 1.x keeps protocol 2, `fp_version` 1, the reply's schema 2 and every documented setting. | none needed |
| D58 | **The first run in a new project** (the owner, 2026-10-03). The plugin worked on a new project: the skill loaded, the scan ran, and the reply led with the verdict and a ranked list. Under Claude Code's *don't ask* permission mode, the `scan` tool and the shell were both refused, and the agent found the way out on its own. **(a) The plugin first.** The README's first screen gives the plugin's two commands as the first way in, and `uvx valvur scan` second. **(b) The permission rule, documented, never written.** The README and the skill's references give the allow rules for a mode that refuses unlisted tools: the read-only tools (`check_package`, `findings`, `scan_status`, `doctor`); `scan`, which writes only the Results Folder and fetches only public data; and `scan_cancel`. `update` is left to ask. valvur writes no permission rule into any settings file: a rule in a project's settings grants it to every contributor's agent, which is why D44 keeps the hook out of `init --write`. **(c) When a tool is refused,** the skill says so, gives (b)'s allow rules and the pinned `! uvx valvur==<version> scan`, and changes nothing else. A test holds the pin to the release, and `prepare_release.py` moves it. **(d) The hook under *don't ask*, measured.** Under `claude -p`, the hook's `ask` became a refusal (R18.4). One smoke run, with R18.4's harness and D46's stubs under *don't ask*, records what that mode does with it, capped at $2. | if *don't ask* lets a flagged install through, the README and D44's record say which modes the hook protects, and §8 holds it for the owner; past the cap, the result is recorded as not measured |
| D59 | **The loop closed** (the owner's run on a new project, 2026-10-03). The agent edited three findings and could not rescan, so nothing was confirmed, and the run felt unfinished. Today a rescan names what it fixed by title alone, which cannot be matched line for line with the first report. **(a) A resolution table.** On a rescan, `SUMMARY.md` and the `scan` reply open with every finding of the previous run, named by rule ID and path as the first report named it. Each gets its state now: `fixed` (its Scanner ran again and the finding is gone), `open`, or `not re-checked`. New findings follow. The reply's field is additive under schema 2. **(b) The skill closes the loop.** After the human's fixes, the agent rescans and leads with that table. When it cannot rescan, it says nothing is confirmed until a rescan, and names the findings it changed. **(c) Lookups the human can run.** For a fix that needs data valvur does not hold offline, `REMEDIATION.md` gives the exact command and the line to write. For zizmor's `unpinned-uses`, that is `gh api repos/<owner>/<repo>/commits/<ref> --jq .sha` for each action, and the `uses:` line with the SHA and the tag as a comment. valvur runs none of them. | if the table would push `SUMMARY.md` past its bound, it lists the first 20 by rank and counts the rest |
| D60 | **The code rules find more** (the owner, 2026-10-03; amends D42). This is the work D42 set aside. On track 1, the command-injection rule flags all 7 safe cases (the category scores below zero), the code-injection rule flags all 33 safe ones (zero), and 8 of 14 categories find nothing. On track 2, 8 of 10 types find nothing. **Order:** first, command and code injection learn to tell safe code from unsafe, using Opengrep's taint mode where it is measured to help (worth about 10 points on track 1). Then Python's path traversal, secure cookies, open redirects and XXE. Then JavaScript's SQL injection, command injection, path traversal and SSRF. **Every rule ships by D29's bar:** from a licence-audited source, or valvur's own (Apache-2.0); at least one true positive at a line no other rule reports; precision of at least 0.5 over tracks 1 and 2 and the corpus; track 8 not lower; and Opengrep's median time on the acceptance set at most 30% higher. **Aims, not gates:** D22's first targets, 25 for track 1 and 50 for track 2. What is measured is recorded, and D42's lowered targets stand until the baseline passes them. The MD5 and `random` rules earn track 1 points and cost track 8; R20's path classes resolve that, which is why R25 follows R20. | a rule below the bar is not shipped, and is recorded as D29 does; where no source has an eligible rule for a category, valvur writes its own, measured the same way |
| D61 | **The build may run in a Claude Code cloud session** (the owner, 2026-10-03, on promotional credit that expires 2026-11-04). The session's VM is Ubuntu 24.04 on x86_64, with 4 vCPUs, 16 GB of memory, 30 GB of disk and Docker. What changes there: **(a) Lanes.** The VM is the exit's local lane, beside GitHub's Linux lane. The Mac lane is not available: each exit records it as *pending*, and §8 holds one Mac run of the acceptance set and the Score over the landed stack, before the next release. **(b) The gate** is `scripts/verify.sh`, piped only under `set -o pipefail`, with the commit chained by `&&`, never `;`. It passes in a session: the signers test steps over the session's signing key and verifies through `ssh-keygen` by name. **(c) Caches.** The VM starts empty, so `VALVUR_CACHE` and `VALVUR_IMAGE` come from the environment (`$HOME/.cache/valvur-build`, `valvur:dev`). The image, the data, the OWASP Benchmark, GitLab's rules at the manifest's commit and the corpus are fetched on first use, from hosts §1's stop condition 5 already allows. A session does not start Docker's daemon, so every session starts it, as `dockerd --feature containerd-snapshotter=false` in the background (the VM runs as root), before stop condition 4 applies. On the default containerd store, bake's export fails: `rewrite-timestamp` conflicts with `unpack` (measured). **The image is built by `scripts/cloud_image.py`**, never plain `docker buildx bake`. The session's network re-terminates TLS with its own CA, which a build's `RUN` steps do not trust, so the script hands the build the host's CA bundle as a secret for `RUN` steps only (measured with a test CA on 2026-10-03: apk and pip both trust it through `SSL_CERT_FILE`). **The vulnerability database** is fetched by Trivy inside a container, which rejects the session's CA (`x509: certificate signed by unknown authority`, measured). The environment therefore sets `VALVUR_DB_REPOSITORY=mirror.gcr.io/aquasec/trivy-db:2` and `VALVUR_DB_INSECURE=1`, the product's documented switch for a certificate the container does not trust. They are set in the cloud environment alone, never in the repository, and the Linux and Mac lanes fetch with verification as before. **A fixture is never scanned in place:** it is copied to a scratch directory first. A Results Folder left in one is read as a previous run by every test that copies it, and `test_fixtures_unscanned.py` names it. Docker's build cache is pruned whenever the disk has under 8 GB free. **(d) Long commands.** A command that can pass 10 minutes (an image build, the e2e suite, the acceptance set, the Score) runs in the background. **(e) Resuming.** The session runs with the laptop closed, so §2's in-session schedule and desktop task are not armed. If the session stops (a usage limit, or a reclaimed VM), the owner starts a new cloud session with §2's prompt, and §2's step 1 still decides whether another executor is alive. **(f) GitHub.** Pushes, pull requests and workflow dispatches go through the session's GitHub proxy. `gh` refuses every GraphQL call there (`HTTP 403`, measured), so REST is used: a pull request is opened with `gh api -X POST repos/MaverickHQ/valvur/pulls -f title=… -f head=… -f base=main -f body=…`, and its checks are read from `gh api repos/MaverickHQ/valvur/commits/<sha>/check-runs`. `gh workflow run` works as it is. The proxy refuses tag pushes and branch deletions, and the executor still never pushes to `main`. **(g) Signed commits, measured.** A session's commits are SSH-signed as `Claude <noreply@anthropic.com>`, and GitHub verifies them, so `main`'s rule accepts them and they land as they are, as Dependabot's do. **(h) Left for a local run:** R21.3's smoke run, which needs `claude -p` with the owner's login. R21.3 is ticked with that behaviour recorded as deferred, and D58's $2 stays unspent. The owner's personal skills and memory are not in the VM; this list and `CLAUDE.md` carry what the build needs. **(i) Runtime fetches, measured by the second pre-flight.** With the database fetched through the mirror switch, everything a phase measures works in the session: scans on `offline` fetch nothing inside a container, and neither does the Score or the acceptance set. Two things still need a network inside a container and fail there: a `full` scan's registry and OSV questions, and the e2e test in which Syft pulls an image from Docker Hub. A failure counts as cloud-only when it is a network or certificate error inside a container and the same test passes in CI's e2e on the phase's pull request. The exit names each one, and none counts toward stop condition 3. **(j) Readiness.** Every session checks, before its first task: the daemon answers, the image is built by the script and `check_image.py` passes, and `valvur update` fetches the database. If the database cannot be fetched, the session stops there, under stop condition 4, and §8 says so. | if the VM cannot build or run the image, the build stops there (stop condition 4) and continues on the Mac |

## 6. Order

```
R9 the Score ─► R10 trust fixes ─► R11 fresh data ─► R12 check_package
                                                           │
R16 drag, documents, 1.2.0 ◄── R15 skill ◄── R14 reuse ◄── R13 static analysis
```

- **R9 first**, so every later exit is judged against a measured baseline, as R2 was.
- **R10** is hours of work that removes the false clean and the false positives users see
  first.
- **R11 before R12**: `check_package` reads the malicious list R11 publishes.
- **R13 after the Score exists**, because a rule ships only on its measured precision.
- **R14** changes speed alone, so it follows every change to what is found.
- **R15 after the tools are final**, because the skill names every tool and field.
- **R16** closes the documents against what exists and prepares `1.2.0`.

```
R17 targets recorded, IDs defined ─► R18 the install asks first ─ ─ ─► R19 the runner move
                                                                       (on or after 2026-11-19)
```

- **R17 first**: both are small, and D43's check guards the IDs R18 adds.
- **R18** is the feature, built on a check that already exists (`check_package`, R12).
- **R19** waits for its date; it changes where CI runs, not what valvur does.

```
R23 layers ─► R24 machinery ─► R20 noise ─► R25 code rules
                                                  │
R19 (dated) ◄─ ─ ─ R22 OpenSSF signals ◄── R21 findable
```

- **R23 first**: it changes no contract and no number, and every later phase lands in its
  layers. R20's path classes go into `core`, and their table beside ranking.
- **R24 next**: it replaces the tests that compare prose before R20 changes the reply and
  `SUMMARY.md`, so R20 pays once. Its CI changes come before R22 measures the workflows.
- **R20** changes what a scan reports, so it is judged by the Score before the documents
  and the demo show it.
- **R25 after R20**: path classes decide where the MD5 and `random` rules fire, and every
  new rule is measured with the noise already cut.
- **R21** records the demo after R20 and R25, so the demo shows the quieter, fuller output.
- **R22** measures the repository as R20 and R21 left it.
- **R19** keeps its date and comes last in §7. R23 comes first there, so
  `build_status.py` finds it first.

---

## 7. The phases

Phases R9 to R15 are closed, each task with its STATUS, in
[the archive](../../../docs/history/tasks-phases-r9-r16.md) (moved by R16.4).

Phase R16 is closed too, in the same archive.

### Phase R17: the targets recorded, and every cited ID defined

- [x] **R17.1** **The three targets, as the owner decided** (D42). D22 is amended by a note;
  `EVALUATING.md`'s Score section and `docs/acceptance/r16.md`'s target column say the
  targets were lowered to the measured values on 2026-10-02, and why; §8's two target rows
  close. Behaviours: traceability holds; the link check passes; `test_readme_as_built.py`
  passes, the README claiming nothing past the baseline.
  **STATUS 2026-10-02:** ✅ all three. D22's row carries D42's amendment.
  `EVALUATING.md` says which three targets were lowered, to what, and that the gap is
  accepted. It also names the false alarms real code still draws. `docs/acceptance/r16.md`
  says every target now stands met at `1.2.0`. §8's two target rows closed with the list's
  amendment. The README already claims only the measured 11.1 and 15.0, which its as-built
  test holds.
- [x] **R17.2** **Every requirement ID cited is defined** (D43). Behaviours:
  1. an `F` or `N` ID cited in a scanned file and defined nowhere fails the check, named
     with its first `file:line`;
  2. an ID of the first version, mapped in the archive, passes;
  3. the files read are the documents, `src/`, `scripts/`, `tests/` and the workflows,
     and a test holds that list;
  4. the repository passes today, so R16.4's N3.4 and N3.5 are the last such gap.
  **STATUS 2026-10-02:** ✅ all four, with no baseline: nothing is undefined today, so D43's
  fallback and its map-based exemption were not needed.
  - **The check.** `check_traceability.py` now fails on an `F` or `N` ID cited in
    `CITING` and defined in no `requirements.md` line, naming its first `file:line`.
    `CITING` is `.kiro`, `docs`, `src`, `scripts`, `tests` and `.github`, plus the five
    top-level documents. `requirements.md` itself is read, so an amendment that names a
    missing ID fails too.
  - **Proved on history.** Run on R16.4's tree before N3.4 and N3.5 were written
    (`3bb5835`), it names exactly those two, at D33's and D34's rows in `tasks.md`.
  - **No exemption needed.** The archives cite 156 defined IDs and no undefined one:
    IDs are never renumbered, so the first version's still resolve, and the archives are
    checked like everything else.
  - **Tested** in `tests/test_traceability_defined.py`, five tests. Its own made-up IDs
    are assembled at runtime, since the check reads the tests too.

**Exit:** traceability holds under the new rule, and the unit suite and CI are green. The
Score is unchanged on both lanes; nothing here touches detection.

**Exit STATUS 2026-10-02** (`docs/acceptance/r17.md`):
- **Traceability:** ✅ holds under the new rule: 0 uncited, 0 orphan ADRs, every cited ID
  defined.
- **The Score:** ✅ 64.9 on both lanes, every track at its baseline. Linux run 37042462329.
  The four gates judged are green.
- **The suites:** ✅ 1770 unit tests on the Mac; CI on #175.

### Phase R18: the install asks first

- [x] **R18.1** **Read and measure first** (D44). Read Claude Code's hook documentation and
  record, with each source:
  - the `PreToolUse` event and its matcher;
  - the fields on stdin, and the decision output, `ask` in particular;
  - how a plugin declares a hook (`hooks/hooks.json`, `${CLAUDE_PLUGIN_ROOT}`).

  Read Kiro's hook documentation the same way. Collect the install commands agents
  actually wrote in R12.5's scenario transcripts and the acceptance agent runs. Behaviour:
  the STATUS records each fact with its source, and each command form with its count.
  **STATUS 2026-10-02:** ✅ read and measured.
  - **Claude Code's hook contract** (code.claude.com/docs/en/hooks.md;
    plugins/manifest-reference.md, plugins/components.md):
    - `PreToolUse` with `"matcher": "Bash"`.
    - On stdin: `tool_name`, `tool_input.command`, `cwd`, `session_id`,
      `hook_event_name` and `permission_mode`.
    - The answer is `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
      "permissionDecision": "ask", "permissionDecisionReason": …}}`. `ask` shows the
      permission dialog, with the reason, to the user and the model.
    - Exit 0 with no output means the usual permission flow. Exit 2 blocks, which D44
      forbids. A timeout does not block; the default is 600 s.
    - A plugin declares hooks in `hooks/hooks.json` under a top-level `"hooks"` key,
      with `${CLAUDE_PLUGIN_ROOT}`.
    - **Not documented:** what `ask` does under `claude -p`; where the hook fires
      relative to `--allowedTools` and `--disallowedTools`; whether plugin hooks are on
      by default; whether `plugin validate` reads `hooks.json`. R18.4's smoke run
      measures the first.
  - **Kiro** (kiro.dev/docs/hooks/, /hooks/types/, /hooks/actions/, /permissions/, and
    the Agent Plugins spec): a `PreToolUse` command hook on `shell` can only allow (exit 0)
    or block (exit 2). No hook can ask, and powers cannot carry hooks: the spec leaves
    hooks out on purpose. `permissions.yaml` can ask, but only by static globs. **By
    D44's fallback, Kiro does not get the hook**; the skill's rule stands alone there.
  - **Install commands agents wrote** in R12.5's scenarios and R7's agent runs, which had
    no shell: `pip install -r requirements.txt` 2, `pip install` 1, `npm install` 1. The
    `-r` file form must be read; a bare install has no names to check.
  - **Measured: the pinned command costs about 0.45 s warm**, against 0.06 to 0.14 s for
    bare Python (three runs each). Paid before *every* shell command, that is too much.
    So the plugin's hook is a shell script that runs `uvx` only when the command names an
    installer: a `grep`, milliseconds, and chains are still caught. The script carries
    the pin.
- [x] **R18.2** **Install commands, parsed** (D44). Behaviours, one test each:
  1. npm, pnpm, yarn and bun names, with versions, tags and scopes;
  2. pip, `uv pip`, `uv add` and poetry names, with specifiers and extras;
  3. `-r requirements.txt` read as the file it names, from the command's directory;
  4. cargo, gem and composer names;
  5. each command of a chain (`&&`, `;`, `|`) parsed on its own;
  6. flags, URLs, paths and git references are never taken for names;
  7. a command that is not an install, or an install with no names (`npm ci`,
     `npm install`), yields nothing: the lockfile's packages are the scan's.
  **STATUS 2026-10-02:** ✅ all seven, in `valvur.installs.packages(command, cwd)`, which
  returns `check`'s own `(ecosystem, name, version)` tuples and runs nothing.
  - **Splitting.** Commands are split at `&&`, `||`, `;`, `|`, `&` and parentheses.
    Each is read without its variable assignments, `sudo` or `env`. Quoted text stays
    text, so `echo 'npm install x'` names nothing, and a command that does not parse
    names nothing.
  - **What is read.**
    - npm, pnpm, yarn (`global add` too) and bun, with scopes, tags and ranges.
    - pip, `pip3`, `python -m pip`, `uv pip`, `uv add` and `poetry add`. An exact pin
      gives the version; a range gives none, since it names no version.
    - `-r` and `--requirement`, read as the file they name, with comments, options and
      direct references skipped and nested `-r` followed three deep.
    - cargo, gem (`-v` belongs to the name before it) and composer.
  - **Never a name:** flag values, paths, URLs, archives and wheels, git references,
    GitHub's `owner/repo`, `name @ url`, and every name of a `cargo add` from `--git`
    or `--path`.
  - **Slices.** Behaviours 5 to 7 passed on arrival: slices 1 and 2's splitter and spec
    filters already did what they test. They are committed as the tests that hold it.
  - **Seen once in the gate:** `test_cli_parity`'s `doctor` case failed in one full run
    and passed alone and in the next. It probes the real Docker, so a container
    starting or stopping between its two calls can change the answer. Not this task's.
    It is in §8.
- [x] **R18.3** **The hook answers** (D44). `valvur hook pre-tool-use` reads Claude Code's
  input on stdin. Behaviours:
  1. a flagged package: `ask`, with each package's verdict and reason;
  2. nothing flagged: no output, exit 0;
  3. a tool other than `Bash`, or a command that installs nothing: no output;
  4. no index: `ask`, naming the cause and `valvur update`;
  5. it never answers `deny` and never runs the command;
  6. no socket is opened (the conftest guard);
  7. 50 names in under 1 s (`timing`).
  **STATUS 2026-10-02:** ✅ all seven, in `valvur.hook`.
  - **The entry point is `valvur-hook`,** a console script beside `valvur-mcp`, not a
    `valvur hook` subcommand as D44 first wrote it: the CLI keeps its nine commands,
    which a test and the README hold.
  - **What it answers.** It reads the event and, for a `Bash` call that installs named
    packages, runs `packages.check` on up to 50. When any is flagged, or cannot be
    checked for want of an index, it prints one `ask` with a line per package and its
    reason. Otherwise it prints nothing.
  - **What it never does.** It always exits 0, so it never blocks. A test makes process
    launches and socket connections raise, and five commands, `rm -rf /` among them,
    pass without either.
  - **Measured against the real index** (4.4 million npm names): 50 names in 0.16 to
    0.30 s through the installed script, of which 45 made-up names were flagged.
  - **Slices.** Behaviours 2 to 6 passed on arrival: slice 1's `answer` already held
    them. They are committed as their tests.
- [x] **R18.4** **Shipped in the plugin** (D40, D44). Behaviours:
  1. `plugins/valvur/hooks/hooks.json` names the hook, pinned like the server, and
     `test_version.py` holds the pin, which `prepare_release.py` moves;
  2. `claude plugin validate --strict` passes;
  3. recorded hook inputs replayed through the plugin's own command line answer as R18.3
     says;
  4. the smoke run, under D46: `claude -p` with the plugin, asked to install a made-up
     npm package. It passes when the transcript shows the hook's `ask` and the stub
     `npm` recorded nothing.
  **STATUS 2026-10-02:** ✅ all four.
  1. **Declared.** `plugins/valvur/hooks/hooks.json` holds one `PreToolUse` hook on
     `Bash`, with a 30 s timeout. It runs `sh "${CLAUDE_PLUGIN_ROOT}/hooks/pre-tool-use.sh"`.
     - The script exits at once unless the command names an installer, so valvur starts
       only for installs (R18.1's 0.45 s).
     - It then runs `uvx --from valvur==<version> valvur-hook`, or `VALVUR_HOOK` when
       set.
     - `test_version.py` holds the pin, and `prepare_release.py` moves it, so a release
       now sets 15 files.
  2. **`claude plugin validate --strict`** passes with the hook.
  3. **Replayed through the plugin's own command.** A flagged install asks; a real
     package, another tool, or a command naming no installer says nothing, the last
     without starting valvur.
  4. **The smoke run**, `scripts/acceptance/hook_smoke.py`: `claude -p` with the
     plugin, `Bash` allowed, every installer and fetcher a recording stub, asked to
     install a made-up npm package.
     - **What `ask` does under `-p`,** which the hook documentation does not say:
       Claude Code turns it into a `permission_denied`, with
       `decision_reason_type: "hook"` and the hook's reason. The model received the
       reason and reported it.
     - The stubs recorded no install. It passed twice: the exploratory run, $0.69, and
       the script's, $0.38. D46 stands at $1.07 of $5.
- [x] **R18.5** **Said where it matters.**
  - `CLAUDE.md` §4 records the owner's approval of this one hook.
  - The skill and the README's skill section name the hook, and `valvur init` says the
    plugin brings it.
  - `CHANGELOG.md` `[Unreleased]` gains it.

  Behaviours: the skill's tests and the documented-commands test pass; `CLAUDE.md` stays
  under 200 lines.
  **STATUS 2026-10-02:** ✅ both.
  - **`CLAUDE.md` §4** names the one hook and the owner's approval (D44); 199 lines.
  - **The skill's first step** says the plugin's hook also asks; the plugin's and the
    power's copies were refreshed and are held byte for byte.
  - **The README's plugin line** says what the hook does and never does.
  - **`valvur init`** says the plugin brings the hook.
  - **Specs.** F3.16 carries R18's amendment, Kiro's lack included. `design.md` §6f
    describes the hook, from the prefilter to `-p`.
  - **`CHANGELOG.md` `[Unreleased]`** gains it.
  - **Tests:** the skill, plugin, power, version, init and documented-commands tests
    pass, and traceability holds.

**Exit:** every behaviour green; the smoke run recorded, or D46's fallback; the Score
unchanged on both lanes; the acceptance set green on both lanes. A release of this is the
owner's choice (§8).

**Exit STATUS 2026-10-02** (`docs/acceptance/r18.md`):
- **Behaviours:** ✅ every one green, 1790 unit tests.
- **The smoke run:** ✅ the hook stopped the install under `claude -p`, and nothing was
  installed. D46: $1.07 of $5.
- **The Score:** ✅ 64.9 on both lanes, Linux run 37049523602. All five gates are green
  on the Mac.
- **The acceptance set:** ✅ both lanes, Linux run 37052248266. Repository 6's pin moved
  to 1.2.0's commit after urllib3's advisories reached the old one.
- **The suites:** ✅ e2e 85 passed on the Mac.

### Phase R23: the host side in layers

Internal only: no contract changes, and the Score unchanged on both lanes.

- [x] **R23.1** **Measure first** (D50 to D54). Record:
  - the import graph: modules, cycles with and without the package's `__init__` as an
    edge, and deferred imports;
  - `api.py`'s length and its longest functions;
  - what `import valvur.hook` loads, and its time;
  - each concept's copies, from the review's §3.3.

  Record goldens of the CLI's text and the MCP reply through `LocalRuntime`, for three
  fixture workspaces (one with findings, one clean, one inconclusive), with times and
  generation IDs normalised. Behaviour: the STATUS gives each number; the goldens are
  committed and pass.
  **STATUS 2026-10-03:** ✅ measured in the cloud session at `3691d2f`, from the AST of
  `src/valvur` (99 modules, 378 import edges between them).
  - **The import graph.** 229 import statements sit inside function bodies. Counting the
    package's `__init__` as an edge of every `from . import x`, two cycles: 58 modules
    and 6 (34, 2, 4 and 4 with the deferred imports left out). Without that edge, two:
    ten modules around `api`, `engine_host` and `runner` (`valvur`, `api`, `compat`,
    `engine_host`, `pipeline`, `provenance`, `results`, `runner`, `staleness`,
    `summary`; `compat`'s generated `_build` resolves to the package), and
    `mcp.server` with `mcp.tools`. At import time alone, six: `api`, `pipeline`,
    `provenance`, `results`, `staleness` and `summary`, as the review found.
  - **`api.py`:** 1,245 lines, importing 33 of valvur's modules. Its longest functions:
    `_engine_fleet` 154 lines, `_assemble` 135, `_ensure_data` 89, `scan` 67,
    `_outcome` 63, `_scan_locked` 48.
  - **`import valvur.hook`** loads 52 of valvur's modules, `api` and `pipeline` among
    them: 0.13 s in-process; as a process, a median 0.17 s against 0.017 s for a bare
    interpreter (five runs each).
  - **Each concept's copies** (the review's §3.3). Staleness: 28 references to a
    threshold, across 11 modules, and `update --if-stale` still refreshes the index only
    past 30 days, where a scan does past 2. Active: six sites (`api`, `summary`,
    `remediation`, `gate`, `reply`, `grouping`). The network grant: four
    (`adapters/check.py`, OSV's adapter, `Invocation.network`, `VALVUR_NETWORK`).
    Launching a container: two flag builders (`runner.ContainerRunner._base_flags`,
    `engine_host.ContainerRuntime.command`). `.security-scan.toml`: one CLI scan of
    `broken-repo` with every default adapter, counted by patching, parsed `[scan]` 76
    times and built the File Set 37 times.
  - **The goldens:** `tests/test_scan_goldens.py` holds the CLI's text and the MCP `scan`
    reply, text and fields, for `findings`, `clean` and `inconclusive` workspaces through
    `LocalRuntime`, times, ids, dates and paths normalised, in
    `tests/fixtures/scan-goldens/`; `python tests/test_scan_goldens.py` regenerates them
    through the tests, which write only to a scratch directory. 9 pass, twice running.
- [x] **R23.2** **The layer check** (D50). Behaviours:
  1. an import of a higher layer from a lower one fails, named with its `file:line`,
     deferred imports included;
  2. a module in no layer fails;
  3. today's upward imports are the baseline, which may only shrink;
  4. it runs in `verify.sh`.
  **STATUS 2026-10-03:** ✅ all four. `scripts/check_layers.py` reads every import from
  the AST, a deferred one marked so, and resolves `from . import x` to the module `x`.
  `scripts/layers.toml` assigns all 99 modules: 17 to `core`, 55 to `infra`, 21 to
  `app` and 7 to `surfaces`, with `valvur._build` named as generated. A module in no
  layer fails, and so does a name the table assigns to no module. The first run found 7
  upward imports, 4 by module, now the baseline: `doctor` and `operations` reach
  `mcp.protocol` for the client's session and roots, `findings` reaches `ecosystems`
  for `index_form`, and `grouping` reaches `coverage` for `NOTE_RULES`. An entry that
  stops happening fails until it is removed. `verify.sh` runs it as `layers`, held by a
  test that runs the gate with a recording `uv`.
- [x] **R23.3** **The package loads only what is asked** (D50). Behaviours:
  1. `from valvur import scan, ScanRun, ScannerFailed, Finding, __version__` still works;
  2. `import valvur.hook` loads neither `api` nor `pipeline`, and a test counts the
     modules it loads;
  3. the hook's import time is in the STATUS, against R23.1's.
  **STATUS 2026-10-03:** ✅ all three. `valvur/__init__.py` exports its five names through
  PEP 562's `__getattr__`, and `import valvur` loads nothing else. `import valvur.hook`
  loads 11 of valvur's modules, down from 52 (the hook, `installs`, `packages`, `cache`,
  `version` and the five `ecosystems` modules), neither `api` nor `pipeline`, and a test
  holds the count. Its cost: 0.075 s in-process against 0.13 s, and as a process a median
  0.10 s against 0.17 s, five runs each, on the cloud VM.
- [x] **R23.4** **One scan service** (D51). Behaviours:
  1. the CLI's `scan` and the MCP tool both run through `service.run_scan`; a test
     replaces it and drives both surfaces;
  2. `operations` and `reply` import nothing from `valvur.mcp`;
  3. the CLI's text and the MCP reply match R23.1's goldens;
  4. `Job.summary`, `operations._summarise`, `start_scan` and `_run_scan` are gone;
  5. a `scan_cancel` sent before the scan's job exists stops that scan (R6's backlog row,
     moved here from §8);
  6. a scan whose image cannot be pulled says why in one line and exits non-zero, as
     `update` does, never with a traceback (found by the cloud pre-flight).
  **STATUS 2026-10-03:** ✅ all six.
  - **The service.** `service.run_scan` owns the runner (`service.new_runner`), the locks
    and budget through `api.scan`, and a `Cancellation` that holds a cancel arriving
    before the runner exists. The CLI's `scan` calls it, its Ctrl-C handler reading the
    runner from the cancellation; the MCP job calls it in its thread and adds nothing
    else. A test replaces `service.run_scan` and drives both surfaces.
  - **The MCP side.** Every tool's handler moved to `mcp/handlers.py`, a surface: it
    passes the client's roots, the call's progress, the scan's job and the served tools
    to `operations`, `reply` and `doctor`, which import nothing from `valvur.mcp` (a test
    reads their imports). The layer baseline lost `doctor` and `operations` reaching
    `mcp.protocol`; two entries remain. `reply` reads a job through a `JobView`
    protocol. The F9.3 structural test now holds every handler to that module and to a
    shared operation, `scan_cancel` aside, the CLI's cancel being Ctrl-C.
  - **Unchanged words.** R23.1's goldens pass, both surfaces, all three workspaces.
  - **Gone:** `Job.summary`, `operations._summarise`, `start_scan`, `_run_scan` and
    `_scan_with_budget`; the 31 test files that reached into them now go through the handlers.
  - **The early cancel.** The server's reader announces each `scan` call before its
    thread runs (`protocol.Handlers.announce`, `jobs.expect`); a `scan_cancel` read
    after it waits up to 15 s for that job and stops it. A scan refused at its arguments
    settles its announcement, so no cancel waits for nothing. Held in-process.
  - **A failed pull, or no runtime,** is one `!` line and exit 1 on the CLI, never a
    traceback.
- [x] **R23.5** **The datasets, once** (D52a). Behaviours:
  1. every dataset's refresh and `inconclusive` thresholds come from one table, and a
     test holds the table to D24;
  2. `update --if-stale` refreshes exactly what a scan would, KEV and EPSS included;
  3. `doctor`, `run.json` and the reply read ages through the table;
  4. no other module compares a dataset's age with a number, which an AST test holds.
  **STATUS 2026-10-03:** ✅ all four.
  - **The table.** `valvur.datasets` has one row each for the database, the index, the
    malicious list, KEV, EPSS and OSV's databases: the mirror setting, the verifier, the
    age reader and the refresh and `inconclusive` thresholds, D24's and F7.16's, which a
    test holds. KEV's row carries the thirty days past which the summary and
    `run.json`'s `enrichment.stale` say its age. The constants in `cache`,
    `enrichment` and `osv_offline` are gone; `osv_offline` takes the table's `due`.
  - **`update --if-stale`** now refreshes, for each of seven cache states, exactly the
    datasets a scan's own fetch step does, KEV, EPSS and the malicious list included,
    and the index past 2 days, not 30. `--if-stale` no longer refreshes a database that
    is past Trivy's `NextUpdate` but under a week old, which a scan never did. Its help
    says so; the help golden was regenerated.
  - **Read through the table:** `doctor`'s database and index lines, `run.json`'s
    `database`, `name_index`, `data` and `enrichment.stale`, and so the reply. A test
    changes one row and reads each surface.
  - **The AST test** finds no comparison of an age with a number outside `datasets`.
    It first found two: `run.json`'s KEV flag (a literal 30, now the row's) and the
    dependency-reality Check's package age, a package's and not a dataset's, renamed
    `on_registry`. The registry walk's cadence in `name_index/build.py`, which builds the
    index for the publishing workflow and decides neither a refresh nor a verdict, is
    named as the one exception.
- [x] **R23.6** **Every other concept, once** (D52b to e). Behaviours:
  1. one predicate decides that a Finding is active, and the six sites call it;
  2. the network grant is `Invocation.network` alone, and the engine sets
     `VALVUR_NETWORK` for each granted tool in every runtime;
  3. one scan parses `.security-scan.toml` once and builds the File Set once, counted;
  4. both launchers build their flags with one function.
  **STATUS 2026-10-03:** ✅ all four.
  - **Active.** `valvur.verdict`, in `core`, holds the note rules (`coverage` names them
    as before) and `active` and `note`, for a Finding and for a `findings.json` record.
    `api`, `summary`, `gate`, `reply` and `grouping` call `active`; `remediation`, whose
    proposals have always covered every Finding but notes, calls `note`. An AST test
    finds no other `in NOTE_RULES`. The layer baseline lost `grouping` reaching
    `coverage`; one entry remains, `findings` reaching `ecosystems`.
  - **The network grant.** Each plan entry carries `network`, and the engine sets
    `VALVUR_NETWORK` for that tool and clears it for every other, whatever it inherited,
    in a Scan Container and in the image as a pipeline step (D54b's lapse, fixed here
    and held again by R23.8). The container's flags no longer carry it; OSV's adapter
    holds its grant as `network`, as the Check adapter does. Two constraint tests were
    restated over the plan's grants, the suite still 54; `PROTOCOL.md` says so.
  - **One read per scan.** `valvur.scancontext` reads `.security-scan.toml` once (its
    tables, why it could not be read, its `[scan]` settings) and builds the File Set
    once; the scan passes it to the adapters' applicability and coverage, the history
    pass, OSV's fetch and the pipeline, whose suppressions come from the same parse.
    Counted on one CLI scan of `broken-repo` with every default adapter: 77 parses and
    37 File Sets before, 1 and 1 after.
  - **One flag builder.** `runner.launch_flags` builds `<runtime> run …` up to the
    image for the Scan Container and the database fetch; `_base_flags` and the second
    list in `ContainerRuntime.command` are gone, and a test watches both launchers call
    it.
- [x] **R23.7** **Typed messages** (D53). Behaviours:
  1. the engine's events carry a `kind`, and the reply reads kinds, never a prefix;
  2. the budget's state is a field;
  3. `Runtime` and `ScannerAdapter` declare every member `app` uses, and an AST test
     finds no `getattr` on either;
  4. `mypy --strict` passes on `core`, or D53's fallback lists what does not.
  **STATUS 2026-10-03:** ✅ all four, D53's fallback not needed.
  - **Events.** `valvur.events`, in `core`, gives each thing a scan says a kind and
    fields: a fetch's start and end, the workspace line, the fleet, a Scanner's start,
    end and reuse, the budget, history and notes. `render` writes their words, the ones
    every surface showed, which R23.1's goldens hold. `api` passes events on, the job
    keeps them, and the reply places each by its kind; `FETCH_STARTED`, `FETCH_ENDED`
    and `WORKSPACE_PREFIX` are gone, and a test finds no prefix match left. The CLI
    prints fetch events by kind; MCP notifications render at the surface.
  - **The budget's state** is `ScannerRun.budget`, `cut` or `not-started`, set where
    the budget acts; the refusal, its fields and the budget line read it. `ScannerRun`
    moved to `core` (`valvur.scanner_run`; `provenance` names it), so the field closes
    no cycle.
  - **The protocols.** `engine_host.Runtime` declares every member the scan uses, and
    `RuntimeDefaults` gives those of a runtime with nothing to fetch, compare or pull;
    `fetches` replaces probing for `update_db`. `ScannerAdapter` declares `version`,
    `artifact` and `network`. An AST test finds no `getattr` or `hasattr` on a runner or
    an adapter in any `app` module (there were 19); the dead `verify_workspace_readable`
    probe went with them. The suite's fakes inherit the defaults.
  - **`mypy --strict`** passes on all 19 `core` modules, and `verify.sh` runs it as
    `strict`. Fixing it took `findings` off `ecosystems`: the pipeline passes
    `index_form` to `merge`. That emptied the layer baseline.
- [x] **R23.8** **The four lapses** (D54). Behaviours:
  1. `/tmp` is `noexec` for every tool, and Opengrep runs from its unpacked tree
     (`e2e`), or D54's fallback;
  2. on `full` in the image, dependency-reality asks the registry, through
     `tests/fake_registry.py`;
  3. `VALVUR_CACHE` wins over `XDG_CACHE_HOME`;
  4. the Profiles share one Scanner list, and `run.json` keeps `scanners_not_run`;
  5. the dead code the review names is gone, and each duplicated constant is one.
  **STATUS 2026-10-03:** ✅ all five, D54's fallback not needed.
  - **(a) `/tmp` noexec.** The image unpacks Opengrep's one-file binary at build into
    `/opt/opengrep` (`XDG_CACHE_HOME`, which it honours), and the adapter points it
    there. `/tmp` is `rw,noexec,nosuid` for every container valvur starts;
    `Invocation.allow_exec` and the launchers' exec flag are gone, and each scan no
    longer unpacks 239 MB. Measured first with a derived image, then held by an e2e
    test against `valvur:dev` rebuilt by the script: Opengrep completes on
    `broken-repo` and reports, with `/tmp` noexec.
  - **(b) `full` in the image.** A test runs the image's pipeline-step runtime on
    `full` with dependency-reality as its own process, through a stand-in for the
    package registries added to `tests/fake_registry.py` (a `sitecustomize` on the
    Check's `PYTHONPATH` that answers and records): the Check asks PyPI, and on
    `offline` asks nothing. With R23.6's per-tool grant switched off, the test fails.
  - **(c)** `cache.root` takes `VALVUR_CACHE`, then the `cache` setting, then
    `XDG_CACHE_HOME`, then `~/.cache`.
  - **(d)** One tuple, `profiles.FLEET`, is both Profiles' list; `run.json` keeps
    `scanners_not_run`, empty.
  - **(e) Dead code:** `api.JOBS_ENV`, `doctor.LEVELS` and `_default_fleet`,
    `fingerprint.for_dependency_reality`, `requirements.REQUIREMENTS_GLOB`,
    `runner.ContainerStartFailed` and `summary._counts_table`, found by counting each
    top-level name's references. **One constant each:** the Results Folder's name, the
    project file's, the image's digest path, the workspace mount, the history pass's
    tool and the server's name had two definitions, and eleven `VALVUR_*` names were
    spelt beside `settings.ENVIRONMENT`, which now names them all. Two tests hold it.
- [x] **R23.9** **The orchestrator, small** (D50). Behaviours:
  1. `api.py` is under 400 lines, and no function in `app` is over 80 lines;
  2. the layer baseline is empty, and no import cycle remains, counting deferred imports
     and the package's `__init__`;
  3. every deferred import left says why in a comment, such as startup cost, and a test
     lists them.
  **STATUS 2026-10-03:** ✅ all three, D50's fallback not needed.
  - **(1)** `api.py` is 185 lines (1,245 at R23.1): the locks, the fetches, the count,
    the fleet and the record, in order. What a first run fetches is `fetching`, the
    Scan Container's fleet `fleet`, the assembly `assembly`, and the record `scanrun`,
    which `summary`, `provenance`, `results` and `staleness` now import instead of the
    scan. The longest `app` function was `provenance.render` at 164 lines; none is over
    80 now, and `tests/test_orchestrator_small.py` holds both numbers.
  - **(2)** No cycle, by `check_layers.py`'s count (deferred imports and the implicit
    edge to each ancestor `__init__`) and by the older soft-cycle test's (annotations
    too), which accepted two groups and accepts none now. The packages' `__init__`
    files load their names through `valvur.lazy` (PEP 562); the registries they held
    moved to `adapters.registry`, `checks.registry` and `ecosystems.vocabulary`, the
    MCP `Tool` to `mcp.tool`, and `staleness` reads a run through a Protocol.
  - **(3)** 229 deferred imports at R23.1, 62 now in 56 statements (115 modules, 484
    edges). The rest moved to the top of their module, and five that tests patched
    read the module's attribute instead. Each left carries `# deferred: <why>`: the
    plugin's hook (`cache`, `packages`, `ecosystems.registries`), the MCP server's
    handshake (`operations`, `mcp.server`, `mcp.tools`), the CLI's commands, the
    registry client and the TLS stack, or the generated `_build`.
    `check_layers.py --deferred` lists them into `tests/fixtures/deferred-imports.txt`,
    and `tests/test_deferred_imports.py` fails on one without a reason or off the list.
    **The cost, measured:** `import valvur.hook` loads 9 modules, as before;
    `import valvur.mcp.server` loads 86 (72 before) and `import valvur.cli` 79 (65),
    about 15 ms more at the median of 21 runs (about 205 ms against 190), with neither
    loading the TLS stack.

**Exit:** the layer baseline empty and no import cycle, or D50's fallback; `api.py` under
400 lines; R23.1's goldens unchanged; the Score unchanged on both lanes; the acceptance set
green on both lanes; `CLAUDE.md` names the layers and the check.

### Phase R24: the machinery made lighter

- [x] **R24.1** **Measure first** (D55). Record:
  - the tests that read prose or other files' text, by file;
  - the image builds a pull request makes, and their minutes;
  - every surface that states the version;
  - the steps copied between workflows.

  Behaviour: the STATUS gives each count.
  **STATUS 2026-10-03:** ✅ measured at `80b1d37`, R23's head.
  - **Tests that read text** (each test's body, its helpers and the module constants
    they name, read from the AST): 80 tests in 36 files read the repository's prose,
    43 read workflow text and 22 read Python source. By file, for prose: `test_skill`
    9, `test_readme_as_built` 6, `test_engine` 6, `test_protocol` 5, `test_version` 4,
    `test_readme_claims` 4, `test_constraints_design` 4, `test_prepare_release` 3,
    `test_mcp_clients` 3, `test_mcp` 3, `test_init_write` 3, `test_scan_goldens`,
    `test_published_index`, `test_pipeline_example`, `test_init_skill` and
    `test_hygiene` 2 each, and 20 more files with one each.
  - **Image builds per pull request:** five in `ci.yml` on #184's run 37153055991:
    the two e2e jobs' (64 s amd64, 62 s arm64), the self-scan's (68 s), and the
    reproducibility job's two, without cache (125 s together): 5.3 minutes of
    building. `eval.yml` and `acceptance.yml` add one each (75 s and 82 s) when their
    paths change. The required jobs finished 8.4 minutes after the run started.
  - **Version surfaces:** 12 files state it: `pyproject.toml`, the README's status,
    the package's skill and its two copies, the plugin's manifest, server and hook,
    the power's manifest and server, and the two pipeline examples. The workflows read
    it from `pyproject.toml` ten times, by the same `grep | cut`, in six of them.
  - **Steps copied between workflows:** the version read 10 times in 6 workflows; the
    issue on failure 9 times in 7; fetching the database and the index 7 times;
    restoring the index cache 3; building the image from the tree 3 (5 with
    `ci.yml`'s differently named ones); `uv venv` 10 and `uv sync` 7.
  - **The eight required checks**, read from branch protection: `no scan output in
    tree`, `lint, types, tests`, `end-to-end (real container)`, `self-scan release
    gate (N2.5)`, `the published image, on amd64`, `the published image, on arm64`,
    `the tests on Python 3.11` and `the tests on Python 3.13`.
- [x] **R24.2** **Generated, not compared** (D55a). Behaviours:
  1. `scripts/generate_docs.py` writes each marked block from the code;
  2. one test regenerates every block and fails on a difference, naming the block;
  3. each test that compared prose with a fact a block now carries is deleted with it,
     and the constraint suite keeps its 54;
  4. the link check passes.
  **STATUS 2026-10-03:** ✅ all four.
  - **Eight blocks in five files:** the skill's `mcp-tools` (`references/tools.md`) and
    `agent-rules` (`SKILL.md`); the README's `mcp-clients` and `cli-commands`;
    `PROTOCOL.md`'s `protocol-paths`, `protocol-binaries` and `protocol-labels`; and
    `AIR-GAPPED.md`'s `settings`. The facts are the code's: the server's tool list and
    handshake, the clients' table, the parser's commands, the paths in every adapter's
    command and the shim's own mounts, each adapter's version, the Dockerfile's labels,
    and `settings.ENVIRONMENT`. The generator refuses a path, binary or mirror setting
    the code adds and its table does not describe. The two older markers (`rules:`,
    `clients:`) are gone.
  - **Deleted with their blocks:** five tests and half of a sixth. The skill's tools
    reference and rules tests, the README's clients test, `PROTOCOL.md`'s paths and
    binaries tests, and the commands half of the README test. The README's tools table
    stays prose, and its test with it. 76 tests now read prose, 80 at R24.1. The
    constraint suite is untouched, at 54. `test_links.py` passes.
- [x] **R24.3** **No test writes the repository** (D55b). Behaviours:
  1. `scripts/sync_skill.py` refreshes the plugin's and the power's copies of the skill,
     and `prepare_release.py` runs it;
  2. `UPDATE_SKILL` is gone, and the byte-equality tests stay.
  **STATUS 2026-10-03:** ✅ both. `sync_skill.sync` rewrites a copy only when it
  differs, and `prepare_release.py` calls it where its own copy loop was. No test file
  names `UPDATE_SKILL`, and a test holds that.
- [x] **R24.4** **CI builds once** (D55c, d). Behaviours:
  1. a pull request builds the image at most three times: once per architecture, and once
     more for reproducibility;
  2. the e2e, the self-scan and the reproducibility comparison use the commit's build;
  3. one composite action reads the version, and one files the issue on failure;
  4. the eight required checks keep their names, and a test holds the list;
  5. zizmor finds nothing in the workflows, and every required check is green.
  **STATUS 2026-10-03:** ✅ all five, D55's fallback not needed.
  - **Three builds.** A new `image` job builds each architecture once, without cache
    and at the commit's timestamp, and hands it on as an artifact. The e2e jobs, the
    self-scan and the reproducibility comparison load it, and the comparison builds
    its second image alone. A job whose build failed fails itself: GitHub counts a
    skipped required check as passed.
  - **Measured on #185, run 37155498359,** against #184's run 37153055991 (R24.1). The
    amd64 build takes 78 s, saving it 19 s and uploading it 5 s. Each job that uses it
    downloads it in 4 to 10 s and loads it in 17 to 22 s, where it built for 62 to 68 s.
    So handing it over is faster than building it, and the fallback does not apply.
    Building took about 3.6 minutes in all, 5.3 before. The cost is wall-clock: the
    jobs that need the image now wait for it. The required checks finished 11.1
    minutes after the run started, 8.4 before. About half of that is the wait; the
    other half is the e2e tests themselves, 448 s this time against 352 s.
  - **One version source, one issue step.** `.github/actions/version` replaces eleven
    reads, in seven workflows with `release.yml`. `.github/actions/file-issue`
    replaces nine copies; `retention.yml` checks out for it. The refresh workflow's
    issue for the owner is not a failure step, and stays as it is.
  - **The eight required checks** keep their names; `tests/test_ci_builds_once.py`
    holds them, the build count, the shared build and the two actions. zizmor
    (pedantic, medium and above) finds nothing in `.github/`. Every check on #185 is
    green, the eight among them.
- [x] **R24.5** **Planning IDs out of the way** (D55e, f). Behaviours:
  1. traceability does not read `docs/history`, and a test holds the list of what it
     reads;
  2. `CONTRIBUTING.md` says new tests are named for what they test, and new comments cite
     ADRs and requirements, not tasks.
  **STATUS 2026-10-03:** ✅ both. `check_traceability.py` skips `docs/history`, and
  nothing became uncited. `tests/test_traceability_reads.py` holds its sources. The
  test that gave the archive no exemption now covers `requirements.md` alone, as D55f
  amends D43. `CONTRIBUTING.md` carries the naming rule and the citation rule, and
  says how the docs are generated and the skill copied. That is prose, so by D55's own
  rule no test compares it.

**Exit:** the prose-comparing tests R24.1 counted, less those kept as contracts, gone; at
most three image builds per pull request, with CI's time against R24.1's; the Score
unchanged on both lanes; CI green.

### Phase R20: the noise real projects draw

*Reshaped 2026-10-03 by D56: path classes first, and D47's (b) and (c) as rows of one
table.*

- [x] **R20.1** **Measure first** (D47, D56). For each of the 26 corpus false alarms,
  record its rule, its path class and its severity. Run each change against tracks 1 to 8
  separately, before any ships. Behaviour: the STATUS gives each change's delta per track;
  a change past the ratchet is withdrawn there.
  **STATUS 2026-10-03:** ✅ the false alarms measured at R24's head, from
  `tests/eval/labels/corpus.toml` and each repository's `findings.json`. The file holds
  27 labels, all `fp`; one, ripgrep's `valvur.licence.mismatch` on `Cargo.toml`, no
  longer appears in a scan, so 26 are judged, as D47 counts. By path class, read by
  D56's segments: 11 `test`, 5 `docs` and 11 `source`, with the licence label among
  the source ones.
  - **Secrets, 12, all `critical`, ranked first in their repositories:**
    `generic-api-key` 6 (fastify, flask ×3 in `docs/`, monolog, sinatra's
    `README.md`), `private-key` 4 (requests' test certificates), `slack-webhook-url`
    1 (monolog's tests). 11 are in `test` or `docs`; sinatra's README is `source`.
  - **The sink inventory, 9, `low`:** `dangerous-exec` 8 and `dangerous-eval` 1, in
    flask, llm and smolagents, four of them in `test`.
  - **`weak-hash`, 4, `low`,** all `source` (flask's sessions, llm's embeddings).
  - **The vendored `random` rule, 3, `medium`:** two in llm's `docs/` plugin and one
    in smolagents' `source`.
  Each change below records its delta per track in its own STATUS: R20.3's inventory,
  R20.4's table, R20.5's `usedforsecurity`.
- [x] **R20.2** **Path classes** (D56). Behaviours:
  1. the File Set gives every path one class, by whole segments:
     `testcode/BenchmarkTest00001.py`, `latest/x.py` and `contest/y.py` are `source`;
  2. `vendor/`, `third_party/` and `node_modules/` are `vendored`; `linguist-generated`
     and a header saying not to edit are `generated`;
  3. every finding carries `context` in `findings.json` and SARIF, and its fingerprint is
     unchanged;
  4. the corpus's count per class is in the STATUS.
  **STATUS 2026-10-03:** ✅ all four. `valvur.pathclass` (core) classes by segments,
  in the order vendored, fixture, test, example, docs; `fileset.classes` adds
  `generated` from `.gitattributes` or a "generated … do not edit" line in the first
  kilobyte. A `context` stage after `merged` sets each Finding's class, which
  `findings.json` and SARIF's result properties carry. A test runs a scan with every
  path classed `vendored` and gets the same fingerprints. **The corpus**, over the
  235 findings of the 13 repositories at R24's scan: 189 `source`, 30 `example`, 11
  `test` and 5 `docs`; none `fixture`, `vendored` or `generated`.
- [x] **R20.3** **The sink inventory is inventory** (D47a). Behaviours:
  1. an inventory rule's finding is marked `inventory` in `findings.json` and SARIF;
  2. it is not active: a project whose only results are inventory reads `clean`, with
     *Sinks to review* counting them in `SUMMARY.md`;
  3. `findings` lists inventory only when asked (`inventory: true`);
  4. a non-inventory finding at the same line still counts.
  **STATUS 2026-10-03:** ✅ all four. `dangerous-eval`, `dangerous-exec` and
  `string-built-sql` declare `inventory: true` in their metadata, and no other rule
  does (a test reads the rules). The Opengrep adapter carries it to the Finding,
  `verdict.active` excludes it, and `findings.json` and SARIF mark it. `SUMMARY.md`
  counts *Sinks to review* and says how to list them. The `findings` tool takes
  `inventory`, and the CLI `--inventory`. The Score's own `_active`, which mirrors the
  verdict, excludes it too. **Measured** on the image built from this change: tracks 1
  to 7 unchanged; track 8 from 3.7 to 5.3, its judged set from 26 findings to 18; the
  Score from 64.9 to 65.1.
- [x] **R20.4** **One table decides what a class changes** (D56; D47b, c). Behaviours:
  1. a Gitleaks finding in `test`, `fixture`, `docs` or `example` is `low`, still
     active, and still makes the verdict `findings`;
  2. `weak-hash` and the vendored `random` rule are not reported in those classes, and
     `run.json` counts what the table removed, by class and rule;
  3. a class with no row changes nothing;
  4. track 3 holds 100, and track 1's `hash` and `weakrand` categories keep every true
     positive they have.
  **STATUS 2026-10-03:** ✅ all four. `valvur.classtable` (core) holds two rows: a
  Gitleaks finding where examples live (`test`, `fixture`, `docs`, `example`) is
  lowered to `low`, and `weak-hash` and `python_random_rule-random` there are removed
  and counted. A `classes` stage after `context` applies it, and `run.json` carries
  `removed_by_class`. `source`, `vendored` and `generated` have no row. **Measured:**
  tracks 1 to 7 unchanged, track 3 at 100. Every track 1 case lives in `testcode/`,
  which is `source`, so no true positive of `hash` or `weakrand` is touched. Track 8
  rises from 5.3 to 5.9 as llm's two `random` findings in `docs/` leave the judged
  set, now 16. The eleven secrets in tests and docs stay judged, at `low`. The Score
  is 65.2.
- [x] **R20.5** **Non-security hashing** (D47c). Behaviours:
  1. `hashlib.md5(data, usedforsecurity=False)` draws no `weak-hash`;
  2. `hashlib.md5(data)` still does.
  **STATUS 2026-10-03:** ✅ both, and already so in the rule: its two `pattern-not`s
  for `usedforsecurity=False` date from 22.E.2, and no test had held them. One does
  now, against the image, for `md5` and `sha1`. Run against a copy of the rule with
  the `pattern-not`s removed, the image's Opengrep reports the cache-key call, so the
  test can fail. Its delta on every track is nil, the rule being unchanged. The four
  `weak-hash` false alarms R20.1 counted carry no `usedforsecurity`, so they stand.
- [x] **R20.6** **The corpus judged again.** Re-label what changed in
  `tests/eval/labels/corpus.toml`; run the Score; raise track 8's baseline by what it
  measures. Behaviours: no track 1 to 7 falls more than 2 points; README and
  `EVALUATING.md` cite the new track 8.
  **STATUS 2026-10-03:** ✅ both. Ten labels went with the findings no longer judged:
  the 8 inventory sinks, and llm's 2 `random` hits in `docs/`. The 16 still judged
  keep their `fp` verdicts, 11 of them secrets now at `low`. On the image built from
  this branch, tracks 1 to 7 are where they were and track 8 is 5.9.
  `--update-baseline` raised track 8's baseline from 4.2 to 5.9. It had raised tracks
  without recomputing the recorded score, which would have read 64.9 beside tracks
  averaging 65.2; it records their mean now, under a test. The README cites 65.2, and
  `EVALUATING.md` gives R20's table of track 8 by change.

**Exit:** the Score on both lanes, track 8 up and no other track past the ratchet; the
acceptance set green on both lanes; `CHANGELOG.md` names the verdict change as a fix.

### Phase R25: what the code rules find

- [x] **R25.1** **Measure the gap per category** (D60). For each of track 1's 14 categories
  and track 2's 10 types, record the true and false positives today, the rule that fires,
  and the eligible candidates in GitLab's `sast-rules` at its pin. Behaviour: the STATUS
  gives the table, and the order D60's work takes.
  **STATUS 2026-10-03:** ✅ measured at R20's head, track 1 at 11.1 and track 2 at 15.0.
  - **Track 1, by category** (true positives, false positives of all cases; the rule):
    - `cmdi` 7 of 13, 7 of 7 (`subprocess-shell-true`), −46.2;
    - `codeinj` 0 of 20, 0 of 33, 0.0: the `eval` and `exec` sinks fired on both until
      R20.3 made them inventory;
    - `deserialization` 5/18, 5/36 (vendored `yaml-load`), 13.9;
    - `hash` 37/71, 0/80 (`weak-hash`), 52.1;
    - `sqli` 5/5, 0/11 (vendored `hardcoded-sql-expression`), 100;
    - `weakrand` 35/99, 0/227 (vendored `random`), 35.4;
    - nothing in `ldapi`, `pathtraver`, `redirect`, `securecookie`, `trustbound`,
      `xpathi`, `xss` or `xxe`.
  - **Track 2, by type:** CWE-798 2 of 2 (Gitleaks) and CWE-94 1 of 2 (vendored
    `eval-with-expression`); nothing in CWE-22, 78, 79, 89, 327, 601, 918 or 1321.
  - **Eligible candidates at GitLab's pin** for D60's categories, from
    `tests/eval/sast-rules-measured.json`:
    - XXE: `minidom` and `sax`, 8 true and 20 false each, under D29's 0.5;
    - path traversal: `tarfile-unsafe-members`, which finds nothing;
    - command injection: `subprocess-popen-shell-true`, the same 7 and 7 as valvur's
      own;
    - code injection: `eval` 10/17 and `exec-used` 10/24;
    - JavaScript path traversal: `non-literal-fs-filename`, 1 against 51.
    - Nothing for secure cookies, open redirects, or JavaScript's SQL injection,
      command injection or SSRF.
    So valvur writes its own rules, as D29's fallback says.
  - **The order, as D60 sets it:** command and code injection by taint first (R25.2),
    then Python's path traversal, secure cookies, open redirects and XXE (R25.3), then
    JavaScript's SQL injection, command injection, path traversal and SSRF (R25.4).
- [ ] **R25.2** **Command and code injection tell safe from unsafe** (D60). Behaviours:
  1. a flow from request data to `subprocess` with `shell=True`, or to `eval` or `exec`,
     still fires;
  2. a constant, or a value that passes a sanitiser on the way, draws nothing;
  3. track 1's command-injection and code-injection categories rise, and no other falls;
  4. track 8 is not lower.
- [ ] **R25.3** **Python: path traversal, secure cookies, open redirects, XXE** (D60).
  Behaviours:
  1. each category's rules have vulnerable and safe twins as tests;
  2. each rule ships only on D29's bar, or is recorded as withdrawn;
  3. the STATUS gives track 1's delta per category.
- [ ] **R25.4** **JavaScript: SQL injection, command injection, path traversal, SSRF**
  (D60). Behaviours:
  1. each type's rules have vulnerable and safe twins as tests;
  2. each rule ships only on D29's bar, or is recorded as withdrawn;
  3. the STATUS gives track 2's delta per type.
- [ ] **R25.5** **The Score and the corpus** (D60). Behaviours:
  1. track 8 is not lower than at R20's exit;
  2. Opengrep's median time on the acceptance set is within 130% of R25.1's;
  3. every shipped rule carries its CWE into `findings.json` and SARIF;
  4. the baselines rise for every track that rose, and the README and `EVALUATING.md`
     cite only what is measured.

**Exit:** the Score on both lanes, tracks 1 and 2 up and measured against D60's aims, no
track past the ratchet; the acceptance set green on both lanes.

### Phase R21: findable

- [ ] **R21.1** **The demo** (D48a). `scripts/demo.py` records one CLI scan of acceptance
  repository 8 and writes `docs/demo.svg`. Behaviours:
  1. the script regenerates the file, so it never drifts from the CLI, and it uses the
     standard library alone;
  2. the SVG is under 1 MB and shows the verdict and the malicious package;
  3. the README's first screen shows it;
  4. it holds no path of this machine and no secret: a test reads it.
- [ ] **R21.2** **Ready to list** (D48b). Behaviours:
  1. the README has *Privacy* and *Support* sections, and the link check passes;
  2. `docs/LISTING.md` holds each directory's text, drawn from the manifests, and a test
     holds it to them;
  3. §8's listing row points to it.
- [ ] **R21.3** **The first run in a new project** (D58). Behaviours:
  1. the README's first screen gives the plugin's two commands first, and
     `uvx valvur scan` second;
  2. the README and the skill's references give the allow rules, and a test holds each to
     a tool the server lists, `update` excluded;
  3. the skill says what to do when a tool is refused, with the pinned command, which
     `test_version.py` holds and `prepare_release.py` moves;
  4. the smoke run under *don't ask* records what happens to the hook's `ask`, or D58's
     fallback applies.
- [ ] **R21.4** **The loop closed** (D59). Behaviours:
  1. on a rescan, `SUMMARY.md` and the `scan` reply open with every earlier finding, by
     rule ID and path, as `fixed`, `open` or `not re-checked`, then the new ones;
  2. `fixed` only where its Scanner ran again, as now;
  3. the skill rescans after the human's fixes and leads with the table, and says nothing
     is confirmed when it cannot rescan;
  4. `REMEDIATION.md` gives each `unpinned-uses` finding its lookup command and the line
     to write, and valvur runs none of them;
  5. the Score is unchanged on both lanes.

**Exit:** the README's first screen, measured in lines, holds what valvur is, the plugin's
two commands and the demo; the documents' tests pass; the hook's behaviour under *don't
ask* recorded.

### Phase R22: OpenSSF signals

- [ ] **R22.1** **Scorecard** (D49a). Behaviours:
  1. `scorecard.yml` is pinned by commit, with the documented minimum permissions, and a
     test holds both;
  2. zizmor finds nothing in it;
  3. `publish_results` is true on `main` alone, and a test holds it;
  4. the score measured on the branch, with publishing off, and each check under 10 are
     recorded, and the cheap ones are fixed;
  5. the README shows the badge, which reads the first result published from `main`.
- [ ] **R22.2** **Best Practices, prepared** (D49b). Behaviours:
  1. `docs/BEST-PRACTICES.md` answers every *passing* criterion, each with a link to its
     evidence;
  2. the link check reads it;
  3. §8 holds the form for the owner.

**Exit:** the Scorecard result recorded, with its run; the Best Practices answers ready;
CI green.

### Phase R19: the runner move (on or after 2026-11-19)

- [ ] **R19.1** **Every runner on 26.04** (D45; 28.3.8). Behaviours:
  1. the release constraints that hold the runner set name `ubuntu-26.04` and
     `ubuntu-26.04-arm`;
  2. every `runs-on` and matrix runner moves;
  3. zizmor finds nothing in the workflows;
  4. every check is green on the PR.
- [ ] **R19.2** **Measured again on 26.04** (D45). Dispatch the corpus, the acceptance set
  and the Score on the branch. Measure N1.1 and N1.4 against their 24.04 numbers, and
  record each in `requirements.md`. Behaviour: each number in the STATUS, with its run.

**Exit:** the Score on Linux at its baseline, the acceptance set green, and N1.1 and N1.4
recorded; or D45's fallback, applied and recorded.

---

## 8. The owner queue

Nothing here blocks the build. The executor adds a row when an item becomes ready. The
rows closed on 2026-09-29 are in [the archive](../../../docs/history/tasks-phases-r7-r8.md).

| item | ready after | what the owner does |
|---|---|---|
| land R23, R24, R20, R25, R21 and R22 | each phase's PR green | one fast-forward of `main` to the newest stacked branch, as for R9 to R18 |
| start R19 | on or after 2026-11-19 | tell any session to proceed, or let the dated schedule start it; it moves CI's runners to Ubuntu 26.04 (D45) |
| list the plugin and the power, optional | R21 landed | submit the plugin to Anthropic's plugin directory and the power to Kiro's catalog, with the text in `docs/LISTING.md` |
| the Scorecard badge's first score | R22 landed | nothing to do: the first run on `main` publishes it; check the README's badge shows a score |
| the OpenSSF Best Practices form | R22 landed | sign in at bestpractices.dev, create the project, and paste the answers from `docs/BEST-PRACTICES.md` |
| the gate with a person (12b.3, 10.1) | now | find someone outside the repository; they follow the README on a project of their own, by `docs/history/usability-gate.md` |
| Kiro's GUI pass | now; the power's part after R15 | one scan through Kiro, and from R15 the power installed from the repository, recorded in `docs/acceptance/` |
| a self-hosted Mac runner, optional | now | register one with the label `docker-desktop` |
| a second maintainer (28.1.3) | any time | `MAINTAINERS.md`'s five steps |
| AWS measured runs: ECR mirror and CodeBuild (F1.10) | now | run once in an AWS account and record the numbers; the steps are in `AIR-GAPPED.md` and `docs/examples/` |
| free disk on the build Mac | now | 30 GB free on 2026-09-29; R9.1 prunes Docker's build cache itself below 20 GB |
| one finding for one package in many lockfiles | R9.3 | a dependency finding's identity is package, version and advisory, without a path (ADR-0003), so the same vulnerable version pinned in two lockfiles of a monorepo is one finding at one path; the second lockfile is never named. Decide whether a finding should list every lockfile it was found in |
| `doctor`'s parity test, flaky once | R18.2 | `test_cli_parity`'s `doctor` case compares two calls that both probe the real Docker; it failed once in a full run on 2026-10-02 and passed alone and in the next. Decide whether it should fake the runtime, as the other readers' cases do |
| the Mac lane over a cloud-built stack (D61a) | the stack landed | `scripts/acceptance.py --generate` and `scripts/eval.py --compare tests/eval/baseline.json` on the Mac, recorded in the last phase's `docs/acceptance/r<n>.md` |
| R21.3's smoke run, locally (D61h) | R21 landed | ask a local session to run it, within D58's $2 |
| plan 2.0 (D57) | R24 landed | ask any session for 2.0's phases, written from D57 and the review of 2026-10-03; each part gets its ADR, and each ADR the owner's acceptance |
| revisit a decision in §5 | any time | `/grill-with-docs` |
