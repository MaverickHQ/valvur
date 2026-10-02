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
  at $5 across R17 to R19 (D46). Past a cap they are skipped and noted in §8.
- **A dated phase waits for its date.** R19 starts on or after 2026-11-19. Until then the
  executor treats it as §8 does: it stops after R18 and leaves R19's row in §8.
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
hook under `CLAUDE.md` §4. The owner may revisit any
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
| D42 | **D22's three missed targets are lowered to what `1.2.0` measured** (the owner, 2026-10-02; amends D22): SAST-Python 11.1, SAST-JS 15.0, real-code precision 3.7, on both lanes. The gap is accepted, and no rule-writing phase is planned. The ratchet still holds each track within 2 points of its baseline, the README claims only what is measured, and a future decision may raise a target again. The other five targets stand, all met. | none needed |
| D43 | **Every requirement ID cited is defined** (amends §3's last rule). `scripts/check_traceability.py` also fails on an `F<n>.<n>` or `N<n>.<n>` ID cited in the repository's documents, code, tests or workflows that `requirements.md` does not define, naming each with its first `file:line`. The first version's IDs, mapped in the archive, are exempt by that map, not by a list. Found by R16.4: N3.4 and N3.5 were cited by D33, D34, two scripts, two test files and a workflow for the whole build, and defined nowhere. | if more than 20 cited IDs are undefined on the first run, they are recorded in the traceability baseline as debt and only new ones fail, as uncited requirements are |
| D44 | **A hook that asks before an install** (the owner, 2026-10-02, under `CLAUDE.md` §4; F3.16). A Claude Code `PreToolUse` hook on the `Bash` tool, shipped in the plugin and pinned with its server (`uvx --from valvur==<version> valvur hook pre-tool-use`). When a command installs named packages, it runs the same check as `valvur check`, offline, and when any package is flagged it answers `ask` with each verdict, so the human decides. The commands: `npm`, `pnpm`, `yarn` and `bun` add and install; `pip`, `uv pip`, `uv add` and `poetry add`; `cargo add`; `gem install`; `composer require`. Otherwise it says nothing. It never answers `deny`, never runs or edits anything, and opens no socket. When valvur cannot check, because the index is absent, it answers `ask` naming the cause and `valvur update`, so the check is never silently off. It is not written by `init --write`: a hook in a project's own settings would run for every contributor without their choosing it. | if Claude Code's hook contract cannot carry `ask` from a plugin, the hook prints its verdicts as context and the skill's rule stands alone, recorded; Kiro gets the hook only if its documented hooks can do the same |
| D45 | **The runner move** (28.3.8, O5). GitHub's `ubuntu-latest` became 26.04 on 2026-10-19. On or after 2026-11-19, every `runs-on` and matrix runner moves from `ubuntu-24.04` to `ubuntu-26.04`, and `-arm` likewise; the corpus, the acceptance set and the Score run on the move; N1.1 and N1.4 are measured against their 24.04 numbers and recorded in `requirements.md`. | if Podman or unprivileged user namespaces fail on 26.04 three times for runner reasons, the jobs that need them stay on 24.04, and the README's platform line says what is tested where |
| D46 | **Agent runs: $5** for R17 to R19, for R18's smoke run alone, which is the one agent run that needs a shell to reach the hook. It runs in an empty scratch directory with stub `npm` and `pip` first on `PATH`, which record their arguments and exit, so no package is ever installed; the names asked for are made up and never published. | past the cap, the smoke run is replaced by replaying recorded hook inputs through the plugin's command, and §8 says so |

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

- [ ] **R18.1** **Read and measure first** (D44). Read Claude Code's hook documentation and
  record, with each source:
  - the `PreToolUse` event and its matcher;
  - the fields on stdin, and the decision output, `ask` in particular;
  - how a plugin declares a hook (`hooks/hooks.json`, `${CLAUDE_PLUGIN_ROOT}`).

  Read Kiro's hook documentation the same way. Collect the install commands agents
  actually wrote in R12.5's scenario transcripts and the acceptance agent runs. Behaviour:
  the STATUS records each fact with its source, and each command form with its count.
- [ ] **R18.2** **Install commands, parsed** (D44). Behaviours, one test each:
  1. npm, pnpm, yarn and bun names, with versions, tags and scopes;
  2. pip, `uv pip`, `uv add` and poetry names, with specifiers and extras;
  3. `-r requirements.txt` read as the file it names, from the command's directory;
  4. cargo, gem and composer names;
  5. each command of a chain (`&&`, `;`, `|`) parsed on its own;
  6. flags, URLs, paths and git references are never taken for names;
  7. a command that is not an install, or an install with no names (`npm ci`,
     `npm install`), yields nothing: the lockfile's packages are the scan's.
- [ ] **R18.3** **The hook answers** (D44). `valvur hook pre-tool-use` reads Claude Code's
  input on stdin. Behaviours:
  1. a flagged package: `ask`, with each package's verdict and reason;
  2. nothing flagged: no output, exit 0;
  3. a tool other than `Bash`, or a command that installs nothing: no output;
  4. no index: `ask`, naming the cause and `valvur update`;
  5. it never answers `deny` and never runs the command;
  6. no socket is opened (the conftest guard);
  7. 50 names in under 1 s (`timing`).
- [ ] **R18.4** **Shipped in the plugin** (D40, D44). Behaviours:
  1. `plugins/valvur/hooks/hooks.json` names the hook, pinned like the server, and
     `test_version.py` holds the pin, which `prepare_release.py` moves;
  2. `claude plugin validate --strict` passes;
  3. recorded hook inputs replayed through the plugin's own command line answer as R18.3
     says;
  4. the smoke run, under D46: `claude -p` with the plugin, asked to install a made-up
     npm package. It passes when the transcript shows the hook's `ask` and the stub
     `npm` recorded nothing.
- [ ] **R18.5** **Said where it matters.**
  - `CLAUDE.md` §4 records the owner's approval of this one hook.
  - The skill and the README's skill section name the hook, and `valvur init` says the
    plugin brings it.
  - `CHANGELOG.md` `[Unreleased]` gains it.

  Behaviours: the skill's tests and the documented-commands test pass; `CLAUDE.md` stays
  under 200 lines.

**Exit:** every behaviour green; the smoke run recorded, or D46's fallback; the Score
unchanged on both lanes; the acceptance set green on both lanes. A release of this is the
owner's choice (§8).

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
| land R17 to R18 | each phase's PR green | one fast-forward of `main` to the newest stacked branch, as for R9 to R16 |
| start R19 | on or after 2026-11-19 | tell any session to proceed, or let the dated schedule start it; it moves CI's runners to Ubuntu 26.04 (D45) |
| release the hook, optional | R18 landed | a `1.3.0` with the hook is the owner's choice: `scripts/prepare_release.py 1.3.0`, then `docs/RELEASING.md` |
| list the plugin and the power, optional | R16 landed | submit the plugin to Anthropic's plugin directory and the power to Kiro's catalog |
| the gate with a person (12b.3, 10.1) | now | find someone outside the repository; they follow the README on a project of their own, by `docs/history/usability-gate.md` |
| Kiro's GUI pass | now; the power's part after R15 | one scan through Kiro, and from R15 the power installed from the repository, recorded in `docs/acceptance/` |
| a self-hosted Mac runner, optional | now | register one with the label `docker-desktop` |
| a second maintainer (28.1.3) | any time | `MAINTAINERS.md`'s five steps |
| AWS measured runs: ECR mirror and CodeBuild (F1.10) | now | run once in an AWS account and record the numbers; the steps are in `AIR-GAPPED.md` and `docs/examples/` |
| free disk on the build Mac | now | 30 GB free on 2026-09-29; R9.1 prunes Docker's build cache itself below 20 GB |
| one finding for one package in many lockfiles | R9.3 | a dependency finding's identity is package, version and advisory, without a path (ADR-0003), so the same vulnerable version pinned in two lockfiles of a monorepo is one finding at one path; the second lockfile is never named. Decide whether a finding should list every lockfile it was found in |
| a `scan_cancel` in the first milliseconds cancels nothing | backlog (R6) | sent before the scan's job exists, the cancel finds no job and the scan then runs to the end. Rare; a fix would queue the cancel for the job about to start |
| revisit a decision in §5 | any time | `/grill-with-docs` |
