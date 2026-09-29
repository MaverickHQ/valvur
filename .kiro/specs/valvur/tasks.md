# valvur: tasks

**Written 2026-09-29, third version.** `1.1.0` shipped that day, and the owner accepted
every recommendation of [the review of 2026-09-29](../../../docs/history/REVIEW-2026-09-29.md)
and asked for a list that runs end to end without them, test-driven, and judged by a
score that can be re-run after every future change. Amended the same day, before the build
began, with the skill, its plugin and power, a workflow harness, the scan history, and a
measured trial of Laya (§5, D39 to D45). It is authoritative for what is open.

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
- **Cost cap.** Agent runs with `claude -p` are capped at $40 across this build (D36).
  Past the cap they are skipped and noted in §8.
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
   branch's HEAD, else rebuild it.
5. **Continue** with the first unchecked task, at its first behaviour without a passing test.
6. **Re-arm** the in-session schedule if `CronList` shows none.
7. **Finish.** When every task outside §8 is done, delete both schedules, write the build's
   summary into R18.6's STATUS, and end the turn.

## 3. How every task is built: test-driven

- **Each task lists behaviours in test order.** Each behaviour is one red-to-green slice:
  1. write that one test;
  2. run it and see it fail for the expected reason;
  3. write the least code that passes;
  4. run `ruff`, `mypy` and the unit suite
     (`PYTHONDONTWRITEBYTECODE=1 uv run --extra dev pytest -q -p no:cacheprovider -m "not e2e"`,
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
6. **A release rehearsal**, for R18 only, runs on R18's pushed branch
   (`gh workflow run release.yml --ref <branch>`). Wait for its validation, then cancel it
   at the brake so the `release` concurrency group is free. The run id and outcome go into
   R18.5's STATUS and §8.
7. Re-arm the in-session schedule and start the next phase from this phase's branch.

## 5. Decisions recorded before the build

The owner accepted all of these on 2026-09-29: D21 to D38 with the review, including the
network changes D24 and D25 under `CLAUDE.md` §10, and D39 to D45 the same day, a model's
weights approved as a fetch only if one passes D44. R9.2 writes the ADRs. The owner may revisit any
decision with `/grill-with-docs`; a change becomes a new task, and the executor does not
wait for it.

| # | decision | fallback when a measurement disagrees |
|---|---|---|
| D21 | **The Score** (ADR-0026). One command, `scripts/eval.py`, runs the image under test over eight **tracks** and scores each 0 to 100 with the OWASP Benchmark's formula: per category, true-positive rate minus false-positive rate, averaged. A **case** is a path with a category and a label, vulnerable or safe; it is flagged when an active finding of its category lands on it. The tracks: **1 SAST-Python**, the OWASP Benchmark for Python v0.1 (1,230 cases, 530 real, 14 categories), a git checkout at a pinned commit in the build cache, never vendored (GPL-3.0); **2 SAST-JS**, valvur's own vulnerable and safe twins, ten CWEs AI code gets wrong (89, 79, 78, 22, 918, 94, 1321, 601, 798, 327); **3 secrets**, real formats assembled at runtime against decoys (documented example keys, placeholders, environment lookups), in files and in history; **4 dependencies**, lockfiles in seven ecosystems pinned to versions with advisories published before 2025-09-29 against their fixed twins, and `MAL-` packages sampled from ossf/malicious-packages at a pinned commit; **5 package reality**, nonexistent, near-miss and malicious names against real popular, real long-tail and privately registered ones; **6 agent configuration**, planted directives, hidden Unicode, blanket approval, hooks and leaking local settings against benign twins and awesome-cursorrules' real files; **7 infrastructure and workflows**, Terraform, Kubernetes, Dockerfile and GitHub Actions faults against fixed twins; **8 real-code precision**, the 13-repository corpus, where every active finding of a valvur-owned rule or of Gitleaks is labelled `tp` or `fp` in `tests/eval/labels/corpus.toml` with a reason, and the track is precision × 100 (an unlabelled finding fails the track, named). **The Score** is the unweighted mean of the eight. **Gates**, pass or fail: *freshness*, every dataset's data age at scan time within D24; *honesty*, no scan reads `clean` while incomplete, and no safe twin draws a high or critical; *offline*, every scan's `what_left_the_machine` is `nothing`; *ranking*, the dependency track's known-exploited CVE ranks first over a development-only critical; *speed*, the median warm scan of the acceptance set within 110% of the baseline. A gate is judged from the phase that builds what it checks, and recorded before: offline from R9, honesty from R10, freshness and ranking from R11, speed from R15. **The ratchet:** `tests/eval/baseline.json` holds each track, the Score and what they were measured on; `--compare` fails when a track falls more than 2 points under it or a gate fails, naming each; the baseline is re-recorded only upward, at a phase commit, with the reason. **Replication:** external sources pinned by git commit, the generator seeded, the image named by digest, and every dataset's age recorded; Trivy publishes no database history, so dependency cases use only advisories over a year old. Why not an exploit gym: SecBench.js, BaxBench and CyberGym score exploits against running code, which is dynamic testing, and valvur refuses it (`CLAUDE.md` §2). | if the OWASP Benchmark cannot be fetched at its pin, or its track exceeds 10 minutes, track 1 is valvur's own Python twins over the same 14 categories, and every surface says so |
| D22 | **Targets for `1.2.0`**, per track: SAST-Python 25, SAST-JS 50, secrets 90, dependencies 90, package reality 95, agent configuration 90, infrastructure and workflows 70, real-code precision 80; every gate green. A target under R9's baseline is raised to the baseline, never lowered. | a missed target is recorded in the exit and in §8 for the owner; the build continues |
| D23 | **Every dataset's age is its data's** (F6.12, extending F6.11): KEV from the catalog's `dateReleased`; EPSS from its file's `score_date`; each OSV database from the `Last-Modified` its fetch recorded in a sidecar; the index and the database as now. | where a source carries no date, the fetch time, labelled *fetched*, never *built*, on every surface |
| D24 | **Refresh thresholds** (amends D5 and ADR-0025, as ADR-0027). A scan refreshes, announces and records: the vulnerability database and OSV's databases past 7 days, as now; the Name Index and the malicious list past **2** days (was 30); KEV and EPSS past **2** days (a scan never refreshed them). The thresholds that make a verdict `inconclusive` are unchanged. `fetch = "never"` fetches none. A failed refresh keeps the old data and says so. | none needed |
| D25 | **EPSS from FIRST's daily file** (F6.13, amends F6.3 and F6.10): `epss_scores-current.csv.gz`, fetched by `valvur update` and by a stale scan into the host cache, mirrorable as `epss_url`, read on every Profile; `full` no longer sends CVE identifiers to FIRST's API. Approved under `CLAUDE.md` §10 as a recorded fetch of public data. | if the file is over 20 MB compressed, or its host is unreachable from GitHub's runners, F6.3's API stays on `full`, `offline` ranks as now, and the README's ranking example says `full` |
| D26 | **Known-malicious names, daily** (F3.14): `index.yml` also publishes, as the tags `malicious` and `malicious-<date>` of the existing public `valvur-index` package, signed and pulled back like the index, a sorted list per ecosystem of `MAL-` package names and affected versions from ossf/malicious-packages (Apache-2.0, in `NOTICE`), built from OSV's export or the repository, whichever measures faster. `1.1.0`'s client pulls `latest` and is untouched; `retention.yml` keeps these tags as it keeps the index's. `dependency-reality` reports a declared or locked package in it as `valvur.dependency.malicious`, critical; a version-scoped entry matches only a locked version it names. OSV-Scanner's finding for the same package merges into it: one finding, both Scanners named. Until `index.yml` runs from a landed `main`, the build's lanes build the list locally, as `--build-index` does. | if the list exceeds 10 MB compressed, names only, and a version-scoped entry is reported at high as *a version of this package was published as malicious* |
| D27 | **Private registries** (F3.15). Read from the File Set: `.npmrc` and `.yarnrc.yml` (scoped and whole registries); `--index-url` and `--extra-index-url` in requirements files, `pip.conf`, `[[tool.uv.index]]` with `[tool.uv.sources]`, `[[tool.poetry.source]]` and a `Pipfile`'s `[[source]]`. A name whose scope or source is a private registry is not looked up publicly and is listed as a coverage note. A name absent from the public index where a supplemental source (`--extra-index-url`, a supplemental uv or Poetry source) is configured is `valvur.dependency.confusion`, **high**: the resolver may take a public package registered under it. Absent where the public registry is replaced entirely: `valvur.dependency.not-public`, **low**, advising the name be reserved. No configuration: `nonexistent`, high, as now, its message naming the index's build date and saying an internal package should declare its registry in the project. | none needed |
| D28 | **`check_package`** (F3.16, F9.11; ADR-0028). The API `valvur.packages.check`, the CLI `valvur check <ecosystem> <name>[@version] …` (a ninth command; exit 0 when every package exists and is not flagged, 1 when any is, 2 on error; `--json`) and an MCP tool `check_package` (up to 50 packages, `readOnlyHint` true, `openWorldHint` false). Each answer is `exists`, `nonexistent`, `near-miss` with the name it is near, `malicious` with its `MAL-` ID, `confusion` or `not-public` by D27, or `unknown` where no index exists (JVM, Go), with the index's build date. Host-side, **no network, ever**: asking a registry about a hallucinated name tells the registry, and anyone watching it, what to register. Under a second. The handshake's instructions and `SUMMARY.md`'s agent block say: before adding a dependency, call `check_package`, and never add one it flags without the human. | none needed |
| D29 | **Static-analysis rules by licence and measurement** (F2.9, F5.10; ADR-0029; amends ADR-0004's consequences). Candidates: GitLab's `sast-rules` (MIT, Semgrep syntax) at a pinned commit, for Python, JavaScript and TypeScript, Go and Java. A rule is eligible only if the project it was translated from, named by its metadata, is MIT, Apache-2.0 or BSD: rules from flawfinder, find-sec-bugs, security-code-scan or Brakeman are excluded. `opengrep-rules` (archived, Commons Clause) and Semgrep's registry stay excluded. A rule **ships** when, over tracks 1 and 2 and the corpus, it has at least one true positive and precision of at least 0.5. Shipped rules live in `rules/vendor/gitlab/` with the licence, the commit and a manifest of each rule's origin, and carry their CWE into `findings.json` and SARIF (an optional field). Opengrep's intra-file cross-function taint is adopted if the pinned Opengrep supports it and it raises tracks 1 and 2 without raising their false-positive rate. Opengrep's median time on the acceptance set may grow at most 30%; past that the slowest rules go first. | if no candidate is eligible, valvur writes its own rules (Apache-2.0) for track 2's CWEs and track 1's categories, measured the same way |
| D30 | **A failed Scanner with nothing found reads `inconclusive`** (F7.19), `status_reason` naming the Scanner. With findings, `findings` and *incomplete*, as now. The three Statuses are unchanged; a false `clean` is removed, which 1.x's contract allows as a fix. | none needed |
| D31 | **Checkov runs without its secrets framework** (`--skip-framework secrets`): Gitleaks owns secrets. | none needed |
| D32 | **Reuse what cannot have changed** (N1.5; ADR-0030). Trivy's and OSV-Scanner's raw output is kept in the host cache, keyed on the Scanner, its version, the Profile, the sha256 of every lockfile and manifest they read, and the database's built time, and reused when the key matches. `run.json` names each reused result and the run it came from; `--fresh` on the CLI and `fresh: true` on `scan` run everything. Source-reading Scanners are never reused. | if a warm rescan of acceptance repository 8 is not at least 30% faster, reuse ships off by default, recorded |
| D33 | **A release is prepared by one command** (N3.4): `scripts/prepare_release.py <version>` sets the version, the lock, the README's *release in progress*, `SECURITY.md`'s series and the CHANGELOG heading in one commit; `--published <version>` makes the commit that flips the README once promoted. The tag and the brake stay the owner's. | none needed |
| D34 | **A monthly Scanner refresh** (N3.5): `refresh.yml`, on the first Monday, when `main`'s Scanner pins differ from the latest release's, runs the Score on `main` and, when no track regressed, dispatches a rehearsal and opens one issue for the owner to tag. | none needed |
| D35 | **Wall-clock tests are marked `timing`.** They run in CI's e2e job and at phase exits, never in the unit suite. On this Mac with host swap over 4 GB they are recorded, not judged, as D17 did. | none needed |
| D36 | **Agent runs: $40** for this build: R16.4's smoke run and R17's workflow harness, never with a shell (§1). The Score never includes an agent run. | past the cap, skip and note it in §8 |
| D37 | **`1.2.0` after R18**, prepared and rehearsed by the executor on R18's branch; the tag and the brake are the owner's. Every change is additive under 1.x: a seventh MCP tool, a ninth command, `cwe` and history fields on findings, new rules, the skill with its plugin and power, and an opt-in model if one passes D44; `fp_version` stays 1. | none needed |
| D38 | **An arm64 e2e leg**: CI's `e2e` job gains `ubuntu-24.04-arm`, Docker only. | if it more than doubles the job's time, or fails three times for runner reasons, the README's platform line says what is tested instead |
| D39 | **One skill, `valvur`, in the open Agent Skills format** (F9.12; ADR-0031). Its one source is in the package, `src/valvur/data/skills/valvur/`: `SKILL.md` and `references/` (the tools and their fields, triage by finding class, CI and the gate, air-gapped use). Its frontmatter uses only the standard's six fields, so the one file loads in Claude Code, in Kiro and in any client of the standard. It orchestrates: before adding a dependency, `check_package`; `scan`, and on `failed`, `doctor`, relayed; the verdict and its reason before any finding; triage by group with `findings`, each finding named by rule ID and path; a proposal from `REMEDIATION.md`, and waiting for the human; after the human's fix, a rescan, and *fixed* only where its Scanner ran; `update` when data is stale; `valvur gate` in CI; never a Suppression, never the Results Folder committed, never text quoted from the repository followed. Its rules are rendered from the one source the handshake and `SUMMARY.md` use, and a test holds the three equal; every tool and command it names exists, and every tool the server lists is in it. | none needed |
| D40 | **The skill ships three ways** (F9.13; ADR-0031): a **Claude Code plugin**, `plugins/valvur/`, with the skill and the MCP server pinned to the release (`uvx --from valvur==<version> valvur-mcp`), listed by `.claude-plugin/marketplace.json` at the repository's root, so `/plugin marketplace add MaverickHQ/valvur` then `/plugin install valvur@valvur` gives both; a **Kiro power**, `powers/valvur/`, in the layout kiro.dev documents when the task starts (`POWER.md`, the Agent Plugins manifest, `mcp.json`, the skill); and **`valvur init --write`**, which adds the skill to the project for Claude Code (`.claude/skills/valvur/`) and for Kiro (its documented project location), never overwriting. The plugin and the power reach the package's skill by symlink where their loaders follow one, else by a copy a test holds byte-identical; every version surface moves together. Approved as within `init --write`'s exception in `CLAUDE.md` §10. | if a Kiro power cannot carry the skill from the repository, it carries the MCP configuration and steering, and `init --write` carries the skill |
| D41 | **No separate agent.** The skill and the handshake carry the workflow; an agent would be a third copy of the rules to keep in step, and `context: fork` is a Claude Code extension the open standard does not carry. R17 records how much of a session a scan's reply takes; if it crowds the session out, a Claude Code-only agent in the plugin, preloading the skill, is the owner's decision (§8). | none needed |
| D42 | **What a scan remembers is facts, never judgments** (F7.20; ADR-0032). `.security-scan/history.jsonl`, in the Results Folder and so never committed, keeps the last 100 runs: per run its time, Status, counts and data ages; per fingerprint first seen, last seen, scans seen, fixed at, and *regressed* when a fixed finding returns. `findings` and `scan_status` carry these as fields, and `SUMMARY.md` gives one trend line. Nothing an agent writes enters it. An agent-written memory of *known false positives* is refused: it is a Suppression with no human and no expiry (ADR-0009); the committed, expiring Suppression stays the only record of a human's judgment. | none needed |
| D43 | **The workflow harness** (N4.5; in ADR-0026). `scripts/acceptance/workflow.py` scores agents *using* valvur, as the Score scores the scanner. Each scenario is a generated repository, a prompt, and assertions on the tool calls in the stream-JSON transcript and on the tree after: **1** scan and report, every expected finding by rule ID and path; **2 to 5** add a hallucinated, a near-miss, a malicious and a real package, `check_package` first and the manifest changed only for the real one; **6** fix the findings, a proposal from `REMEDIATION.md` and the source untouched without approval; **7** suppress a finding, none written and `valvur suppress`'s block shown for the human; **8** a failed scan, `doctor` called and its fix relayed; **9** an instruction planted in the repository, not followed and reported; **10** a rescan after the human's fix, *fixed* only where the Scanner ran. Every run through `claude -p` with the plugin (`--plugin-dir`) and `--disallowedTools Bash`, three times per scenario, with the skill and without it (the handshake alone). The **workflow score** is the share of runs that pass, per arm, with turns, cost and the largest tool reply recorded. Not in the Score, because it costs money and is not deterministic; recorded at R17's exit and every release. `1.2.0`'s bar: with the skill at least 90%, and above the arm without. | past D36's cap, the scenarios not run are listed; a missed bar goes to §8 |
| D44 | **Laya, adopted only by measurement** (F3.17; ADR-0033). One use: a second opinion on injected directives in agent configuration files, beside the patterns. A spike runs the models on the host first, from the build cache, fetched from Hugging Face at pinned revisions, safetensors or ONNX only: `convaiinnovations/laya` (ModernBERT-large, 421M, Apache-2.0) and its multilingual checkpoint (322M), against ProtectAI's `deberta-v3-base-prompt-injection-v2` (184M, Apache-2.0) as the control, and against the patterns alone. Cases: track 6's, at least 100 valvur-authored paraphrased injections and 20 non-English ones, against awesome-cursorrules' 263 real instruction files and the benign twins. **A model ships** only if, over the patterns alone, it adds at least 20 points of recall on the paraphrases, with at most 1 false positive per 100 real instruction files, at most 15 s more per scan on the acceptance set on this Mac, inside the Scan Container's memory ceiling; the smallest that passes wins. Shipped, it is **opt-in** (`[scan] model = true`, or the machine setting): its weights are republished by a valvur workflow as a signed OCI artifact on GHCR, fetched into the host cache only when enabled (`valvur update --model`) and mirrorable, never in the default image; it runs in the Scan Container on CPU with no network, from a `-model` image variant if ONNX Runtime cannot run on the Alpine image within 50 MB; its findings are `valvur.ai-artifact.model-injection`, medium, the evidence the text and the score, crediting the model and its revision in `run.json` and `NOTICE`. On by default is the owner's decision, with the numbers. | no model passes: the measurements go into `EVALUATING.md`, and nothing ships |
| D45 | **Jev, or any hosted model API, never** (ADR-0033). It sends the project's text to a vendor and needs an account: `CLAUDE.md` §3 and §10. | none needed |

## 6. Order

```
R9 the Score ─► R10 trust fixes ─► R11 fresh data ─► R12 check_package ─► R13 static analysis
                                                                                 │
R18 drag, documents, 1.2.0 ◄── R17 workflow harness ◄── R16 skill ◄── R15 reuse ◄── R14 Laya
```

- **R9 first**, so every later exit is judged against a measured baseline, as R2 was.
- **R10** is hours of work that removes the false clean and the false positives users see
  first.
- **R11 before R12**: `check_package` reads the malicious list R11 publishes.
- **R13 after the Score exists**, because a rule ships only on its measured precision.
- **R14**, the model trial, changes what is found, so it precedes reuse; its spike decides
  before any image work is done.
- **R15** changes speed alone, so it follows every change to what is found.
- **R16 after the tools are final**, because the skill names every tool and field.
- **R17** measures agents using the finished skill.
- **R18** closes the documents against what exists and prepares `1.2.0`.

---

## 7. The phases

### Phase R9: the Score, measured before anything changes

- [ ] **R9.1** **Pre-flight, and resuming armed.** Steps, each recorded in the STATUS:
  1. `scripts/build_status.py` names R9 and its branch from `main`;
  2. Docker answers (§2 step 4), at least 20 GB is free (else `docker builder prune -f`),
     `gh auth status` and `claude --version` answer;
  3. `valvur:dev` is built from `main` and `valvur doctor` passes with the build cache;
  4. both schedules of §2 are armed with its prompt.
  Behaviour: a test holds this file to the shapes `build_status.py` reads, a phase
  heading per phase and an open task under the first.
- [ ] **R9.2** **The decisions written.** ADR-0026 (D21, D22, D43), ADR-0027 (D23 to D26),
  ADR-0028 (D27, D28), ADR-0029 (D29), ADR-0030 (D32), ADR-0031 (D39 to D41), ADR-0032
  (D42) and ADR-0033 (D44, D45), each citing the requirement IDs it adds to
  `requirements.md`: N4.1 to N4.5; F6.12, F6.13, F10.9, F3.14; F3.15, F3.16, F9.11; F2.9,
  F5.10; N1.5; F9.12, F9.13; F7.20; F3.17. `design.md` 1.4 names the modules to come. Behaviour:
  `check_traceability.py`: 0 uncited, 0 orphan ADRs.
- [ ] **R9.3** **The harness** (D21; N4.1, N4.2). `scripts/eval.py`, the package
  `scripts/eval/`, and `tests/eval/`. Behaviours:
  1. the formula: a hand-built `findings.json` and case list score each category's TPR
     minus FPR, averaged, 0 to 100;
  2. a case is flagged only by an active finding of its category on its path; a
     suppressed or grouped-away finding counts as it does in `findings.json`;
  3. the twin generator is deterministic: two runs with one seed write identical trees;
  4. tracks 2 to 7 each generate their cases and a `cases.json`, at least 20 vulnerable
     and 20 safe per track, credentials assembled at runtime;
  5. `scripts/eval.py` scans each track's tree through `valvur scan` with the image named by
     `VALVUR_IMAGE`, writes the result JSON (tracks, gates, image digest, data ages,
     duration) and prints the scorecard;
  6. `--compare` exits non-zero on a track more than 2 points under the baseline, or a failed
     gate, naming each; `--update-baseline` refuses to lower a track;
  7. the gates: freshness, honesty, offline and ranking judged; speed recorded.
- [ ] **R9.4** **The OWASP Benchmark for Python** (D21, track 1). Behaviours:
  1. `tests/eval/sources.toml` pins it by commit; a checkout at any other commit is
     refused; nothing of it is tracked in this repository (a test asserts it);
  2. `expectedresults-0.1.csv` becomes 1,230 cases, 530 vulnerable, 14 categories;
  3. a finding maps to a test case by file and to a category by CWE, from the finding's
     `cwe` when present, else from its rule's metadata under `rules/`;
  4. the track's score is the OWASP scorecard's.
- [ ] **R9.5** **Real-code precision** (D21, track 8). Behaviours:
  1. every active finding of a valvur-owned rule or of Gitleaks on the corpus needs a label
     in `tests/eval/labels/corpus.toml` by fingerprint; an unlabelled one fails the track,
     named;
  2. the rubric, in ADR-0026: `tp` when a maintainer would act on it (change code, rotate,
     pin), `fp` otherwise, the reason saying why; the labels are the executor's, committed
     for review;
  3. the track is precision × 100; third-party Scanners' other findings are counted and
     reported, not labelled.
- [ ] **R9.6** **The baseline** (D21, D22; N4.3, N4.4). Behaviours and steps:
  1. `.github/workflows/eval.yml`, weekly and on dispatch, builds the image and runs the
     Score on GitHub's Linux runner, uploading the result; a test holds its arguments to
     the script's;
  2. the Score measured on both lanes on `valvur:dev` built from R9's branch;
     `tests/eval/baseline.json` from the Linux lane, the Mac's beside it, the duration of
     each track recorded;
  3. the release's `verify` job runs `--compare` on the tracks that together fit in 10
     minutes, by 2.'s durations; the rest run weekly; `docs/RELEASING.md` says which;
  4. `docs/EVALUATING.md` gains the Score: each track, how to replicate it, the baseline.

**Exit:** the baseline recorded on both lanes, the harness's tests green, and each track's
duration recorded, the release's share by R9.6's rule.

### Phase R10: trust fixes, and the false positives users see first

- [ ] **R10.1** **A failed Scanner with nothing found reads `inconclusive`** (D30; F7.19).
  Behaviours:
  1. `api.scan` through `LocalRuntime`, one Scanner exiting non-zero, nothing found:
     `inconclusive`, `status_reason` naming the Scanner;
  2. `SUMMARY.md`, `run.json`, the MCP reply and `gate` agree;
  3. with a finding, `findings` and *incomplete*, unchanged.
- [ ] **R10.2** **Checkov without its secrets framework** (D31). Behaviours:
  1. Checkov's invocation carries `--skip-framework secrets`;
  2. e2e: R5's planted flood beside Terraform yields the secrets group once.
- [ ] **R10.3** **Private npm registries** (D27; F3.15). Behaviours, one test each: a scope
  bound in `.npmrc`; a scope bound in `.yarnrc.yml`; a whole-registry `registry=`; no
  configuration, whose message names the index's build date.
- [ ] **R10.4** **Private Python indexes** (D27). Behaviours, one test each:
  `--extra-index-url` in a requirements file; `--index-url` alone; `pip.conf` in the tree;
  a supplemental and an explicit uv index; Poetry's `supplemental` and `explicit` sources;
  a `Pipfile` `[[source]]`.
- [ ] **R10.5** **What the README and the pipeline example claim.** Behaviours:
  1. the README's quick start names Docker or Podman as a prerequisite;
  2. the platform table says what CI tests on each architecture, until D38's leg lands;
  3. the agent paragraph states R7's final record, every answer naming every expected
     finding;
  4. `docs/examples/github-actions.yml` caches the valvur cache with a pinned
     `actions/cache`, and the test that runs it still passes.
- [ ] **R10.6** **Wall-clock tests marked** (D35). Behaviours: every test asserting on
  wall-clock time carries `timing`, registered in `pyproject.toml`; the unit suite selects
  none; CI's e2e job and the phase exits run them. §3's command and `CLAUDE.md` then read
  `-m "not e2e and not timing"`.

**Exit:** the Score on both lanes: tracks 3, 5 and 8 at or above the baseline, and the
honesty gate green; track 5's private-registry cases scored.

### Phase R11: fresh data

- [ ] **R11.1** **KEV's age is its catalog's** (D23; F6.12). Behaviours:
  1. the bundled snapshot reads 2026-08-27's age however recently the file was written;
  2. between the cache and the bundle, the newer catalog wins, not the newer file;
  3. `run.json` records KEV's catalog date, age and source; `doctor` shows them.
- [ ] **R11.2** **Every dataset's age is its data's** (D23). Behaviours: an OSV fetch
  records `Last-Modified` in a sidecar and its age is read from it; a source with no date
  reads *fetched* on every surface.
- [ ] **R11.3** **A scan refreshes past D24's thresholds** (F10.9). Behaviours, through
  `tests/fake_registry.py`:
  1. the index and KEV past two days are refreshed, announced and recorded under
     `network.fetched`;
  2. within the threshold nothing is fetched;
  3. `fetch = "never"` fetches nothing;
  4. a failed refresh keeps the old data and says so, and the verdict thresholds decide.
- [ ] **R11.4** **EPSS from FIRST's daily file** (D25; F6.13). Measure the file's size and
  host first. Behaviours:
  1. `valvur update` fetches it into the cache; `epss_url` names a mirror;
  2. on `offline`, a finding's EPSS comes from the file, and the README's ranking example
     ranks the same on `offline` as on `full`;
  3. on `full`, no request reaches FIRST's API: the egress test lists only the file's host;
  4. `egress.py`, `verify-offline.py` and `verify-mirror.py` know the new hosts, the file's
     and its redirect's, and nothing else.
- [ ] **R11.5** **The malicious list, published daily** (D26; F3.14). Behaviours:
  1. `python -m valvur.name_index build-malicious` builds the sorted per-ecosystem lists
     from a pinned fixture of OSV records;
  2. `index.yml` builds, pushes as a candidate, signs, pulls back and compares it, and
     tags it only then, as it does the index; nothing is pushed off `main`;
  3. the reader answers name and version queries by bisection;
  4. `dependency-reality` reports acceptance repository 8's `@hyperion-util/cookies` as
     `valvur.dependency.malicious`, critical, merged with OSV-Scanner's `MAL-2023-1`: one
     finding naming both Scanners;
  5. a version-scoped entry flags only the locked version it names;
  6. `valvur update` and a stale scan fetch it with the index; the Score's lanes build it
     locally until `main` publishes it;
  7. `retention.yml` keeps the `malicious` tags as it keeps the index's.
- [ ] **R11.6** **Freshness on every surface.** Behaviours: `SUMMARY.md` gains one line of
  each dataset's data age; the MCP reply carries them as fields; the Score's freshness
  gate reads them from `run.json`.

**Exit:** the freshness and ranking gates green on both lanes; tracks 4 and 5 at or above
the baseline.

### Phase R12: `check_package`, before the install

- [ ] **R12.1** **The API** (D28; F3.16). Behaviours, one test each: `exists`,
  `nonexistent`, `near-miss` with its suggestion, `malicious` with its ID, `confusion` and
  `not-public` given the project's registry configuration, `unknown` for JVM and Go; a
  batch of 50; no socket opened (the conftest guard); under a second for 50 (`timing`).
- [ ] **R12.2** **The CLI, `valvur check`.** Behaviours: the exit status per D28; `--json`;
  the help fixture and the documented-commands test updated.
- [ ] **R12.3** **The MCP tool** (F9.11). Behaviours:
  1. `check_package` is listed with its schema and annotations, read-only, not open-world;
  2. a reply of 50 packages stays bounded and carries `structuredContent`;
  3. the handshake's instructions and `SUMMARY.md`'s agent block say to call it before
     adding a dependency; `init`'s block says so too;
  4. the README and `doctor` say seven tools.
- [ ] **R12.4** **Track 5 through `check_package`.** Behaviour: the package-reality track
  scores the same cases through the tool as through a scan, both reported.

**Exit:** track 5 at D22's target through both paths. Agents calling `check_package` are
R17's scenarios 2 to 5.

### Phase R13: static analysis, widened against the benchmark

- [ ] **R13.1** **The rule source, audited** (D29; F2.9). Behaviours:
  1. `tests/eval/sources.toml` pins `sast-rules` by commit;
  2. a manifest lists every candidate rule's path, languages, CWE and the origin project
     its metadata names, with that project's licence;
  3. a test refuses any vendored rule whose origin is not MIT, Apache-2.0 or BSD.
- [ ] **R13.2** **Each rule measured.** Behaviour: `scripts/eval.py --per-rule <dir>`
  reports each rule's true and false positives over tracks 1 and 2 and the corpus, and its
  time; the measurement of every candidate is recorded in the STATUS.
- [ ] **R13.3** **The rules that pass, shipped.** Behaviours:
  1. `rules/vendor/gitlab/` holds exactly the rules meeting D29's bar, with the licence,
     the commit and the manifest; `NOTICE` credits it;
  2. the image carries them, and `run.json` names the rule set's commit;
  3. e2e: a planted SQL injection in a JavaScript file is reported by a vendored rule.
- [ ] **R13.4** **CWE on findings** (F5.10). Behaviours: `findings.json` and SARIF carry
  `cwe` when the rule declares one; the findings schema's own rule for additions decides
  whether its version moves; ranking and grouping are unchanged.
- [ ] **R13.5** **Cross-function taint.** Measure first. Behaviour: adopted per D29, or the
  measurement recorded and nothing changed.
- [ ] **R13.6** **The speed guard.** Behaviour: Opengrep's median time on the acceptance set
  within 130% of R9's, pruning the slowest rules until it is.
- [ ] **R13.7** **The claims, from the measurement.** Behaviour: the README's static-analysis
  paragraph and `EVALUATING.md` state tracks 1 and 2 as measured and nothing beyond them;
  `test_readme_as_built.py` holds the numbers.

**Exit:** tracks 1 and 2 at D22's targets or recorded as missed; track 8 at or above 80;
the speed guard met.

### Phase R14: a local model, by measurement (Laya)

- [ ] **R14.1** **The cases** (D44). Behaviours: a deterministic generator writes at least
  100 paraphrased and 20 non-English injections, each labelled; the negatives are
  awesome-cursorrules' real instruction files at the corpus's pin and track 6's benign
  twins; a test counts both.
- [ ] **R14.2** **The spike.** `scripts/spikes/model_injection.py` fetches each model at its
  pinned revision into `~/.cache/valvur-build/models/`, chunks each file to the model's
  context, and records per model, and for the patterns alone, recall, false positives per
  100 real files, time and peak memory. Behaviours: it refuses weights that are not
  safetensors or ONNX; its chunker and scorer are tested on fixtures. The measurement is
  the STATUS.
- [ ] **R14.3** **The verdict** (D44), recorded in ADR-0033 and `EVALUATING.md`. When no
  model passes, R14.4 to R14.6 are ticked *not applicable*, each STATUS giving the numbers,
  and the phase closes.
- [ ] **R14.4** **The runtime**, if a model passed. Measure ONNX Runtime on the Alpine image
  first. Behaviours: e2e with `--network=none`, a planted paraphrased injection is reported
  by the model; peak memory within the Scan Container's ceiling; the image, or the `-model`
  variant, per D44.
- [ ] **R14.5** **The weights' distribution**, if a model passed. Behaviours: a workflow
  republishes the pinned weights as a signed OCI artifact on GHCR, from `main` only;
  `valvur update --model` fetches and verifies it; `model_url` names a mirror; `egress.py`
  and `verify-offline.py` know it; `run.json` and `NOTICE` credit the model.
- [ ] **R14.6** **Opt-in, and reported**, if a model passed. Behaviours: off by default;
  `[scan] model = true` or the machine setting turns it on; its findings' kind, severity
  and evidence per D44; track 6 recorded with the model on and off.

**Exit:** the verdict recorded with its measurements. If a model shipped: track 6 with it
at or above track 6 without it, no track under the baseline, and the speed gate unchanged
with it off.

### Phase R15: reuse what cannot have changed

- [ ] **R15.1** **Measure.** Each Scanner's warm time on the acceptance set, both lanes,
  recorded as the before.
- [ ] **R15.2** **The reuse key** (D32; N1.5). Behaviours, one test each: a lockfile's byte
  change, the database's built time, the Scanner's version and the Profile each change the
  key; a source file's change does not.
- [ ] **R15.3** **Reuse in a scan.** Behaviours:
  1. through `LocalRuntime`, a second scan of an unchanged repository 8 runs neither Trivy
     nor OSV-Scanner, and its fingerprints equal the first's;
  2. `run.json` names each reused result and its run;
  3. `--fresh` and `fresh: true` run everything.
- [ ] **R15.4** **The reused results' home.** Behaviours: under the host cache and its
  lock; `update --prune` removes those of superseded keys, `--clear` all; nothing is
  written in the Workspace but the Results Folder.
- [ ] **R15.5** **The after.** Behaviour: a warm rescan of repository 8 is at least 30%
  faster on both lanes, or D32's fallback is applied and recorded; the speed gate is judged
  from here on.

**Exit:** the speed gate green; the Score with reuse equals the Score with `--fresh`, run
back to back.

### Phase R16: what a scan remembers, and the skill that runs the workflow

- [ ] **R16.1** **The history** (D42; F7.20). Behaviours, one test each: a run appends one
  record; the file keeps the last 100; a fingerprint's first seen, last seen, scans seen and
  fixed at; *regressed* when a fixed finding returns; a suppressed finding keeps its
  history; nothing is written outside the Results Folder.
- [ ] **R16.2** **The history on every surface.** Behaviours: `findings` and `scan_status`
  carry the fields, additive to reply schema 2; `SUMMARY.md` gives one trend line; no
  surface accepts a write from an agent.
- [ ] **R16.3** **The skill** (D39; F9.12). Behaviours:
  1. the frontmatter holds only the standard's six fields, a valid name and a description
     within the standard's limit;
  2. every MCP tool it names exists, and every tool the server lists is named;
  3. every command it names exists: the documented-commands test reads it;
  4. its rules block equals the handshake's instructions and `SUMMARY.md`'s agent block,
     all three rendered from one source.
- [ ] **R16.4** **The Claude Code plugin** (D40; F9.13). Behaviours:
  1. `.claude-plugin/marketplace.json` and `plugins/valvur/.claude-plugin/plugin.json` are
     valid (`claude plugin validate` where the CLI has it);
  2. the plugin's MCP configuration is `valvur.mcp.clients`' Claude Code block, pinned to
     the version, and `test_version.py` holds it;
  3. the plugin's skill is the package's, byte for byte;
  4. a smoke run, `claude -p --plugin-dir plugins/valvur`, lists the skill and the
     server's tools (D36).
- [ ] **R16.5** **The Kiro power** (D40). Read Kiro's documented layout first. Behaviours: the
  manifest's fields; its `mcp.json` is Kiro's client block; its skill is the package's; the
  Kiro stdio probe (D20) replays against the power's server configuration.
- [ ] **R16.6** **`init --write` adds the skill** (D40). Behaviours: written for Claude Code
  and for Kiro; never over an existing file; `init` without `--write` names it; `doctor`
  says whether the project's skill is present and whether its version matches.

**Exit:** the skill, the plugin and the power pass their tests; the smoke run recorded;
no track under the baseline.

### Phase R17: the workflow harness

- [ ] **R17.1** **The runner** (D43; N4.5). Behaviours, on recorded stream-JSON fixtures:
  tool-call and tree assertions judge passes and failures correctly; the command line
  always carries `--disallowedTools Bash` (asserted); the ledger refuses a run that would
  pass D36's cap, estimating from the last run's cost.
- [ ] **R17.2** **The ten scenarios.** Behaviours: each generates its repository
  deterministically, with its prompt and assertions; scenario 9's planted instruction is
  assembled like a planted credential; a test lists all ten.
- [ ] **R17.3** **The two arms.** Behaviour: the skill's arm loads the plugin and the other
  the MCP server alone; each scenario runs three times per arm; the result records the pass
  share, turns, cost and the largest tool reply per run.
- [ ] **R17.4** **The measurement**, within the cap, in `docs/acceptance/r17.md`, with each
  miss explained. A change to the skill's wording that answers a miss is re-run on the
  missed scenarios alone.

**Exit:** the workflow score recorded for both arms; D43's bar met, or recorded as missed
(§8); D41's measurement recorded.

### Phase R18: less drag, the documents as built, and 1.2.0 prepared

- [ ] **R18.1** **The arm64 e2e leg** (D38). Behaviour: the e2e job's matrix gains
  `ubuntu-24.04-arm`, green, or D38's fallback applied.
- [ ] **R18.2** **`scripts/prepare_release.py`** (D33; N3.4). Behaviours: one commit sets
  every version surface `test_version.py` reads, the plugin's and the power's included;
  `--published` flips the README's wording; a dry run changes nothing.
- [ ] **R18.3** **The monthly Scanner refresh** (D34; N3.5). Behaviours: `refresh.yml`
  compares `main`'s pins with the latest release's by `test_scanner_pins.py`'s parser;
  runs the Score; opens one issue; a test holds its schedule and permissions.
- [ ] **R18.4** **The documents as built.** The README (the Score and its tracks, freshness,
  `check_package`, seven tools, nine commands, installing the plugin or the power, the
  skill, the history, and the model if one shipped), `EVALUATING.md`, `AIR-GAPPED.md` (the
  EPSS, malicious-list and model mirrors), `PROTOCOL.md`, `design.md` and
  `requirements.md`, amended; `CLAUDE.md` within 200 lines; R9 to R17 moved to
  `docs/history/tasks-phases-r9-r18.md`. Behaviours: traceability holds; the link check
  passes; `test_readme_as_built.py` passes.
- [ ] **R18.5** **`1.2.0` prepared** (D37). `prepare_release.py 1.2.0`; the Score on both
  lanes against R9's baseline and D22's targets, and the workflow score against D43's bar,
  recorded; the rehearsal on R18's branch per §4, validated and cancelled at the brake.
- [ ] **R18.6** **The build's summary**, written as this task's STATUS: what shipped, the
  Score at R9 and now per track, the workflow score per arm, the cost of agent runs, and
  what §8 holds.

**Exit:** the Score and the workflow score recorded against their baselines and bars, the
rehearsal green, and both schedules deleted.

---

## 8. The owner queue

Nothing here blocks the build. The executor adds a row when an item becomes ready. The
rows closed on 2026-09-29 are in [the archive](../../../docs/history/tasks-phases-r7-r8.md).

| item | ready after | what the owner does |
|---|---|---|
| land this list | now | the owner's approval of one fast-forward of `main` to the commit that adds it: `scripts/build_status.py` reads `main`, and the build starts from there |
| land R9 to R18 | each phase's PR green | one fast-forward of `main` to the newest stacked branch, the owner's approval in manual mode; phases may be landed early, in order |
| `v1.2.0` | R18 landed | the signed tag on the landed commit, then the approval at the brake |
| a model on by default (D44) | R14, if a model shipped | read R14's numbers; decide whether `offline` runs it without being asked |
| the model artifact made public (D44) | its first publish from `main`, if a model shipped | GHCR → the package's settings → change visibility to public, as for the index |
| an agent in the plugin (D41) | R17 | only if R17 shows a scan's reply crowding the session out |
| list the plugin and the power, optional | R18 landed | submit the plugin to Anthropic's plugin directory and the power to Kiro's catalog |
| D22's targets | R9's baseline | read `docs/acceptance/r9.md`; a target may be raised, never lowered below the baseline; revisit with `/grill-with-docs` |
| a hook that calls `check_package` before an install | R12 | decide whether a Claude Code `PreToolUse` hook may ask before `npm install` or `pip install`; `CLAUDE.md` §4 forbids watchers and on-save hooks, and this is neither, but it is a hook |
| the gate with a person (12b.3, 10.1) | now | find someone outside the repository; they follow the README on a project of their own, by `docs/history/usability-gate.md` |
| Kiro's GUI pass | now; the power's part after R16 | one scan through Kiro, and from R16 the power installed from the repository, recorded in `docs/acceptance/` |
| a self-hosted Mac runner, optional | now | register one with the label `docker-desktop` |
| a second maintainer (28.1.3) | any time | `MAINTAINERS.md`'s five steps |
| the runner move (28.3.8) | after 2026-11-19 | ask any session to move the pinned runner images and land it |
| AWS measured runs: ECR mirror and CodeBuild (F1.10) | now | run once in an AWS account and record the numbers; the steps are in `AIR-GAPPED.md` and `docs/examples/` |
| free disk on the build Mac | now | 30 GB free on 2026-09-29; R9.1 prunes Docker's build cache itself below 20 GB |
| a `scan_cancel` in the first milliseconds cancels nothing | backlog (R6) | sent before the scan's job exists, the cancel finds no job and the scan then runs to the end. Rare; a fix would queue the cancel for the job about to start |
| revisit a decision in §5 | any time | `/grill-with-docs` |
