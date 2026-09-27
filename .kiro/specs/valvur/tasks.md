# valvur: tasks

**Written 2026-09-27** from [the first-principles review](../../../docs/REVIEW-2026-09-27.md),
which the owner accepted the same day. This file is authoritative for what is open.

**Phases 0 to 30 are archived** in
[`docs/history/tasks-phases-0-30.md`](../../../docs/history/tasks-phases-0-30.md), unchanged.
Their task IDs stay valid references in commits, ADRs and the CHANGELOG, so numbering here
starts at Phase 31 and no ID is reused. Requirement IDs (F1.1, N1.1, P1 …) are never
renumbered; a task that changes a requirement amends it in `requirements.md`.

---

## How every task is built

1. **Measure first.** Each task names the evidence that it is needed. Where the evidence is
   a measurement, take it again before writing code, and record the after-measurement when
   closing the task.
2. **Test-driven, in vertical slices** (the `tdd` skill). Write one test for one behaviour,
   watch it fail, write the least code that passes, repeat. Never write all the tests first.
   Never refactor while a test is red.
   - Tests exercise public interfaces: `api.scan`, the MCP server over stdio, the CLI,
     `python -m valvur.engine`, and the acceptance harness.
   - Fakes live at two boundaries only: the container runtime and the network. Everything
     else runs for real, `git` included.
   - Assert on fields, kinds and counts. Assert on a sentence only where the sentence is the
     contract, such as a refusal the user reads.
3. **Commits.** Each red-to-green slice may be committed on the phase branch. **Every phase
   ends with a phase commit** that closes its tasks with `**STATUS <date>:** ✅` notes,
   updates `CHANGELOG.md`, and records the phase exit as measured. The phase lands on `main`
   by one PR, fast-forwarded once the required checks pass.
4. **The acceptance set judges.** From Phase 33 on, a phase's exit is measured with
   `scripts/acceptance.py` (Phase 32) on a Mac through Docker Desktop and on Linux.
5. **Local runs** use `VALVUR_CACHE=<scratch>/gen-cache VALVUR_IMAGE=valvur:dev`, never the
   owner's cache or pulled images.

## Order, and why

```
31 safety release 0.6.0 ──► 32 acceptance set ──► 33 one container, the git view
                                                        │
                           34 Scanner set ◄─────────────┘
                                 │
                           35 the report ──► 36 the agent surface ──► 37 documents, gate, 1.0.0
```

- **31 first** because `0.5.0` users have two silent misses and a cancel that does not stop.
  It touches the current engine as little as possible.
- **32 before any engine work**, so the rebuild is measured against a baseline, not memory.
- **33 is the critical path.** It removes the three root causes the review names for the
  engine, and every later phase builds on its plan and progress stream.
- **34 before 35 and 36**, so the report and the reply are designed on the final Scanner set.
  Its measurement spike, 34.1, needs nothing from 33 and may run alongside it.
- **35 before 36**, because the reply carries the report's groups.
- **May run in parallel in a second worktree:** 34.1 (spike), 35.3 (agent-config rule),
  36.1 (the client measurement).

## Carried from Phases 0 to 30

| old | where it went |
|---|---|
| 30.0.1 cancel stops the queue | 31.1 (minimal), 33.5 (structural) |
| 30.0.2 missing workspace refused | 31.2, 36.4 |
| 30.0.3 input errors at the call | 31.5, 36.4 |
| 30.1.1 a flood is one Finding | 35.1 |
| 30.1.2 `doctor` names an older server | 36.7 |
| 30.1.3 the folder ignores itself | 36.7 |
| 30.1.4 the small things | 33.4 (stderr excerpt), 35.2 (titles), 36.2 and 36.5 (fields, clamp) |
| C10, the owner's newer report: git history never scanned | 31.6, 34.6 |
| 12b.3 `v1.0.0` | 37.5 |
| 28.1.3 a second maintainer | 37.6, owner |
| 28.3.8 the runner move, after 2026-11-19 | 37.7, dated |

---

## Phase 31: safety release `0.6.0`

The current engine, patched where users can be misled today. `0.6.0` rather than `0.5.1`:
`main` already carries additive MCP schema changes (29.0.5, 29.2.4), and this project's
precedent makes that a minor.

- [ ] **31.1** **A cancel stops the queue** (F1.11; C1). Evidence: at width 2, Scanners
  launched after `scan_cancel` and `CANCELLED` was reported with a container up.
  - Tests first: a fake runtime with `jobs=1` and a cancel during the first Scanner; the
    second is never launched. `CANCELLED` is reported only once the runtime lists none of
    the scan's containers. e2e: cancel at width 2, then `docker ps` shows no `valvur-`
    container at the moment the state reads `CANCELLED`.
  - Build: cancel queued futures on kill; check the flag before each launch; wait for the
    runner's containers to be gone before settling.
- [ ] **31.2** **A workspace must exist** (F9.1, N2.2; C2, N5). Evidence: a relative path
  created `relative/path/.security-scan/` in the project and reported on it.
  - Tests first, through the MCP handlers and the CLI: a relative path resolves against
    `CLAUDE_PROJECT_DIR` when set and is refused otherwise; a missing path or a file is
    refused synchronously with `isError`; no refusal creates a directory. `list_findings`
    and `explain_finding` refuse the same way.
- [ ] **31.3** **An exclude means the same to every Scanner** (F2.1; N1). Evidence:
  `exclude = ["archive"]` hid `src/archive/` from Opengrep; Checkov and OSV-Scanner use the
  same unanchored form.
  - Measure first, in the image, each tool's root-anchored form.
  - Tests first (e2e, planted tree): flows in `archive/`, `src/archive/` and `src/app/`
    with `archive` excluded. Every Scanner reports `src/archive/` and `src/app/`.
  - Build: use the anchored form where it exists. Where a tool has none, pass it no exclude
    and filter its findings afterwards.
- [ ] **31.4** **Built-in skips are named** (F7.7; N2). Evidence: `mypkg/build/steps.py`
  was read by no Scanner and the report did not say so.
  - Tests first: a tree with `mypkg/build/` names that directory and its file count in
    `run.json`, `SUMMARY.md`, the CLI output and the `scan_status` reply.
- [ ] **31.5** **Input errors fail at the call, and `doctor` is suggested only when it can
  help** (F9.10; C3, C4). Evidence: `budget_s: -5` started a job and failed it; the field
  `doctor_may_help` was true on every state.
  - Tests first: every bad argument is refused synchronously in one plain sentence with no
    exception class name. `doctor_may_help` is true only for a precondition failure
    (runtime, image, database, index, SELinux, TLS). A Busy refusal carries `next` and does
    not mention `doctor`.
- [ ] **31.6** **The README says what the secrets step reads** (P2; C10). Evidence:
  Gitleaks runs in `dir` mode and the image has no `git`; `README.md` says *including git
  history*. Test: the README's Gitleaks row matches the adapter's mode. Phase 34.6 restores
  the claim with a real history scan.
- [ ] **31.7** **Release `0.6.0`**. Owner steps are marked.
  - Cancel rehearsal run 36317791899, held at the brake since 2026-09-27.
  - Version `0.6.0`. The CHANGELOG's `[1.0.0]` entry becomes `[0.6.0]` without the
    stability claim. The README's status line and `SECURITY.md` follow `test_version.py`.
  - A rehearsal on the exact tree. *Owner:* the signed tag and the approval at the brake.
  - Verify as a user: `pip index versions valvur`, the cosign and attestation commands.

**Phase exit:** `0.6.0` promoted. The four regression tests from 31.1 to 31.4 pass on Linux
CI and on the Mac.

---

## Phase 32: the acceptance set

The judge for every later phase, and a baseline of today's engine.

- [ ] **32.1** **Six acceptance repositories, generated** (P1, N1.1, F5.6). A script builds
  each from nothing, so the set is reproducible and small in git:
  1. *gate-shaped*: 300 source files, a gitignored 100,000-file data directory, a `.venv`;
  2. *lockfiles*: `tests/fixtures/broken-repo`, with known CVEs;
  3. *history secret*: a credential committed and removed in the next commit;
  4. *nested names*: planted issues in `archive/`, `src/archive/`, `mypkg/build/`;
  5. *infrastructure*: `terraform-aws-vpc` at a pinned commit;
  6. *self*: this repository at a pinned commit.

  Each carries `expected.toml`: the rules and paths that must be found, and those that must
  not. Test: the generator is deterministic; two runs produce byte-identical trees.
- [ ] **32.2** **The harness** (`scripts/acceptance.py`). Runs a CLI scan per repository
  and reports, as JSON and a table: expected findings present, unexpected findings, status,
  wall time, containers alive afterwards, and the platform. Tests first: against a fake
  results folder, a missing expected finding fails and an extra one is listed.
- [ ] **32.3** **Lifecycle probes**: cancel mid-scan, a budget cut, `kill -9` of the MCP
  server mid-scan, stdin closed mid-scan. Each probe asserts that no container remains and
  that the next scan starts.
- [ ] **32.4** **Agent scoring**, opt-in because it needs a login and costs money. One
  `claude -p` sentence per repository with the project's `.mcp.json`. Records turns, cost,
  seconds, whether the final answer names every expected finding, and containers left.
- [ ] **32.5** **A Mac in the loop.** `acceptance.yml`: Linux nightly on GitHub's runners;
  macOS on a self-hosted runner with the label `docker-desktop` when one is registered
  (*owner*). Until then, a documented local command the owner runs before each phase exit.
- [ ] **32.6** **The baseline.** The current engine, `0.6.0`, through 32.2 to 32.4 on both
  platforms, recorded in `docs/acceptance/baseline-<date>.md`. Known misses are marked
  expected to fail with the task that fixes them (repository 3 until 34.6).

**Phase exit:** the baseline recorded on both platforms. The harness fails on repository 3
and passes wherever the current engine is right.

---

## Phase 33: one scan, one container, fed the files git would publish

The engine rebuilt around the review's E1, E2 and E6. The old path serves until 33.8 deletes
it, behind `VALVUR_ENGINE=2` until then.

- [ ] **33.1** **The decisions, written** (F1.1, F1.6, F2.6, F2.7, F1.9). Owner agreement:
  2026-09-27.
  - ADR-0021 *The File Set is the git view*: tracked plus untracked-not-ignored files; local
    agent configuration always included; `[scan] exclude` is root-relative prefixes;
    `scope = "tree"` walks instead, for a directory that is not a repository.
  - ADR-0022 *One Scan Container per Profile boundary*: an in-image engine runs the
    Scanners; the source arrives as a Snapshot, never a mount; protocol 2; amends
    ADR-0001's implementation, keeps its principle.
  - `CONTEXT.md` gains **File Set**, **Snapshot** and **Scan Container**, with _Avoid_
    lists. F1.1 and F1.6 are amended for the Snapshot.
- [ ] **33.2** **Tracer bullet.** `valvur scan` of a two-file git repository with
  `VALVUR_ENGINE=2` runs one container in which Gitleaks reads a Snapshot and the planted
  secret is reported in `findings.json`.
  - Tests first: one e2e test through the real runtime. One unit test through
    `LocalRuntime`, a runtime adapter that runs `python -m valvur.engine` as a host
    subprocess with fake tools, so the engine's behaviour is tested without a container.
- [ ] **33.3** **The File Set** (F1.1, F7.7). Tests first, on real temporary git
  repositories:
  - the git view lists tracked and untracked-not-ignored files, and never `.git/`;
  - ignored `.mcp.json`, `.claude/` and `.kiro/settings/` are included;
  - `exclude = ["archive"]` removes `archive/` and keeps `src/archive/`;
  - a symlink leaving the repository is listed as a link and never followed; a submodule is
    named and not entered; an LFS pointer is scanned as the pointer file;
  - past a file-count ceiling the scan refuses before any container starts, naming the
    largest directories and the exclude line;
  - the manifest records count, bytes and the list's sha256;
  - measured: repository 1 lists in under half a second.
- [ ] **33.4** **The engine runs every `offline` Scanner** (F2.1, F2.4, F2.5, F2.6, F2.7).
  Adapters return a plan entry (argv, report path, timeout) instead of running anything;
  parsing is unchanged. Tests first, through `LocalRuntime` with fake tools:
  - the tools run in parallel, each in its own process group;
  - one that sleeps past its timeout is killed with its whole group and recorded as timed
    out, with a stderr excerpt cut at a word boundary;
  - one that crashes or writes an unreadable report fails alone, and the others' results
    stand;
  - progress arrives as JSON lines, one when each tool starts and ends;
  - argv snapshots are re-taken.
- [ ] **33.5** **One deadline and one kill** (F1.11, F2.7; the budget of 23.3.7). Tests
  first:
  - at the budget the engine stops what runs and writes a partial manifest naming each cut;
  - if the engine does not return within a grace period, the host kills the container;
  - `scan_cancel` sends one kill and waits for the runtime to confirm the container is gone
    before `CANCELLED`;
  - e2e: zero containers after each of these, measured with `docker ps`.
- [ ] **33.6** **Nothing outlives its owner** (F1.11, F1.12).
  - Every container carries the labels `valvur.generation` and `valvur.pid`.
  - At each scan start and in `doctor`, containers whose owning process is dead are
    removed.
  - The MCP server exits on stdin EOF, and on parent death by polling `getppid()`; shutdown
    kills by label and is bounded at three seconds.
  - The workspace lock records its holder's PID, and *Busy* says whether that holder is
    alive.
  - Tests first: e2e `kill -9` of the server mid-scan, then the next scan reaps the orphan
    and runs; a unit test of the parent-death watch with a real child process.
- [ ] **33.7** **`full` adds one networked container** (N2.1, ADR-0010, ADR-0016).
  OSV-Scanner and dependency-reality's registry questions run in a second container with a
  network; `egress.py` remains the only authority. Tests first: the exfiltration constraint
  tests, restated for two containers, pass. `offline` still starts exactly one container
  with no network.
- [ ] **33.8** **Switch over and delete.** The new engine is the only engine.
  - Deleted: the thread-pool fleet, both name registries, `skip_args`, `VENDORED`, the
    generated Gitleaks config (the project's own `.gitleaks.toml` is still honoured),
    `verify_workspace_readable`, width-from-memory, `honour_gitignore`.
  - `PROTOCOL.md` 2 and `org.valvur.protocol="2"`; a major-1 image is refused with the fix
    named.
  - Tests first: the constraint suite restated for the new invariants: one container per
    `offline` scan; the workspace never mounted; zero containers after any stop.

**Phase exit**, on the acceptance set, Mac and Linux:
- every expected finding except repository 3's;
- repository 1 complete warm in under 30 s on the Mac with no configuration;
- one container per `offline` scan, and zero after every lifecycle probe;
- the net line change of `api.py` and `runner.py` recorded.

---

## Phase 34: the Scanner set, decided by measurement

- [ ] **34.1** **The spike** (F2.1, N1.1; reopens ADR-0019 on its own condition). Run
  Trivy's misconfiguration scanner and zizmor against Checkov, and Trivy's CycloneDX output
  against Syft's, on the thirteen corpus repositories and the acceptance set.
  - Record a findings parity table and times.
  - Decide each replacement in ADR-0023. zizmor's licence, offline mode and pinning are
    checked before anything enters the image.
- [ ] **34.2** **zizmor for GitHub Actions**, if 34.1 says so (F3.11). Pinned by hash in
  the image, credited in `NOTICE`, run offline. Tests first: planted workflows with an
  unpinned action, top-level write permissions and template injection each produce one
  ranked Finding.
- [ ] **34.3** **Trivy for infrastructure; Checkov removed**, if 34.1 says so (F2.1,
  F2.2). Removes the Checkov venv, its lock and overrides, its Dependabot entry and its
  adapter. Tests first: `terraform-aws-vpc`'s expected findings under the new rules. The
  image size is recorded before and after.
- [ ] **34.4** **The SBOM from Trivy's pass; Syft removed**, if 34.1 says so (P3, F10.3).
  Tests first: `sbom.cdx.json` validates as CycloneDX, and its component count on the corpus
  is within the parity recorded in 34.1.
- [ ] **34.5** **The action-pin rule moves to zizmor**, if parity holds (F3.11). Opengrep
  keeps the sink inventory and the taint rules. Tests first: the pin findings on the corpus
  are unchanged in count and path.
- [ ] **34.6** **Secrets in history** (F2.1, P2; C10). The host writes `git log -p --all`,
  with commit markers and bounded by commit count and size, into the Snapshot. Gitleaks scans
  it, and the adapter maps each hit to its commit and path. On by default in a repository,
  with `[scan] history = false` to turn it off. Tests first: repository 3's credential is
  reported with its commit; the bound is reported when hit. The README's claim is restored.

**Phase exit:**
- the parity table accepted by the owner;
- the fastest application-repository scan on Linux halves against the Phase 32 baseline;
- repository 3 correct;
- `NOTICE`, the licence checks and the reproducible-image check green.

---

## Phase 35: the report

- [ ] **35.1** **Groups** (F5.8, F7.5, F7.14; 30.1.1). Findings group by rule and
  directory: one entry with a count and its locations. A flood, meaning one rule over many
  files in one directory, ranks below distinct findings and says it may be machine-written
  data. `findings.json` keeps every Finding with its group id. Tests first: 3,890
  `generic-api-key` hits under one directory are one group ranked below eight distinct
  findings.
- [ ] **35.2** **`SUMMARY.md` leads with what matters** (F7.4 to F7.7, N1.3). The verdict,
  the scope manifest, what did not run, then the top groups. The agent block is shortened and
  moved to the end, because the MCP handshake carries it. No title is cut mid-word. Tests
  first: the golden files are re-taken; a sentence-boundary test covers every truncation
  site.
- [ ] **35.3** **Local agent configuration that would leak** (F3.6). An AI Artifact Check
  rule: `.mcp.json`, `.claude/settings.local.json`, `.kiro/settings/mcp.json` and their peers
  that git does not ignore and that hold absolute local paths or credential-shaped values.
  Ranked medium. Tests first: planted files, ignored and not ignored.
- [ ] **35.4** **`REMEDIATION.md` per group** (F7.14). One action per group, never *rotate
  3,890 credentials*. Tests first: the gate's flood yields one action that names the count
  and the exclude line.

**Phase exit:** on the acceptance set, `SUMMARY.md` for repository 1 fits one screen. An
occams-shaped fixture reports the local-config exposure the owner's 2026-09-27 audit found.

---

## Phase 36: the agent surface

- [ ] **36.1** **Measure the client before relying on it** (F9.1). In Claude Code, a stdio
  tool call that runs 150 s and sends progress: is it backgrounded at two minutes, and does
  its result reach the model? In Kiro, the same call. Recorded in ADR-0024, *`scan` returns
  the result*.
- [ ] **36.2** **Reply schema 2** (F9.1, F9.8 to F9.10). `structuredContent` is the primary
  form, because it is what Claude Code's model reads. It holds state, verdict, reason,
  complete, scope, counts, groups, what did not run, `next`, `error.kind`, and a `report`
  field with the Markdown summary. Tests first: the snapshot is re-taken; the largest
  acceptance repository's reply is under 25,000 tokens; every state's fields agree with its
  text.
- [ ] **36.3** **`scan` blocks and returns** (F9.1). It sends progress notifications and
  returns the result within its budget. A second call on a workspace with a running scan
  attaches and returns the same result. `scan_status` remains as an alias that attaches.
  Tests first, over stdio: one call yields the result; a disconnect then a second call yields
  the same generation.
- [ ] **36.4** **Inputs from the client's roots** (F9.1, N2.2; 30.0.2, 30.0.3). The
  workspace defaults to `CLAUDE_PROJECT_DIR` or the first root from `roots/list`, and must
  exist, be a directory and lie inside the roots. Every schema has
  `additionalProperties: false`. Tests first: each violation fails synchronously with a kind
  and one sentence.
- [ ] **36.5** **One `findings` tool** (F9.1, F9.8, F9.10). It replaces `list_findings` and
  `explain_finding`, filtered by fingerprint, group, rule or path, and says when it clamped
  a limit. The CLI keeps parity (F9.3). Tests first: every filter; the clamp stated.
- [ ] **36.6** **Fresh data without a terminal** (F10.8; amends task 14.2, owner-agreed
  2026-09-27). ADR-0025. A scan refreshes a stale database and index as it fetches absent
  ones: announced, and recorded in `network.fetched`. `[scan] fetch = "never"` is for
  air-gapped users. A new `update` MCP tool. Tests first: an eight-day-old database is
  refreshed and recorded; with `never` the result is `inconclusive` with the reason.
- [ ] **36.7** **`doctor` and the reply tell the truth about the session** (30.1.2,
  30.1.3). `doctor` says when the running server is older than the configuration names. The
  reply and the handshake say the Results Folder ignores itself. Tests first: each sentence
  appears when its condition holds and never otherwise.

**Phase exit:**
- agent scoring on the acceptance set: a correct report in six turns or fewer on every
  repository in Claude Code;
- one manual pass in Kiro;
- every bad input fails synchronously.

---

## Phase 37: documents, the gate, `1.0.0`

- [ ] **37.1** **README rewritten against the new engine** (P6). Every number measured on
  the acceptance set, and the tool table matches the Scanner set.
- [ ] **37.2** **`EVALUATING.md`, `design.md`, `PROTOCOL.md` and `requirements.md` as
  built.** Amendments only; no ID renumbered.
- [ ] **37.3** **`CLAUDE.md` refreshed** within its 200-line budget, and this file's closed
  phases moved to `docs/history/`.
- [ ] **37.4** **The gate with a person** (10.1, 12b.3's person half). Someone outside the
  repository, the README, one project of their own. Recorded in `docs/gates/`.
- [ ] **37.5** **`v1.0.0`** (12b.3). The CHANGELOG states the stability claim. A rehearsal,
  then *owner:* tag and approval. Verified as a user.
- [ ] **37.6** **A second maintainer** (28.1.3). *Owner.*
- [ ] **37.7** **The runner move** (28.3.8). Dated: after 2026-11-19.

**Phase exit:** `1.0.0` promoted after a person completed the gate unaided.
