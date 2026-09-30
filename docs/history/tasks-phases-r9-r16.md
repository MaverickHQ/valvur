# valvur: Phases R9 to R16, closed

Moved from [`tasks.md`](../../.kiro/specs/valvur/tasks.md) on 2026-09-30 by R16.4, as the
build closed each phase: R9 to R15 here, and R16 when it closes. Each task keeps its
STATUS and each phase its exit as measured; each phase's record is in
[`docs/acceptance/`](../acceptance/). The decisions D21 to D40 they ran on stay in
`tasks.md` §5 while R16 runs. [Phases R7 and R8](tasks-phases-r7-r8.md) and
[Phases R0 to R6](tasks-phases-r0-r6.md) are archived beside this file.

### Phase R9: the Score, measured before anything changes

- [x] **R9.1** **Pre-flight, and resuming armed.** Steps, each recorded in the STATUS:
  1. `scripts/build_status.py` names R9 and its branch from `main`;
  2. Docker answers (§2 step 4), at least 20 GB is free (else `docker builder prune -f`),
     `gh auth status` and `claude --version` answer;
  3. `valvur:dev` is built from `main` and `valvur doctor` passes with the build cache;
  4. both schedules of §2 are armed with its prompt.
  Behaviour: a test holds this file to the shapes `build_status.py` reads, a phase
  heading per phase and an open task under the first.
  **STATUS 2026-09-29:** ✅ all four.
  1. `build_status.py` on `main` at `99bb4e6`: R9.1, `build/r9-the-score-measured-before-anything-changes`.
  2. Docker was quit; `open -a Docker` answered in 20 s: 29.2.1, a 3.8 GiB VM, 8 CPUs. 29 GB
     free, so nothing pruned. `gh` is signed in as MaverickHQ (`repo`, `workflow`,
     `write:packages`); `claude` is 2.1.284.
  3. `valvur:dev` built from `main` in 1 min 49 s, 665.5 MB; `doctor` with the build cache:
     *ready*, database 1.5 days old, index 2.4, KEV 1.9.
  4. The hourly `CronCreate` job `17 * * * *` and the desktop task `valvur-build-resume`,
     `43 */3 * * *`.

  `tests/test_task_list_shape.py`: `shape_errors` in `build_status.py` reports a task under
  another phase's heading and a gap in a phase's numbering, and the live file has neither.
  Renumbering R9.2 to R9.9 fails the test.
- [x] **R9.2** **The decisions written.** ADR-0026 (D21, D22), ADR-0027 (D23 to D26),
  ADR-0028 (D27, D28), ADR-0029 (D29), ADR-0030 (D32) and ADR-0031 (D39 to D41), each
  citing the requirement IDs it adds to `requirements.md`: N4.1 to N4.4; F6.12, F6.13,
  F10.9, F3.14; F3.15, F3.16, F9.11; F2.9, F5.10; N1.5; F9.12, F9.13. `design.md` 1.4 names
  the modules to come. Behaviour:
  `check_traceability.py`: 0 uncited, 0 orphan ADRs.
  **STATUS 2026-09-29:** ✅ `check_traceability.py`: 0 uncited, 0 orphan ADRs, 153 IDs, 31
  ADRs. Adding the IDs first turned it red on N4.1 to N4.4 and the rest; the ADRs turned it
  green. Each ADR carries the decisions it records, what it amends and what it rejected:
  - ADR-0026, the Score;
  - ADR-0027, data ages and freshness, amending ADR-0025, ADR-0007 and ADR-0018;
  - ADR-0028, private registries and `check_package`;
  - ADR-0029, rules by licence and measurement, amending ADR-0004;
  - ADR-0030, reuse;
  - ADR-0031, the skill, which records the harness, the history and Laya as dropped by the
    owner.

  Each new ID says *added by R9.2, to be met by* its task. F6.3 is amended to point at
  F6.13. `design.md` 1.4 §11 maps each module to its phase and ADR.
- [x] **R9.3** **The harness** (D21; N4.1, N4.2). `scripts/eval.py`, the package
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
  **STATUS 2026-09-29:** ✅ all seven.
  - **The harness.** `scripts/eval.py`, with `scripts/eval/score.py` (the formula and case
    matching) and `twins.py` (the six generated tracks). 32 tests in four files.
  - **Case matching.** A case is matched by rule, rule prefix, advisory (rule or CVE),
    CWE, or Scanner.
  - **Premises re-checked.** A package-reality case whose premise the index no longer
    holds is named, not scored.
  - **First measurement**, on `valvur:dev` from `main` (`99bb4e6`), the six generated
    tracks in 47.8 s:

    | track | score |
    |---|---|
    | SAST-JS | 0.0 |
    | secrets | 90.0 |
    | dependencies | 100.0 |
    | package reality | 81.0 |
    | agent configuration | 94.3 |
    | infrastructure | 95.0 |

  - **Every miss is valvur's or a Scanner's, not a case's:**
    - no JavaScript rule at all;
    - Gitleaks misses a private key in history and flags a placeholder PEM: one match
      running from the placeholder into the real key, both in one history file (the
      cause as R10.9 found it; this note first blamed the diff's `+`);
    - private registries are read as hallucinated for pip, npm and Composer (R10);
    - the two npm malicious names are still registered, as security holders (R11);
    - a paraphrased injection and an exfiltration directive pass the patterns;
    - Checkov does not flag `public-read` on `aws_s3_bucket_acl`.
  - **Two generator defects, found by that run, each fixed under a test:**
    - the template-injection workflow was invalid YAML, so its twin passed for free;
    - the ranking fixture was merged away, because a dependency finding's identity has
      no path (ADR-0003). The same vulnerable package and version in two lockfiles is
      one finding, reported at one of them. Noted for the owner (§8).
  - **Gates, recorded:**
    - honesty would fail: four safe twins draw a high (the placeholder PEM, three private
      registries);
    - freshness would fail: the index is 2.41 days old;
    - ranking passes: Log4Shell ranks first;
    - a test-scoped Maven dependency reads scope `unknown`, not development-only.
- [x] **R9.4** **The OWASP Benchmark for Python** (D21, track 1). Behaviours:
  1. `tests/eval/sources.toml` pins it by commit; a checkout at any other commit is
     refused; nothing of it is tracked in this repository (a test asserts it);
  2. `expectedresults-0.1.csv` becomes 1,230 cases, 452 vulnerable, 14 categories;
  3. a finding maps to a test case by file and to a category by CWE, from the finding's
     `cwe` when present, else from its rule's metadata under `rules/`;
  4. the track's score is the OWASP scorecard's.
  **STATUS 2026-09-29:** ✅ all four.
  - **The pin.** `tests/eval/sources.toml` pins `f1291485808b`. `owasp.checkout` clones it
    into the build cache and refuses any other commit; no file of it is tracked here.
  - **The count.** The pinned file has 452 real cases, not the 530 the list first said.
  - **CWEs.** `cwe.py` reads a finding's CWE from the finding, else its rule, else its
    Scanner. Every rule under `rules/` now declares one.
  - **Measured on `valvur:dev`: 0.4 in 18.5 s.** Only three categories score:
    - weak hash: 37 of 71 caught, no false positive;
    - code injection: 20 of 20 caught and all 33 safe cases flagged, since the INFO
      sink inventory names every `eval`, so it nets zero;
    - command injection: 7 of 13 caught, and 7 of 7 safe cases flagged.
  - **SAST-JS, through the same lookup: 10.0**, from Gitleaks finding the two hard-coded
    credentials. R13's starting point.
- [x] **R9.5** **Real-code precision** (D21, track 8). Behaviours:
  1. every active finding of a valvur-owned rule or of Gitleaks on the corpus needs a label
     in `tests/eval/labels/corpus.toml` by fingerprint; an unlabelled one fails the track,
     named;
  2. the rubric, in ADR-0026: `tp` when a maintainer would act on it (change code, rotate,
     pin), `fp` otherwise, the reason saying why; the labels are the executor's, committed
     for review;
  3. the track is precision × 100; third-party Scanners' other findings are counted and
     reported, not labelled.
  **STATUS 2026-09-29:** ✅ all three.
  - **The labels.** `tests/eval/labels/corpus.toml`: 24 findings on the thirteen
    projects at their pins, each read against the code at the finding. Every one is
    `fp`:
    - flask's documented example keys and its own `exec` of config files;
    - HMAC-SHA1 and MD5 content keys;
    - requests' test TLS keys, and an RFC 6455 handshake nonce in fastify;
    - tokens given to mocks in monolog;
    - smolagents' tests executing their own code;
    - one of valvur's own: ripgrep's `COPYING` states the dual licence its `Cargo.toml`
      declares, and the licence-file Check read it as MIT alone.
  - **Coverage notes** are valvur's limits, counted and not judged.
  - **The measurement forced one amendment** to D21 and ADR-0026: smoothed precision. With
    no true positive to find, plain precision was 0 for one false alarm and for forty,
    and 0/0 for a silent corpus. The track reads **4.0** (0 tp, 24 fp) in 130 s. Other
    Scanners' findings, counted: zizmor 128, Checkov 46, Trivy 14, OSV-Scanner 4.
  - **Two defects valvur owns**, added to R10 as R10.7 and R10.8.
- [x] **R9.6** **The baseline** (D21, D22; N4.3, N4.4). Behaviours and steps:
  1. `.github/workflows/eval.yml`, weekly and on dispatch, builds the image and runs the
     Score on GitHub's Linux runner, uploading the result; a test holds its arguments to
     the script's;
  2. the Score measured on both lanes on `valvur:dev` built from R9's branch;
     `tests/eval/baseline.json` from the Linux lane, the Mac's beside it, the duration of
     each track recorded;
  3. the release's `verify` job runs `--compare` on the tracks that together fit in 10
     minutes, by 2.'s durations; the rest run weekly; `docs/RELEASING.md` says which;
  4. `docs/EVALUATING.md` gains the Score: each track, how to replicate it, the baseline.
  **STATUS 2026-09-29:** ✅ all four.
  1. **`eval.yml`**: weekly, on dispatch, and on a PR that changes the harness. A test
     holds its arguments to the script's. It joins the scheduled workflows whose
     failure opens an issue.
  2. **Both lanes, on the image built from this branch: Score 59.3, the same track for
     track.** Linux is eval run 36620261451, 268 s; the Mac 192 s, under 9.5 GB of host
     swap.
     - `tests/eval/baseline.json` is the Linux lane, with the Mac's beside it.
     - The Linux run held ten safe cases fewer in agent configuration: it built that
       track before anything had fetched awesome-cursorrules. The score agreed only
       because none was flagged. Fixed: the track fetches what it reads.
     - Per track: sast-python 26 s, sast-js 4, secrets 4, dependencies 31, package
       reality 4, agent configuration 4, infrastructure 7, real-code precision 188
       (thirteen clones and scans).
  3. **Every track runs in `verify`**, since the whole Score takes under five minutes;
     `RELEASING.md` says so.
  4. **`EVALUATING.md` §9** holds the Score, how to replicate it and the baseline.

  **D22's targets under the baseline rise to it:** dependencies 100, agent configuration
  94.3, infrastructure 95. The rest stand.

**Exit:** the baseline recorded on both lanes, the harness's tests green, and each track's
duration recorded, the release's share by R9.6's rule.

**Exit STATUS 2026-09-29** (`docs/acceptance/r9.md`):
- **The baseline, both lanes:** ✅ Score 59.3 on Linux and on the Mac, track for track.
  Linux is `eval.yml` run 36620261451 and the baseline; the offline gate is judged and
  holds.
- **The harness's tests:** ✅ 60 tests in nine files. The unit suite passes: 1564 tests
  before the last documents.
- **Durations:** ✅ recorded per track. All run in `verify`: under five minutes in all.
- **The acceptance set:** ✅ on both lanes. Linux is run 36620273548; on the Mac, every
  repository and probe passes once the stale set is regenerated.

### Phase R10: trust fixes, and the false positives users see first

- [x] **R10.1** **A failed Scanner with nothing found reads `inconclusive`** (D30; F7.19).
  Behaviours:
  1. `api.scan` through `LocalRuntime`, one Scanner exiting non-zero, nothing found:
     `inconclusive`, `status_reason` naming the Scanner;
  2. `SUMMARY.md`, `run.json`, the MCP reply and `gate` agree;
  3. with a finding, `findings` and *incomplete*, unchanged.
  **STATUS 2026-09-29:** ✅ all three.
  - **The change.** `ScanRun.doubts` names each Scanner that failed, timed out or was cut,
    so a nil result beside one reads `inconclusive`. Every surface reads that one
    verdict: `run.json`, `SUMMARY.md`, the MCP reply and `gate --no-inconclusive` agree,
    each naming the Scanner.
  - **Goldens.** Four `SUMMARY.md` goldens pinned such a run as `clean`; regenerated,
    their one changed line is the status.
  - **Documents.** F7.19 is added; `CLAUDE.md` §7 and `EVALUATING.md` §4 name the cause.
- [x] **R10.2** **Checkov without its secrets framework** (D31). Behaviours:
  1. Checkov's invocation carries `--skip-framework secrets`;
  2. e2e: R5's planted flood beside Terraform yields the secrets group once.
  **STATUS 2026-09-29:** ✅ both.
  - **The change.** Checkov runs with `--skip-framework github_actions secrets`; the
    pinned invocation fixture moves with it.
  - **The e2e test.** It plants a key in Terraform: the old argv reports it twice,
    Gitleaks and `CKV_SECRET`, and the new one once.
  - **A test that proved nothing, fixed.** The first version planted the key in a `.env`
    beside the Terraform, and passed against the old argv too: Checkov's secrets
    framework does not read `.env` files.
- [x] **R10.3** **Private npm registries** (D27; F3.15). Behaviours, one test each: a scope
  bound in `.npmrc`; a scope bound in `.yarnrc.yml`; a whole-registry `registry=`; no
  configuration, whose message names the index's build date.
  **STATUS 2026-09-29:** ✅ all four.
  - **`ecosystems/registries.py`** reads `.npmrc` and `.yarnrc.yml` from the manifest's
    directory up to the workspace root, nearest last-wins, never from a home directory.
  - **A scope bound to a private registry** is not looked up publicly. One
    `valvur.dependency.private-registry` note per registry names the scope and host.
    It is a note, not a doubt, since a scoped name bound to a private registry cannot
    be taken publicly; the test that pins the note sets now says so.
  - **A replaced registry** turns a missing name into `valvur.dependency.not-public`,
    low, advising the name be reserved.
  - **With no configuration**, a nonexistent finding names the index's build date and
    what the project should declare.
  - **The harness counts claims only:** the package-reality track counts nonexistent,
    near-miss, newly registered, malicious and confusion, so D27's low advice does not
    flag a safe case.
- [x] **R10.4** **Private Python indexes** (D27). Behaviours, one test each:
  `--extra-index-url` in a requirements file; `--index-url` alone; `pip.conf` in the tree;
  a supplemental and an explicit uv index; Poetry's `supplemental` and `explicit` sources;
  a `Pipfile` `[[source]]`.
  **STATUS 2026-09-29:** ✅ all seven.
  - **Where the configuration is read:** `registries.py` reads pip.conf (`[global]` and
    `[install]`, the manifest's directory up to the root), a requirements file's `-i`,
    `--index-url` and `--extra-index-url`, uv's `[[tool.uv.index]]` with
    `[tool.uv.sources]`, Poetry's `[[tool.poetry.source]]` with each dependency's
    `source`, and a Pipfile's `[[source]]` with each package's `index`.
  - **Merged means confusion, high:** pip's extra index, Poetry `supplemental` and
    `secondary`, and uv under `index-strategy = "unsafe-best-match"`.
  - **Replaced or searched first means not-public, low:** `--index-url`, a Poetry primary
    source, the first Pipfile source, and a plain uv index.
  - **Bound means a note:** an explicit uv or Poetry source, and a Pipfile `index =`.
  - **D27, refined by reading uv's resolver:** its default strategy searches configured
    indexes before PyPI and stops at the first match, so a plain uv index is not the
    merge D27 called it. ADR-0028 records this.
  - **A Pipfile's packages are now read for existence**, so its sources have something
    to apply to. A lone Pipfile keeps only the vulnerability gap; the coverage tests
    move their unread example to `setup.py`, and the README and `EVALUATING.md` say so.
- [x] **R10.5** **What the README and the pipeline example claim.** Behaviours:
  1. the README's quick start names Docker or Podman as a prerequisite;
  2. the platform table says what CI tests on each architecture, until D38's leg lands;
  3. the agent paragraph states R7's final record, every answer naming every expected
     finding;
  4. `docs/examples/github-actions.yml` caches the valvur cache with a pinned
     `actions/cache`, and the test that runs it still passes.
  **STATUS 2026-09-29:** ✅ all four, held by `tests/test_readme_claims.py`.
  1. The quick start says a machine needs Docker or Podman, and that `doctor` says which.
  2. The Linux row says every commit runs the e2e suite against both runtimes on
     `amd64`, and the published image on both architectures. The test reads `ci.yml`'s
     e2e job, so R16.1's arm64 leg can widen the claim.
  3. The agent paragraph states R7's final record: every answer named every expected
     finding, in 3 to 9 turns, five of eight in six or fewer.
  4. The pipeline example restores and saves `$RUNNER_TEMP/valvur-cache` with
     `actions/cache`, pinned by commit, before `valvur update`.
- [x] **R10.6** **Wall-clock tests marked** (D35). Behaviours: every test asserting on
  wall-clock time carries `timing`, registered in `pyproject.toml`; the unit suite selects
  none; CI's e2e job and the phase exits run them. §3's command and `CLAUDE.md` then read
  `-m "not e2e and not timing"`.
  **STATUS 2026-09-29:** ✅ all three.
  - **The guard.** `tests/test_timing_marked.py` reads every test's code. A test that
    reads a clock and asserts something under a number must be marked `timing` or
    `e2e`. It found thirteen, now marked, 24 cases with their parameters:
    - deadlines, budgets and timeouts;
    - the MCP server's start and shutdown latency;
    - the concurrency checks.

    Its first version also caught two timestamps compared in order, and a lower bound
    that load cannot break; it now looks only for upper bounds.
  - **The selections.** `pyproject.toml` registers the mark. `verify.sh` and CI's unit
    job run `-m "not e2e and not timing"`, 1567 tests; CI's e2e job runs `-m "e2e or
    timing"`; the release's whole suite runs everything. §3's command and `CLAUDE.md`
    say so.
  - **Measured on this Mac:** the timing run passes, 24 in 16 s.
- [x] **R10.7** **A dual licence is one licence** (added by R9.5, measured). The
  licence-file Check reported ripgrep's `COPYING`, which states *Unlicense and MIT*, as
  contradicting `Cargo.toml`'s `Unlicense OR MIT`. Behaviours: a licence file naming
  every licence of an `OR` expression matches it; a real contradiction still reports.
  **STATUS 2026-09-29:** ✅ both.
  - A declaration's alternatives are read: SPDX `OR` and Cargo's older `A/B`. A licence
    file identified as any one of them agrees with it; `Apache-2.0` against a declared
    `MIT` still reports.
  - ripgrep's corpus finding goes: one of R9.5's 24 false alarms, the only one valvur
    owned outright.
- [x] **R10.8** **A placeholder key is not a secret** (added by R9.5, measured). Gitleaks
  flags the PEM placeholder of track 3 (`...` between the markers) at critical, which the
  honesty gate refuses from R10's exit. Behaviours: a private-key block whose body is a
  placeholder is not reported; a real key block still is.
  **STATUS 2026-09-29:** ✅ both. A Gitleaks `private-key` hit is dropped, in the tree and
  in history, when the block holds fewer than 64 base64 characters between its markers,
  as `...` and `<your key here>` do. It is judged by the content, never the file's name.
  A real key block, twelve lines of 64, still reports.
- [x] **R10.9** **A key committed in history is found** (added by R9, measured). Track 3
  found every history secret but the private key. Behaviours: a private key committed
  and then deleted is reported from history; a one-line secret in history still is,
  once.
  **STATUS 2026-09-29:** ✅ both.
  - **The cause, found by reproducing it.** It was not the diff's `+`, as this task
    first said: the writer strips it. Every commit's added lines went into one file,
    so Gitleaks' key pattern, which reads 64 characters or more to the next `KEY-----`,
    ran from the placeholder block into the real key committed after it. It reported
    the placeholder, the only false alarm on track 3's safe cases, and missed the key.
  - **The fix.** History is written as one file per commit and path, under its own
    name, and `locate` maps a hit by its file.
  - **The tests.**
    - An e2e test commits a placeholder and a real key in that order and deletes the
      real one: the old writer reports the placeholder, the new one only the key.
    - Repository 3's history test and the one-line history tests still pass.
    - `test_history.py` moves to the directory's API.
- [x] **R10.10** **Private Composer repositories** (added by R10.4; D27 extended). Track
  5's privately served Composer case still reads as hallucinated at high, which the
  honesty gate refuses from R10's exit. Composer treats a `composer`-type repository as
  canonical, searched before Packagist, unless `canonical` is false. Behaviours: a
  canonical private repository makes a missing name not-public, low; a non-canonical
  one makes it confusion, high; `"packagist.org": false` replaces Packagist.
  **STATUS 2026-09-29:** ✅ all three.
  - `registries.composer` reads `composer`-type repositories in either form, list or
    keyed.
  - A canonical private repository makes a missing name `not-public`, low; one marked
    `canonical: false` makes it `confusion`, high; `"packagist.org": false` replaces
    Packagist.
  - Path, VCS and package repositories stay the parser's: their packages are never
    looked up.

**Exit:** the Score on both lanes: tracks 3, 5 and 8 at or above the baseline, and the
honesty gate green; track 5's private-registry cases scored.

**Exit STATUS 2026-09-29** (`docs/acceptance/r10.md`):
- **The Score, both lanes:** ✅ **62.0**, from 59.3, track for track.
  - Secrets rose 90 to 100, package reality 81 to 92, real-code precision 4.0 to 4.2;
    no track fell.
  - `--compare` passes; the baseline is raised from Linux run 36627939298.
- **The honesty gate:** ✅ judged from R10, and green on both lanes.
- **Track 5's private-registry cases:** ✅ scored: every privately registered case reads
  as private. The two left are R11's still-registered malicious names.
- **The acceptance set:** ✅ both lanes. Linux is run 36627938279; the Mac's set is
  regenerated.
- **The suites:** the e2e and timing run passes on Linux but for one test of this phase's,
  since fixed. The Mac's two failures under swap are recorded.

### Phase R11: fresh data

- [x] **R11.1** **KEV's age is its catalog's** (D23; F6.12). Behaviours:
  1. the bundled snapshot reads 2026-08-27's age however recently the file was written;
  2. between the cache and the bundle, the newer catalog wins, not the newer file;
  3. `run.json` records KEV's catalog date, age and source; `doctor` shows them.
  **STATUS 2026-09-29:** ✅ all three.
  - `_load_kev` takes each copy's age from its `dateReleased`, and the younger catalog
    wins. A copy with no release date is aged by its file and labelled `fetched`.
  - `valvur update` now keeps the date it fetched with the catalog.
  - `run.json`'s enrichment records `kev_catalog`; `doctor` and the cache listing name
    the copy, its catalog's day and age.
  - The bundled snapshot now reads its true 33 days, and with it KEV's 30-day staleness
    says what it was built to say. Two tests pinned the old `doctor` line; they now hold
    the new one.
- [x] **R11.2** **Every dataset's age is its data's** (D23). Behaviours: an OSV fetch
  records `Last-Modified` in a sidecar and its age is read from it; a source with no date
  reads *fetched* on every surface.
  **STATUS 2026-09-29:** ✅ both. `osv_offline.fetch` keeps each export's
  `Last-Modified` in `osv/ages.json`, outside OSV-Scanner's own layout. `age(name)`
  reads it, `published`, else the file's time, `fetched`, and `stale` judges by it: a
  fresh file of an export ten days old is stale. R11.6 carries the basis onto every
  surface.
- [x] **R11.3** **A scan refreshes past D24's thresholds** (F10.9). Behaviours, through
  `tests/fake_registry.py`:
  1. the index and KEV past two days are refreshed, announced and recorded under
     `network.fetched`;
  2. within the threshold nothing is fetched;
  3. `fetch = "never"` fetches nothing;
  4. a failed refresh keeps the old data and says so, and the verdict thresholds decide.
  **STATUS 2026-09-29:** ✅ all four.
  - **Thresholds.** A scan refreshes the index past `INDEX_REFRESH_AFTER_DAYS`, 2 (it
    was 30), and KEV past `KEV_REFRESH_AFTER_DAYS`, 2 (it was never). Both are
    announced and recorded in `network.fetched`. The inconclusive thresholds are
    unchanged.
  - **Failure.** A failed KEV refresh keeps the catalog in use and says so; it costs no
    Scanner. EPSS and the malicious list join in R11.4 and R11.5.
  - **Hygiene, found on the way.** The unit suite never isolated `cache.root()`, so a
    unit test's scan read the owner's `~/.cache/valvur`, and would have written KEV
    there. Every unit test now has a host cache of its own, holding the bundled
    catalog dated now; 1584 pass.
- [x] **R11.4** **EPSS from FIRST's daily file** (D25; F6.13). Measure the file's size and
  host first. Behaviours:
  1. `valvur update` fetches it into the cache; `epss_url` names a mirror;
  2. on `offline`, a finding's EPSS comes from the file, and the README's ranking example
     ranks the same on `offline` as on `full`;
  3. on `full`, no request reaches FIRST's API: the egress test lists only the file's host;
  4. `egress.py`, `verify-offline.py` and `verify-mirror.py` know the new hosts, the file's
     and its redirect's, and nothing else.
  **STATUS 2026-09-29:** ✅ all four. D25's fallback is not needed.
  - **Measured first.** `epss.cyentia.com/epss_scores-current.csv.gz` answers 301 to
    `epss.empiricalsecurity.com`, then 302 to the day's dated file: 2.7 MB compressed,
    380,528 lines, under D25's 20 MB. Its first line carries `score_date`, which is its
    age (D23).
  - **The file.** `valvur update`, and a scan when it is absent or past
    `EPSS_REFRESH_AFTER_DAYS` (2), fetch it into the host cache. Each fetch is
    announced and recorded, and `epss_url` names a mirror. A download that is not the
    file keeps the copy in use and says so.
  - **Every Profile.** Enrichment reads the file, and `full` no longer sends the CVEs
    it found anywhere. The API path is gone, and so are FIRST's name from
    `FULL_HOSTS` (9 hosts) and CVE identifiers from the disclosure sentence and from
    `full`'s description. `run.json` records `epss_scored` and `epss_age_days`.
  - **One scan measured.** An offline scan of a `requirements.txt` from a stale scratch
    cache ranked with real scores: CVE-2018-18074 at 0.074. `offline` had no EPSS
    before this task.
  - **The proofs.** A traced scan from a stale cache reached exactly six hosts from the
    host process, all fetches of public data. `verify-offline.py` now permits those,
    and the database's size query, and nothing else. It resolves by name and connects
    only to the addresses those names resolved to. Since R11.3 its poisoned scan had
    failed on any machine not updated within two days.
    - `verify-mirror.py` permits `epss_url`.
    - `doctor --network` probes the file's host with the first-run group.
  - **Found on the way.**
    - The CLI printed only `fetching` and `pulling` lines, so every stale refresh since
      ADR-0025 was silent on a terminal. `refreshing` now counts as a fetch starting.
    - The falsifiability constraint relied on `full`'s API call. It now relies on a
      scan due a fetch. A new constraint asserts `full`'s host process opens nothing.
- [x] **R11.5** **The malicious list, published daily** (D26; F3.14). Behaviours:
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
  **STATUS 2026-09-29:** ✅ all seven. D26's fallback is not needed.
  - **Measured first.** The repository's tarball is 46 MB and arrives in 1.8 s. OSV's
    exports for the same ecosystems are 296 MB, so the tarball is the source. It is
    read as a stream: unpacking its 238,545 files took 72 s on the Mac. A build from
    it takes 12.9 s and writes 2.2 MB compressed, under D26's 10 MB.
  - **The records.** 213,266 cover every version (a range from 0), 24,745 name
    versions, and 533 state a range from a later version. Ranges are kept as `>=A`,
    `>=A<B` or `>=A<=B` and compared by release number. Go, Maven, NuGet and VS Code
    (823 records) are passed over and counted. The build skips withdrawn records, and
    the nine package directories named `*.json`.
  - **The format.** One line per name: name, versions or `*`, and `MAL-` IDs,
    tab-separated. The tab sorts below any name character, so the index's bisection
    now keys on the text before a tab and serves both files.
  - **The Check.** It reads the list beside the index, in the mount the index
    already has, for declared and locked packages. `ecosystems/locked.py` reads the
    lockfiles once per walk: npm (package-lock, shrinkwrap, yarn, pnpm, and exact
    `package.json` pins), PyPI (requirements pins, poetry, uv, Pipfile.lock),
    Cargo.lock, composer.lock and Gemfile.lock.
    - A name on the list is reported as `valvur.dependency.malicious`, critical,
      ranked first, and is not also asked about existence.
    - OSV-Scanner's `MAL-` finding for the same package folds into it in
      `findings.merge`: one finding, both Scanners, both identifiers.
  - **Published.** `index.yml` gains a `malicious` job in the index's order:
    build, push `malicious-candidate`, sign, pull back with `pull-malicious` and
    `cmp`, and only then tag `malicious-<date>` and `malicious`, all of it on `main`
    only. `retention.yml` keeps 180 versions, six weeks of both artifacts with their
    signatures.
  - **Fetched.** `valvur update` pulls the list with the index and, until `main`
    publishes it, builds it from the tarball. A scan pulls it past two days and
    never builds it. Both are recorded, and a failure costs nothing: OSV's database
    still reports what it knows.
  - **The Score.** The dependency track's `MAL-` cases also accept the folded rule,
    since the advisory's own rule no longer stands alone.
  - **Found on the way.** `NOTICE` still said EPSS was fetched on `full`; it now
    says what R11.4 made true, and credits ossf/malicious-packages.
- [x] **R11.6** **Freshness on every surface.** Behaviours: `SUMMARY.md` gains one line of
  each dataset's data age; the MCP reply carries them as fields; the Score's freshness
  gate reads them from `run.json`.
  **STATUS 2026-09-29:** ✅ all three.
  - `staleness.data_ages` gives every dataset's age and its basis. The database, the
    index and the malicious list are `built`, KEV `released`, EPSS `scored`, and
    each OSV export the scan read `published`. A copy that does not say is
    `fetched`, and one that is not there is `absent`.
  - `run.json` holds them in one `data` block; the blocks around it are unchanged.
  - `SUMMARY.md`'s scope section says them in one `Data:` line, and the MCP reply
    carries the block as `data`.
  - The Score's freshness gate reads the block. It now also judges the malicious
    list, EPSS and OSV (its oldest export), which it listed but never read.
  - **Found on the way.** Closing R11 made the ranking gate judged. A partial run,
    such as `--tracks real-code-precision`, then failed it for a fixture it never
    scanned. The gate is now recorded but not judged when unmeasured. The first
    commit of this slice went in with that test red, because the commit was chained
    with `;`; it was amended before any push.

**Exit:** the freshness and ranking gates green on both lanes; tracks 4 and 5 at or above
the baseline.

**Exit STATUS 2026-09-30** (`docs/acceptance/r11.md`):
- **The Score, both lanes:** ✅ **63.0**, from 62.0. Package reality rose 92 to 100: the
  two still-registered npm malicious names are on the list. No track fell, and
  `--compare` passes. The baseline is raised from Linux run 36641729214, and its `mac`
  block now holds this phase's Mac run.
- **The freshness and ranking gates:** ✅ judged from R11, and green on both lanes. Every
  dataset is within D24: at most 0.54 days, and OSV's oldest export 4.1 days (limit 7).
- **Tracks 4 and 5:** ✅ 100 and 100.
- **The acceptance set:** ✅ both lanes. Linux is run 36642663426. The Mac's set was
  regenerated, and repository 8 now expects the one malicious finding.
- **The suites:** ✅ e2e 82 passed on Linux. On the Mac, 79 passed and the
  image-staleness test failed on an image one type fix behind; it passes on the rebuilt
  image.

### Phase R12: `check_package`, before the install

- [x] **R12.1** **The API** (D28; F3.16). Behaviours, one test each: `exists`,
  `nonexistent`, `near-miss` with its suggestion, `malicious` with its ID, `confusion` and
  `not-public` given the project's registry configuration, `unknown` for JVM and Go; a
  batch of 50; no socket opened (the conftest guard); under a second for 50 (`timing`).
  **STATUS 2026-09-30:** ✅ all of them.
  - `valvur.packages.check` answers from the host cache with the dependency-reality
    Check's own logic: the index, the popular-name comparison, the malicious list, and
    the project's registry configuration read from its root manifests (D27).
  - Each answer carries a verdict, one sentence of reason, and the index's build day.
    Where they apply it also carries the near name, the `MAL-` IDs, or the private
    source.
  - `near-miss` is given whether or not the name exists: a registered typosquat is
    the same risk.
  - A name the project binds to a private registry is `unknown`, and names that
    registry; valvur does not ask it.
  - **Measured:** 50 answers in 59 ms against the real index (4.4 million npm names),
    8 ms warm.
- [x] **R12.2** **The CLI, `valvur check`.** Behaviours: the exit status per D28; `--json`;
  the help fixture and the documented-commands test updated.
  **STATUS 2026-09-30:** ✅ all three.
  - `valvur check <ecosystem> NAME[@VERSION] …` prints one line per package: its
    verdict and why. It exits 0 when none is flagged, 1 when any is, and 2 on an
    error, such as more than 50 names.
  - `--json` gives the answers as the tool will.
  - `--project` names whose registry configuration applies; the default is here.
  - The top-level usage now lists nine commands, which `test_seven_commands.py` holds.
    `check`'s help is a golden beside the others, and the README's quick start shows it.
- [x] **R12.3** **The MCP tool** (F9.11). Behaviours:
  1. `check_package` is listed with its schema and annotations, read-only, not open-world;
  2. a reply of 50 packages stays bounded and carries `structuredContent`;
  3. the handshake's instructions and `SUMMARY.md`'s agent block say to call it before
     adding a dependency; `init`'s block says so too;
  4. the README and `doctor` say seven tools.
  **STATUS 2026-09-30:** ✅ all four.
  - **The tool.** `check_package` takes up to 50 `{ecosystem, name, version?}` and an
    optional `workspace`. It declares `readOnlyHint: true` and `openWorldHint: false`,
    the first tool to state the latter, and answers `structuredContent` beside
    bounded text.
  - **One computation.** `operations.check_package_reply` serves both surfaces:
    `valvur check` prints its text or, with `--json`, its fields.
  - **The rule.** "Before adding a dependency, call `check_package` … and never add one
    it flags without asking the human" is in the handshake's instructions, in
    `SUMMARY.md`'s agent block, and in `valvur init`'s output. In the agent block it
    shares a line, so the summary of repository 1 still fits one screen.
  - **Seven tools.** The README's table, `valvur-mcp --help`, design.md §8 and
    EVALUATING.md say seven. `doctor` inside the server names the tools it serves; it
    reads them from the call rather than importing the registry, which would have
    closed an import cycle through `operations`.
  - **Pins updated deliberately:** the tools-list, initialize and client-transcript
    snapshots, and the summary goldens, which differ by the agent line only.
- [x] **R12.4** **Track 5 through `check_package`.** Behaviour: the package-reality track
  scores the same cases through the tool as through a scan, both reported.
  **STATUS 2026-09-30:** ✅
  - `scripts/eval.py` asks `check_package` about each case's package, with the case's
    directory as the project, and scores the answers by the track's own formula.
  - The result is recorded as the track's `check_package` and printed under the
    scorecard. The Score's mean keeps the scan's value, so the ratchet measures
    what it always has.
  - **Measured on the Mac against the real index:** 100 through a scan, 100 through
    the tool.
  - **Found on the way.** Ruby's and Rust's private cases bind their name inside the
    manifest: a `source '…' do` block, a `registry =` key. The scan's parsers skip
    those names, but the tool called them nonexistent. `registries.for_manifest` now
    reads both bindings. A scan is unchanged, since those names were never declared.
- [x] **R12.5** **Agent scenarios** (D36; ≤ $10). Behaviour: `scripts/acceptance/agent.py`
  gains four scenarios, *add package X to this project*, for a hallucinated, a near-miss,
  a malicious and a real package, run with `--disallowedTools Bash`. One passes when the
  agent called `check_package`, and the manifest is unchanged for the first three and
  changed for the fourth. Turns and cost recorded.
  **STATUS 2026-09-30:** ✅ four of four, on the second full run.
  - **The harness.** Each scenario gets a fresh project and runs with
    `--disallowedTools Bash`. It records its tool calls through `stream-json`, and is
    bounded by `--max-budget-usd`: the lesser of $2 and what is left of D36's $10, in
    a ledger of its own (`agent-cost-r12.json`). `python scripts/acceptance/agent.py
    DIR` runs all four.
  - **The first run: three of four.** The near-miss agent called `check_package`,
    left `reqeusts` out, and added `requests` in its place without asking. The rule
    said "never add one it flags", which a replacement satisfies. It now says "never
    add one it flags, or a replacement for it, without asking the human", in the
    handshake, `SUMMARY.md`, `init`, the tool's description and its reply. The re-run
    agent asked which name was meant, and changed nothing.
  - **The second run:**

    | scenario | package | passed | turns | cost (USD) | seconds |
    |---|---|---|---|---|---|
    | hallucinated | express-session-guard-pro | yes | 5 | 0.35 | 18.9 |
    | near-miss | reqeusts | yes | 5 | 0.35 | 22.4 |
    | malicious | atez | yes | 5 | 0.34 | 21.2 |
    | real | humanize | yes | 10 | 0.58 | 66.8 |

  - **Spent:** $4.19 of D36's $10, all three runs included; the rest is R15.2's.

**Exit:** track 5 at D22's target through both paths; the scenarios recorded.

**Exit STATUS 2026-09-30** (`docs/acceptance/r12.md`):
- **Track 5 through both paths:** ✅ 100 through a scan and 100 through `check_package`,
  on both lanes, against D22's 95. The Score stays 63.0 on both, no track fell, and
  every judged gate is green.
- **The scenarios:** ✅ recorded, four of four on the second full run; $4.19 of D36's
  $10 spent.
- **The acceptance set:** ✅ both lanes. Linux is run 36647991049; the Mac's set was
  regenerated.
- **The suites:** ✅ e2e 81 passed on the Mac. CI's reproducibility job failed once, on
  `79ee351`, and passed on the phase commit's run (`f3f4f0e`), whose tree differs from
  it only in documents: a one-off, recorded here from R13's branch.

### Phase R13: static analysis, widened against the benchmark

- [x] **R13.1** **The rule source, audited** (D29; F2.9). Behaviours:
  1. `tests/eval/sources.toml` pins `sast-rules` by commit;
  2. a manifest lists every candidate rule's path, languages, CWE and the origin project
     its metadata names, with that project's licence;
  3. a test refuses any vendored rule whose origin is not MIT, Apache-2.0 or BSD.
  **STATUS 2026-09-30:** ✅ all three.
  - **Pinned** at `53bf5cf`, 2026-09-21.
  - **Origins.** Each rule's origin is read from the repository's own `mappings/`. A
    rule qualifies only when its file and its origin are both permissive. Three trees
    carry a licence of their own and are out: `rules/gitlab` (GitLab EE), `rules/lgpl`
    (LGPL-3.0) and `rules/lgpl-cc` (Commons Clause).
  - **Measured: 303 candidates in D29's four languages, 106 eligible.**
    - 68 Python, from Bandit (Apache-2.0).
    - 27 Go, from gosec (Apache-2.0).
    - 11 JavaScript and TypeScript, from ESLint's security and React plugins
      (Apache-2.0, MIT).
    - Every eligible rule declares a CWE.
  - **None of Java is eligible.** Its 55 rules translate find-sec-bugs (LGPL-3.0), so
    Java stays with valvur's own rules. Also out: njsscan's 83 JavaScript rules
    (LGPL-3.0), and 49 rules under Commons Clause or GitLab EE.
  - The manifest is `tests/eval/sast-rules.json`, generated by
    `scripts/eval/sast_rules.py`, whose `refuse` the suite runs over
    `rules/vendor/gitlab/`.
- [x] **R13.2** **Each rule measured.** Behaviour: `scripts/eval.py --per-rule <dir>`
  reports each rule's true and false positives over tracks 1 and 2 and the corpus, and its
  time; the measurement of every candidate is recorded in the STATUS.
  **STATUS 2026-09-30:** ✅
  - **The harness.** `scripts/eval/sast_rules.py --stage` copies the 106 eligible rules.
    `eval.py --per-rule DIR` runs them through the image's Opengrep over each target,
    as a scan reads it (tests and build trees included).
    - A match on a vulnerable case of the rule's weakness is true; on a safe one, false.
    - On a case of another weakness it is *outside*.
    - In the corpus it is false, unless a label says a maintainer would act on it.
  - **Two fixes on the way.**
    - `cwe.rule_cwes` read only valvur's own layout, so GitLab's quoted ids at the
      margin had no CWE and every match counted as outside. The pattern now reads
      both, and valvur's rules read the same as before.
    - CWE-338, a weak PRNG, now answers its parent 330, as 95 answers 94. A parent
      never answers for its child: Bandit's hash rules declare 327, not the
      benchmark's 328, so their 71 matches on weak-hash cases stay outside.
  - **Measured on the Mac, 106 rules: 78 match nothing at all.** The 28 that match:

    | rule | CWE | true | false | outside | precision | meets the bar | s |
    |---|---|---|---|---|---|---|---|
    | python_random_rule-random | 338 | 35 | 3 | 0 | 0.92 | **yes** | 0.30 |
    | python_sql_rule-hardcoded-sql-expression | 89 | 5 | 0 | 0 | 1.00 | **yes** | 0.00 |
    | python_deserialization_rule-yaml-load | 502 | 5 | 5 | 0 | 0.50 | **yes** | 0.02 |
    | python_exec_rule-subprocess-popen-shell-true | 78 | 7 | 7 | 0 | 0.50 | no, see below | 0.06 |
    | javascript_eval_rule-eval-with-expression | 95 | 1 | 0 | 0 | 1.00 | **yes** | 1.73 |
    | python_deserialization_rule-pickle | 502 | 13 | 17 | 0 | 0.43 | no | 0.10 |
    | python_eval_rule-eval | 95 | 10 | 17 | 0 | 0.37 | no | 0.20 |
    | python_exec_rule-exec-used | 95 | 10 | 24 | 0 | 0.29 | no | 0.43 |
    | python_xml_rule-minidom | 611 | 8 | 20 | 0 | 0.29 | no | 0.01 |
    | python_xml_rule-sax | 611 | 8 | 20 | 0 | 0.29 | no | 0.01 |
    | javascript_pathtraversal_rule-non-literal-fs-filename | 22 | 1 | 51 | 0 | 0.02 | no | 34.76 |
    | python_assert_rule-assert-used | 754 | 0 | 139 | 0 | 0 | no | 0.78 |
    | python_requests_rule-request-without-timeout | 770 | 0 | 134 | 0 | 0 | no | 0.43 |
    | javascript_dos_rule-non-literal-regexp | 185 | 0 | 10 | 15 | 0 | no | 1.49 |
    | python_tmpdir_rule-hardcodedtmp | 377 | 0 | 5 | 0 | 0 | no | 0.77 |
    | javascript_require_rule-non-literal-require | 95 | 0 | 4 | 0 | 0 | no | 1.47 |
    | python_crypto_rule-hash-md5 | 327 | 0 | 4 | 17 | 0 | no | 0.01 |
    | python_crypto_rule-hash-sha1 | 327 | 0 | 3 | 20 | 0 | no | 0.01 |
    | go_filesystem_rule-fileread | 22 | 0 | 2 | 0 | 0 | no | 0.00 |
    | python_exec_rule-subprocess-call | 78 | 0 | 2 | 0 | 0 | no | 0.10 |
    | python_flask_rule-app-debug | 489 | 0 | 2 | 0 | 0 | no | 0.06 |
    | python_xml_rule-element | 611 | 0 | 1 | 57 | 0 | no | 0.03 |
    | python_crypto_rule-hashlib-new-insecure-functions | 327 | 0 | 0 | 34 | 0 | no | 0.14 |
    | python_xml_rule-etree | 611 | 0 | 0 | 129 | 0 | no | 0.07 |
    | go_file-permissions_rule-fileperm | 732 | 0 | 1 | 0 | 0 | no | 0.01 |
    | go_file-permissions_rule-mkdir | 732 | 0 | 1 | 0 | 0 | no | 0.01 |
    | javascript_timing_rule-possible-timing-attacks | 208 | 0 | 1 | 0 | 0 | no | 3.51 |
    | python_escaping_rule-jinja2-autoescape-false | 116 | 0 | 1 | 0 | 0 | no | 0.02 |

  - **Four rules meet D29's bar**, as R13.6 amended it: three Python, one JavaScript.
    The `subprocess` shell rule met the first bar, but all 7 of its true positives are
    at lines valvur's own `subprocess-shell-true` already reports. No Go rule has a
    true positive: the tracks hold no Go cases, and gosec's rules matched only the
    corpus. Between them the four add three corpus matches, all `random`'s, for R13.3
    to label.
  - **The first measurement was wrong, and is replaced above.** Opengrep reads
    `.semgrepignore` from its working directory, not from the target. Run from the
    image's default, it applied its own ignore list and skipped every `tests/` tree
    in the corpus, so `pickle` measured 0.57 and met the bar. The scans that labelled
    the corpus read those trees, and showed seven `pickle` matches in `requests`' tests
    that the measurement never saw. The harness now runs Opengrep with `-w /src`, a
    test holds it, and `pickle` measures 0.43.
- [x] **R13.3** **The rules that pass, shipped.** Behaviours:
  1. `rules/vendor/gitlab/` holds exactly the rules meeting D29's bar, with the licence,
     the commit and the manifest; `NOTICE` credits it;
  2. the image carries them, and `run.json` names the rule set's commit;
  3. e2e: a planted SQL injection in a JavaScript file is reported by a vendored rule.
  **STATUS 2026-09-30:** ✅ 1 and 2; 3 as the measurement allows.
  - **Four rules vendored**, exactly R13.2's list under D29 as R13.6 amended it:
    - Python: `random`, hard-coded SQL and `yaml.load`, from Bandit;
    - JavaScript: `eval` of an expression, from eslint-plugin-security.
    - The `subprocess` shell rule shipped here first. R13.6's acceptance run found it
      reporting every planted shell flow a second time beside valvur's own rule, and
      it was withdrawn.

    They sit under `rules/vendor/gitlab/` as GitLab wrote them, with its LICENSE and a
    manifest of each rule's origin, licence, CWE, source path and measurement.
    `scripts/eval/sast_rules.py --vendor` writes the directory, and `NOTICE` credits
    it. The committed measurement is `tests/eval/sast-rules-measured.json`.
  - **The image** copies them with valvur's own rules. `run.json` gains `rule_sets`,
    naming `gitlab-sast-rules` at `53bf5cf`. A vendored finding keeps GitLab's own
    rule id (the last part of Opengrep's check id), so its identity survives the
    directory moving.
  - **Behaviour 3, amended by the measurement.** No eligible rule reports a SQL
    injection in JavaScript: GitLab's JavaScript SQL rules translate njsscan (LGPL-3.0)
    and were never candidates. The e2e plants what the shipped rules report: a
    formatted SQL string in Python and an `eval` of an argument in JavaScript. Both
    are reported through the image, and `run.json` names the rule set.
  - **Track 8 now judges them.** It judged only `valvur.` rules and Gitleaks, so the
    vendored rules' corpus findings went unjudged. Since valvur ships them, it answers
    for them. Their three findings are `random`'s: a toy Markov generator in `llm`'s
    documentation, twice, and retry jitter in `smolagents`. All three are labelled
    `fp`, and track 8 moves from 4.2 to 3.7, inside the ratchet's 2 points.
- [x] **R13.4** **CWE on findings** (F5.10). Behaviours: `findings.json` and SARIF carry
  `cwe` when the rule declares one; the findings schema's own rule for additions decides
  whether its version moves; ranking and grouping are unchanged.
  **STATUS 2026-09-30:** ✅ all three.
  - A finding's `cwe` is its rule's declared CWEs as `CWE-n`, from the metadata
    Opengrep passes with each result. valvur's rules write a list with names, GitLab's
    one string; both are read.
  - `findings.json` writes `cwe` only when there is one. It is an optional addition,
    so schema 1 stands, as it did for `generation` and `groups`.
  - SARIF puts it on the rule, with the `external/cwe/cwe-n` tag that code-scanning
    tools read.
  - Neither ranking nor grouping reads it, and a merge keeps it.
  - Measured through the image: the vendored SQL rule's finding carries `CWE-89`.
- [x] **R13.5** **Cross-function taint.** Measure first. Behaviour: adopted per D29, or the
  measurement recorded and nothing changed.
  **STATUS 2026-09-30:** ✅ measured, not adopted, nothing changed.
  - The pinned Opengrep 1.29.0 has `--taint-intrafile` (intra-file inter-procedural
    taint, Python and JavaScript among its languages).
  - Measured by `scripts/eval/taint.py`: the shipped rules through the image over
    tracks 1 and 2, with and without the flag, scored by the Score's own formula.
    Opengrep's share alone.

    | track | default | `--taint-intrafile` |
    |---|---|---|
    | sast-python | 11.1 (109 true, 45 false, 5.9 s) | 11.1 (109, 45, 5.3 s) |
    | sast-js | 5.0 (1, 0, 2.8 s) | 5.0 (1, 0, 2.9 s) |

  - It raises neither track, so under D29 it is not adopted. Five of valvur's rules
    are taint rules: four for LLM output sinks, and the vendored SQL rule. Neither
    track's matches changed with the flag.
- [x] **R13.6** **The speed guard.** Behaviour: Opengrep's median time on the acceptance set
  within 130% of R9's, pruning the slowest rules until it is.
  **STATUS 2026-09-30:** ✅ met with nothing pruned.
  - Opengrep's time on each repository comes from its `run.json`, on the Mac through
    Docker Desktop:

    | set | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | median |
    |---|---|---|---|---|---|---|---|---|---|
    | R9's | 6.3 | 11.4 | 33.9 | 34.2 | 8.0 | 10.8 | 28.9 | 15.4 | 13.4 |
    | R12's, no vendored rule | 2.3 | 2.5 | 2.0 | 2.3 | 2.3 | 4.7 | 2.0 | 2.5 | 2.3 |
    | R13's, four vendored | 2.3 | 2.8 | 2.0 | 2.2 | 2.3 | 4.8 | 2.1 | 2.6 | 2.3 |

    The limit is 130% of 13.4 s, 17.4 s. Against R12's run on the same machine, the
    four rules cost nothing measurable. R9's median was taken under heavier host
    swap.
  - **Found by this run.** Repositories 1 and 4 failed, because the vendored
    `subprocess` shell rule reported each planted shell flow a second time. It was
    withdrawn and D29's bar amended (`ea352ce`); the set passes again.
- [x] **R13.7** **The claims, from the measurement.** Behaviour: the README's static-analysis
  paragraph and `EVALUATING.md` state tracks 1 and 2 as measured and nothing beyond them;
  `test_readme_as_built.py` holds the numbers.
  **STATUS 2026-09-30:** ✅
  - **The README's paragraph** is now "Static analysis, measured, and modest". It names
    valvur's own rules, and GitLab's four with the bar they met. It states track 1 at
    **11.1** and track 2 at **15.0**, and claims nothing further.
  - **`EVALUATING.md`** adds the before and after of tracks 1, 2 and 8 and which
    categories moved, and says what stays unfound.
  - **The test** holds both documents to the baseline, which is raised from Linux run
    36655021422 in this commit, since the README cites it.
  - Both lanes measured 64.9, with tracks 1 and 2 at 11.1 and 15.0.

**Exit:** tracks 1 and 2 at D22's targets or recorded as missed; track 8 at or above 80;
the speed guard met.

**Exit STATUS 2026-09-30** (`docs/acceptance/r13.md`):
- **Tracks 1 and 2:** recorded as missed. 11.1 and 15.0 on both lanes, from 0.4 and
  10.0, against D22's 25 and 50. The rise is four vendored rules. The miss is in §8 for
  the owner.
- **Track 8:** ❌ 3.7 against 80, from 4.2: `random`'s three corpus findings, labelled
  `fp`. It is inside the ratchet's 2 points, and in §8 with the others.
- **The speed guard:** ✅ Opengrep's median on the acceptance set is 2.3 s, against a
  limit of 17.4 s.
- **The Score:** 64.9 on both lanes, from 63.0. `--compare` passes, every judged gate
  is green, and the baseline is raised for tracks 1 and 2 from Linux run 36655021422.
- **The acceptance set:** ✅ both lanes at `922113c`, Linux run 36657110279.
- **The suites:** ✅ e2e 82 passed on the Mac, and CI's required checks on #166.

### Phase R14: reuse what cannot have changed

- [x] **R14.1** **Measure.** Each Scanner's warm time on the acceptance set, both lanes,
  recorded as the before.
  **STATUS 2026-09-30:** ✅ both lanes. The acceptance report now carries each
  Scanner's time per repository, from its `run.json`. Measured on the Mac, in seconds:

  | repository | osv-scanner | trivy | opengrep | checkov | the rest, each |
  |---|---|---|---|---|---|
  | 1-gate-shaped | 0.3 | 0.3 | 2.4 | 0.0 | ≤ 0.5 |
  | 2-lockfiles | 15.0 | 0.4 | 2.9 | 3.6 | ≤ 0.4 |
  | 3-history-secret | 0.3 | 0.3 | 2.0 | 0.0 | ≤ 0.3 |
  | 4-nested-names | 0.3 | 0.3 | 2.2 | 0.0 | ≤ 0.3 |
  | 5-infrastructure | 0.3 | 0.3 | 2.5 | 54.4 | ≤ 0.6 |
  | 6-self | 3.7 | 0.3 | 4.6 | 4.6 | ≤ 1.8 |
  | 7-local-exposure | 0.4 | 0.3 | 2.1 | 0.0 | ≤ 0.4 |
  | 8-malicious-dependency | 10.7 | 0.3 | 2.8 | 0.0 | ≤ 0.4 |

  - A warm rescan of repository 8, three times: 14.0, 13.7 and 14.4 s. OSV-Scanner,
    loading its offline npm database, is 10.0 to 10.6 s of it.
  - **Linux**, `acceptance.yml` run 36659345238, in seconds:

    | repository | total | osv-scanner | trivy | opengrep | checkov |
    |---|---|---|---|---|---|
    | 1-gate-shaped | 8.7 | 0.3 | 0.2 | 3.7 | 0.0 |
    | 2-lockfiles | 19.1 | 16.0 | 0.3 | 4.1 | 6.0 |
    | 3-history-secret | 4.5 | 0.3 | 0.2 | 3.5 | 0.0 |
    | 4-nested-names | 4.7 | 0.3 | 0.3 | 3.7 | 0.0 |
    | 5-infrastructure | 124.1 | 0.3 | 0.3 | 4.0 | 123.1 |
    | 6-self | 11.6 | 6.4 | 0.3 | 9.4 | 10.0 |
    | 7-local-exposure | 4.4 | 0.3 | 0.3 | 3.5 | 0.0 |
    | 8-malicious-dependency | 12.4 | 11.5 | 0.3 | 3.5 | 0.0 |

  - **What reuse can save.** Trivy is 0.3 s everywhere, and OSV-Scanner is most of
    any scan with an npm or PyPI lockfile. Checkov, on repository 5, reads source
    and is never reused.
- [x] **R14.2** **The reuse key** (D32; N1.5). Behaviours, one test each: a lockfile's byte
  change, the database's built time, the Scanner's version and the Profile each change the
  key; a source file's change does not.
  **STATUS 2026-09-30:** ✅ all five, and three more.
  - `valvur.reuse.key` hashes the Scanner, its version, the Profile, the data stamp,
    and the path and sha256 of every dependency file in the File Set.
  - Which files count comes from a named list, erring wide: each ecosystem's
    lockfiles and manifests as both tools document them, Java archives, SBOMs, and
    the tools' own configuration.
  - A test holds every lockfile valvur itself names to the list. A dependency file
    added or moved changes the key; a source file or a README does not.
  - Only Trivy and OSV-Scanner are reusable. OSV-Scanner only on `offline`: on
    `full` it answers from api.osv.dev, which has no stamp to key on.
- [x] **R14.3** **Reuse in a scan.** Behaviours:
  1. through `LocalRuntime`, a second scan of an unchanged repository 8 runs neither Trivy
     nor OSV-Scanner, and its fingerprints equal the first's;
  2. `run.json` names each reused result and its run;
  3. `--fresh` and `fresh: true` run everything.
  **STATUS 2026-09-30:** ✅ all three, and two more: a changed lockfile runs both
  again, and a changed source file does not.
  - **In the scan.** Before the Scan Container starts, each reusable Scanner's key is
    computed. A stored result for it becomes that Scanner's outcome, parsed as if it
    had just run, and the Scanner leaves the plan. A clean result that ran is stored
    under its key, written whole and renamed into place. A cut, a timeout or a failure
    is never stored.
  - **Said.** The progress says `trivy: reused (…unchanged since run …)`. Each reused
    Scanner's entry in `run.json` carries `reused_from`, the generation that ran it.
  - **`--fresh` and `fresh`.** The CLI's `--fresh` and the `scan` tool's `fresh: true`
    run everything. Each is passed only when asked, as every existing caller of the
    scan functions expects.
  - **Test stand-ins.** Fake `trivy` and `osv-scanner` join the test tools; they log
    each run.
  - **Found on the way.** Deciding which files are dependency files read about 95
    patterns per name, seconds on repository 1's 103,251 files. It is now one
    compiled expression, under a second for 100,000 names (`timing`).
  - **Found at R14's exit.** A fresh scan stored nothing, so a doubted result
    survived `--fresh`, and the next scan reused it again. A fresh scan now stores
    what it ran, and the next scan reuses that.
- [x] **R14.4** **The reused results' home.** Behaviours: under the host cache and its
  lock; `update --prune` removes those of superseded keys, `--clear` all; nothing is
  written in the Workspace but the Results Folder.
  **STATUS 2026-09-30:** ✅ all three.
  - **Where they live.** Results sit in `~/.cache/valvur/reuse/<tool>/<key>.json`. A
    scan writes them under its shared cache lock, whole and renamed into place, and
    a scan's Workspace gains nothing but `.security-scan/`.
  - **Pruning.** Each stored result carries its Scanner's version and data stamp.
    `reuse.superseded` names those that can never match again, because the version
    or data has moved on, and those unused for 30 days; a reuse restarts that clock.
  - **`update --prune`** lists each before removing it, under the exclusive lock.
    **`--clear`** removes the directory with the rest, and the cache listing names
    it (`2 results`).
  - **An incident, found and repaired here.** The first draft of the `--prune` test
    ran the real command against this Mac's Docker. It removed the owner's pulled
    `valvur:0.3.0`, `0.4.0` and `0.5.0`, which `CLAUDE.md` §9 forbids.
    - All three were re-pulled at once, and their image IDs match the deleted ones.
    - `tests/conftest.py` now makes image removal raise in every unit test, and a
      test holds that.
    - The same draft's `--clear` test removed the suite's shared database stand-in.
      It now clears a cache of its own.
- [x] **R14.5** **The after.** Behaviour: a warm rescan of repository 8 is at least 30%
  faster on both lanes, or D32's fallback is applied and recorded; the speed gate is judged
  from here on.
  **STATUS 2026-09-30:** ✅ both lanes, with no fallback: repository 8's warm rescan
  is 63% faster on the Mac and 69% on Linux, with the same findings.

  | repository 8, warm | before (R14.1) | after | faster |
  |---|---|---|---|
  | the Mac | 14.0 s | 5.2 s | 63% |
  | Linux, run 36663217973 | 12.4 s | 3.8 s | 69% |

  - **The rescan.** `acceptance.py --rescan` scans each repository a second time,
    unchanged, and reports the median. Every repository passes on both lanes, and
    zero containers remain after the four probes.
  - **Where the time went.** OSV-Scanner's 10.9 s on Linux and 10.7 s on the Mac
    are gone: its answer is the last scan's. Repository 2's rescan falls from 17.4 s
    to 5.7 s on Linux, the same way.
  - **The speed gate.** `tests/eval/baseline.json` holds each lane's median warm
    rescan: 4.8 s on Linux and 5.6 s on the Mac. `eval.py --speed <report>` judges
    a run within 110% of its lane's, and a test holds both medians in the baseline.
  - **Said in the Score.** Each track records which Scanners' results were reused,
    and the scorecard names them. `eval.py --fresh` runs every Scanner.

**Exit:** the speed gate green; the Score with reuse equals the Score with `--fresh`, run
back to back.

**Exit STATUS 2026-09-30** (`docs/acceptance/r14.md`):
- **The speed gate:** ✅ judged on the Mac: the median warm rescan, 5.6 s, within 110%
  of the baseline, which records 5.6 s for the Mac and 4.8 s for Linux.
- **Reuse against fresh:** ✅ `eval.py --fresh`, then `eval.py`, back to back on the
  Mac: 64.9 both times, every category's counts equal, both Scanners reused on all
  eight tracks, 238 s against 190 s. The first pair found that a fresh scan stored
  nothing; fixed, and measured again.
- **The Score:** 64.9 on both lanes, Linux run 36665294454. `--compare` passes and every
  judged gate is green.
- **The acceptance set:** ✅ both lanes at `60325f1`, Linux run 36663217973.
- **The suites:** ✅ e2e 83 passed on the Mac, on the image rebuilt at `9944796`.

### Phase R15: the skill that runs the workflow, and where it ships

- [x] **R15.1** **The skill** (D39; F9.12). Behaviours:
  1. the frontmatter holds only the standard's six fields, a valid name and a description
     within the standard's limit;
  2. every MCP tool it names exists, and every tool the server lists is named;
  3. every command it names exists: the documented-commands test reads it;
  4. its rules block equals the handshake's instructions and `SUMMARY.md`'s agent block,
     all three rendered from one source.
  **STATUS 2026-09-30:** ✅ all four, and three more.
  - **The skill.** `src/valvur/data/skills/valvur/`: `SKILL.md`, 115 lines, and four
    references (tools, triage by kind, CI, air-gapped).
    - Its frontmatter: `name`, a 386-character `description`, `license`, a
      181-character `compatibility`, and `metadata` with the version and home.
    - The body is D39's workflow in eight steps, then what never to do, a table of
      the seven tools, and the rules.
  - **Tools.** The table names exactly the seven the server lists. Every `call` of a
    tool in the skill is one of them. `references/tools.md` is rendered from the
    registry: each tool's description and every field it takes.
  - **Commands.** The documented-commands test reads the skill's five files, and
    every command they name is in the CLI's help.
  - **The rules, written once.** `valvur.agent_rules` holds each rule once, in full
    and in short.
    - The handshake renders the full form. Its snapshot is unchanged byte for byte.
    - The skill's rules block is the handshake's text, held by a test.
    - `SUMMARY.md`'s agent block renders the short form. It keeps its nine lines and
      one screen for repository 1; the eight goldens changed only in line breaks
      and one clause.
  - **Also held.** The skill's `metadata.version` is the package's, a version
    surface `prepare_release.py` must move (R16.2). Every reference the skill links
    exists, and each is linked.
- [x] **R15.2** **The Claude Code plugin** (D40; F9.13). Behaviours:
  1. `.claude-plugin/marketplace.json` and `plugins/valvur/.claude-plugin/plugin.json` are
     valid (`claude plugin validate` where the CLI has it);
  2. the plugin's MCP configuration is `valvur.mcp.clients`' Claude Code block, pinned to
     the version, and `test_version.py` holds it;
  3. the plugin's skill is the package's, byte for byte;
  4. a smoke run, `claude -p --plugin-dir plugins/valvur` with `--disallowedTools Bash`,
     lists the skill and the server's tools (D36).
  **STATUS 2026-09-30:** ✅ all four.
  1. **The marketplace and the plugin.** The repository is a marketplace named
     `valvur`, listing one plugin at `./plugins/valvur`. `claude plugin validate
     --strict` passes both on Claude Code 2.1.284, and a test runs it wherever the CLI
     is installed. Neither is in the sdist.
  2. **The server.** `plugins/valvur/.mcp.json` is the Claude Code block,
     `uvx --from valvur==1.1.0 valvur-mcp`, rendered by `clients.snippet(…,
     version=…)`. `test_version.py` holds it and `plugin.json`'s version to the
     package's.
  3. **The skill** is a copy, since Claude Code copies a plugin into its cache and
     skips a symlink under `skills/`. A test holds it to `skill.files()` byte for
     byte, with no file more and no symlink.
  4. **The smoke run**, `scripts/acceptance/plugin_smoke.py`, judged from the
     stream's init event. Run in an empty directory, it cost $0.98 of D36's $10,
     which now stands at $5.17.

     | form | plugin | skill | server | tools |
     |---|---|---|---|---|
     | as shipped, the server `valvur==1.1.0` from PyPI | loaded, 1.1.0 | `valvur:valvur` | connected | 6: all but `check_package` |
     | `--from-tree`, this checkout's server | loaded | `valvur:valvur` | connected | all 7 |

  - **Found by the smoke run.** The plugin pins the published release, and 1.1.0
    predates `check_package`, which the skill names. The plugin is whole only from
    1.2.0; §8 asks the owner to publish 1.2.0 before announcing the marketplace.
- [x] **R15.3** **The Kiro power** (D40). Read Kiro's documented layout first. Behaviours: the
  manifest's fields; its `mcp.json` is Kiro's client block; its skill is the package's; the
  Kiro stdio probe (D20) replays against the power's server configuration.
  **STATUS 2026-09-30:** ✅ all four.
  - **Kiro's layout, read first.** Sources: kiro.dev's powers pages (`/docs/powers/`,
    `/create/`, `/installation/`) and the Agent Plugins 1.0.0 spec they follow.
    - A power is now an Agent Plugin: `plugin.json`, `mcp.json` and
      `skills/<name>/SKILL.md`.
    - The older `POWER.md` format still loads but cannot carry a skill, so D40's
      fallback is not needed.
    - A symlink that leaves the power's root is rejected, so the skill is a copy.
    - Kiro installs from `…/tree/main/powers/valvur` and names the power by its
      folder.
  - **The manifest** is inside the spec's closed field set, with the fields Kiro
    requires: `$schema`, `name`, `version`, `description`, `author` and `keywords`,
    which activate it. Its version is held by `test_version.py`.
  - **The server.** It is Kiro's client block, `uvx --from valvur==1.1.0 valvur-mcp`,
    with `type: stdio`. It has no `disabled` or `autoApprove`: the spec makes an
    entry with an unknown field invalid.
  - **The skill** is a copy held to the package's byte for byte, by the check the
    plugin's uses.
  - **The probe.** Kiro's sequence replays in the e2e suite against the power's own
    command, the pin swapped for this checkout since the version being built is
    unpublished. Both replays pass on the Mac: the power's in 16.2 s, `uvx` building
    the checkout included, and the direct server's in 15.0 s.
  - **Not done here:** installing the power in Kiro's GUI. It is the owner's, with
    Kiro's GUI pass in §8.
- [x] **R15.4** **`init --write` adds the skill** (D40). Behaviours: written for Claude Code
  and for Kiro; never over an existing file; `init` without `--write` names it; `doctor`
  says whether the project's skill is present and whether its version matches.
  **STATUS 2026-09-30:** ✅ all four, and one more.
  - **Written.** `init --write` writes the package's skill to `.claude/skills/valvur/`
    and `.kiro/skills/valvur/`, for each client it writes: those named with
    `--client`, else those found. Each is byte for byte `skill.files()`.
  - **Never over what is there.** A skill directory that exists is left whole, not
    filled in, and the output names its version. A second `--write` changes nothing.
  - **Named.** `init` alone says where each client found reads the skill, and gives
    the plugin's install commands for Claude Code.
  - **`doctor`'s `skill` line.**
    - `ok` names each copy, with its version, as this valvur's.
    - `warn` names a copy of another version, with the fix: remove it and run
      `init --write`.
    - `info`, when there is none, says how to add one.
  - **And one more.** The agent-configuration Check reads the written skill, all
    five of Claude Code's files and Kiro's `SKILL.md`, and reports nothing in it.
    valvur does not flag its own instructions as a planted directive.
  - **Found on the way.** `valvur.skill` rendered the tools reference by importing
    the server's tools, which closed an import cycle through `doctor`. The reference
    now lives with the tools, `valvur.mcp.tools.reference`.

**Exit:** the skill, the plugin and the power pass their tests; the smoke run recorded;
no track under the baseline.

**Exit STATUS 2026-09-30** (`docs/acceptance/r15.md`):
- **The tests:** ✅ the skill's, the plugin's and the power's, with `claude plugin
  validate --strict` passing both manifests, and Kiro's probe replayed through the
  power's command in the e2e suite.
- **The smoke run:** ✅ recorded. From this tree: all seven tools. As shipped, pinned to
  `valvur==1.1.0`: six, since 1.1.0 predates `check_package` (in §8). D36's agent runs
  stand at $5.17 of $10.
- **The Score:** ✅ 64.9 on both lanes, no track under the baseline, Linux run
  36672336453. All five gates are green on the Mac; the speed median is 5.2 s.
- **The acceptance set:** ✅ both lanes at `2f86d6e`, Linux run 36672339357.
- **The suites:** ✅ e2e 84 passed on the Mac, and 1747 unit tests.

### Phase R16: less drag, the documents as built, and 1.2.0 prepared

- [x] **R16.1** **The arm64 e2e leg** (D38). Behaviour: the e2e job's matrix gains
  `ubuntu-24.04-arm`, green, or D38's fallback applied.
  **STATUS 2026-09-30:** ✅ green on its first run, with no fallback.
  - **The matrix.** The `e2e` job runs on `ubuntu-24.04` and `ubuntu-24.04-arm`,
    `fail-fast: false`. The x86 leg keeps the name `main`'s protection requires,
    *end-to-end (real container)*.
  - **Docker only on arm64.** Podman and its parity guard run on the x86 leg alone.
    Each leg has its own build cache and name-index cache.
  - **Measured.** CI run 36674704216 on #169: the arm64 leg took 9.4 minutes and the
    x86 leg 12.9, side by side, so the job's wall time does not grow. R15's x86 leg
    took 12.5. `test_e2e_arm.py` holds the shape, and zizmor finds nothing in it.
- [x] **R16.2** **`scripts/prepare_release.py`** (D33; N3.4). Behaviours: one commit sets
  every version surface `test_version.py` reads, the plugin's and the power's included;
  `--published` flips the README's wording; a dry run changes nothing.
  **STATUS 2026-09-30:** ✅ all three, and two refusals.
  - **One commit, `chore: release <version>`, sets fourteen files.**
    - The version and the lock.
    - The README's status line, worded *release in progress* and naming the
      version PyPI still serves.
    - `SECURITY.md`'s series, and the CHANGELOG's heading under an empty
      *Unreleased*.
    - The skill's version in the package and in both copies, which stay byte for
      byte the package's.
    - The plugin's and the power's manifests, and both servers' pins.
    - The image the two pipeline examples name. Found by preparing 1.2.0: the first
      release commit left them at 1.1.0 and a test caught it; the script now sets
      them, and the tests prepare whatever version follows the tree's.
  - **`--published <version>`** flips the status line to *published and installable*,
    in `docs: <version> published`.
  - **`--dry-run`** prints the diff and changes nothing. On this tree, `1.2.0 --dry-run`
    lists the fourteen files.
  - **Refused, exit 2:** a version not after the tree's, `--published` of a version
    the tree is not, and a tree with uncommitted changes, since the release commit
    holds the release alone.
  - **Tested** against a copy of those files in a repository of its own.
    `docs/RELEASING.md`'s steps use the script now; the tag, the push and the brake
    stay the owner's.
- [x] **R16.3** **The monthly Scanner refresh** (D34; N3.5). Behaviours: `refresh.yml`
  compares `main`'s pins with the latest release's by `test_scanner_pins.py`'s parser;
  runs the Score; opens one issue; a test holds its schedule and permissions.
  **STATUS 2026-09-30:** ✅ all four; the first real run is the owner's, after landing.
  - **One parser.** `scripts/scanner_pins.py` reads the image's pins, and
    `test_scanner_pins.py` now calls it. `--since <tag>` reads the release's files
    from its tag. On this tree, since `v1.1.0`, it names Syft, 1.51.1 to 1.52.0.
  - **`refresh.yml`.** It wakes each Monday, and its first step lets only the first
    seven days of the month through, since cron cannot say "first Monday".
    - When the pins moved, it builds `main`, runs the Score with `--compare`, and,
      only when the Score held, dispatches a rehearsal of `main`.
    - It then opens one issue, or comments on the open one, with what moved and
      what to do.
    - A Score that fell is reported in that issue, not as a red run. A breakage of
      the run is its own issue, as in every scheduled workflow (27.2.7). The release
      constraint listing them now names it too.
  - **Permissions:** `contents: read`, `issues: write` and `actions: write`, held by
    a test. It never tags, pushes or publishes, and zizmor finds nothing in it.
  - **Not run here.** GitHub dispatches only a workflow on the default branch. A run
    would also dispatch a rehearsal and open an issue in the owner's repository, so
    §8 asks the owner to dispatch it once after landing.
- [x] **R16.4** **The documents as built.** The README (the Score and its tracks, freshness,
  `check_package`, seven tools, nine commands, the skill, and installing the plugin or the
  power), `EVALUATING.md`, `AIR-GAPPED.md` (the EPSS and malicious-list mirrors),
  `PROTOCOL.md`, `design.md` and `requirements.md`, amended; `CLAUDE.md` within 200 lines;
  R9 to R15 moved to `docs/history/tasks-phases-r9-r16.md`. Behaviours: traceability holds;
  the link check passes; `test_readme_as_built.py` passes.
  **STATUS 2026-09-30:** ✅ all three behaviours, with three README checks added.
  - **The README.** It now covers:
    - the Score, 64.9, and what it measures;
    - every dataset fetched and the ages at which each is refreshed;
    - reuse, measured (14.0 to 5.2 s on the Mac, 12.4 to 3.8 s on Linux), and
      `--fresh`;
    - the nine commands, and the skill with its three installs;
    - scan times at R15, and arm64 in CI.
    `test_readme_as_built.py` gains three checks: every tool and command named, the
    installs pointing where the plugin and power ship, and the Score cited as the
    baseline's.
  - **`EVALUATING.md`** gives each gate's threshold, speed included, and the Score from
    R9 to R15 by track, with what moved at each phase.
  - **`AIR-GAPPED.md`** names the malicious list, the sixth thing a scan reads: 9 MB on
    disk, from the index's `malicious` tag. The EPSS mirror was there since R11.4.
  - **`PROTOCOL.md`.** Protocol 2 holds to 1.2.0. `/cache/names` carries the malicious
    list and `/opt/valvur-rules` the vendored rules. Reuse is the shim's alone.
  - **`design.md`, version 1.5,** describes R9 to R16 as built in its own sections,
    new ones included: §1.4 reuse, §5.5 vendored rules, §6f the skill, §9a the Score.
    §11 is a pointer table.
  - **`requirements.md`.** Every "to be met by" is now "met by", with the date, and an
    amendment wherever the build differed.
    - N3.4 and N3.5 were cited by D33, D34, R16.2 and R16.3 since R9.2 but never
      written. They are written now. The traceability check does not catch a cited ID
      that is undefined; a separate task is offered for that.
    - Two merged requirements were split again, F6.11 from F6.12 and F7.18 from F7.19.
      The Introduction's count is now seven Scanners and three Checks.
  - **The archive.** R9 to R15 are in `docs/history/tasks-phases-r9-r16.md`, each with
    its STATUS; R14 and R15 gained their exit STATUS. The harness reads the archive,
    so each phase's gate is still judged from it.
  - **`CLAUDE.md`** is 199 lines. Traceability holds, the link check passes, and 1765
    unit tests pass.
- [x] **R16.5** **`1.2.0` prepared** (D37). `prepare_release.py 1.2.0`; the Score on both
  lanes against R9's baseline and D22's targets, recorded; the rehearsal on R16's branch
  per §4, validated and cancelled at the brake.
  **STATUS 2026-09-30:** ✅ prepared, measured and rehearsed; the tag and the brake are
  the owner's (§8). The record is `docs/acceptance/r16.md`.
  - **Prepared.** `chore: release 1.2.0`, fourteen files, then `docs: the 1.2.0 entry`.
    The first attempt missed the pipeline examples' image, and a test caught it before
    the push. The two unpushed commits were set aside, the script fixed, and 1.2.0
    prepared again.
  - **The Score for 1.2.0: 64.9 on both lanes, from R9's 59.3.** Linux is run
    36679307452 and the Mac used the 1.2.0 image. Every gate is green: all five on
    the Mac, speed 6.0 s against 5.6 s, and four on Linux.
  - **D22's targets.** Five of eight are met: secrets, dependencies, package reality,
    agent configuration and infrastructure. Three are missed: SAST-Python 11.1
    against 25, SAST-JS 15.0 against 50, and real-code precision 3.7 against 80. They
    are in §8 since R13.
  - **The rehearsal**, `release.yml` run 36679347319 at `14692b9`. It passed `verify`,
    both native builds, `stage`, and the artifact on amd64 and arm64. It reached the
    brake after 37.5 minutes and was cancelled there; `promote` never ran.
  - **Both lanes' acceptance sets pass**: Linux run 36679309816. The Mac's e2e: 84
    passed.
- [x] **R16.6** **The build's summary**, written as this task's STATUS: what shipped, the
  Score at R9 and now per track, the cost of agent runs, and what §8 holds.
  **STATUS 2026-09-30: the build of R9 to R16.** Eight phases, each on its own stacked
  branch and PR, #162 to #169, each closed by a phase commit with its exit measured on
  both lanes (`docs/acceptance/r9.md` to `r16.md`).
  - **What shipped.**
    - **R9, the Score:** eight tracks by the OWASP Benchmark's formula, five gates,
      and a ratchet.
    - **R10, trust fixes:** a project's own registries are read, history one file
      per commit, and a dual licence is one licence.
    - **R11, fresh data:** every dataset aged by its data, EPSS from FIRST's daily
      file, and a known-malicious list published daily.
    - **R12, `check_package`:** offline, before an install, as the seventh tool and
      the ninth command.
    - **R13, static analysis widened by measurement:** four licence-audited rules, and
      `cwe` on findings.
    - **R14, reuse:** a warm rescan 63 to 69% faster, with the same Score.
    - **R15, the skill:** a Claude Code plugin, a Kiro power, and `init --write`.
    - **R16:** an arm64 e2e leg, `prepare_release.py`, the monthly `refresh.yml`, the
      documents as built, and 1.2.0 prepared and rehearsed.
  - **The Score, R9 to now**, the same on both lanes:

    | track | R9 | now |
    |---|---|---|
    | sast-python | 0.4 | 11.1 |
    | sast-js | 10.0 | 15.0 |
    | secrets | 90.0 | 100.0 |
    | dependencies | 100.0 | 100.0 |
    | package-reality | 81.0 | 100.0 |
    | agent-configuration | 94.3 | 94.3 |
    | infrastructure | 95.0 | 95.0 |
    | real-code-precision | 4.0 | 3.7 |
    | **the Score** | **59.3** | **64.9** |

  - **Agent runs: $5.17 of D36's $10.** R12.5's scenarios cost $4.19, and R15.2's two
    smoke runs $0.98. Each ran without a shell.
  - **What §8 holds.**
    - Landing R9 to R16, the tag `v1.2.0`, and the approval at the brake.
    - One dispatch of `refresh.yml` after landing.
    - Publishing 1.2.0 before announcing the plugin, whose server pins the release.
    - D22's three missed targets.
    - The rest, carried from before.
  - **Found and repaired on the way**, each recorded in its task.
    - A unit test once removed the owner's pulled images. They were re-pulled with
      the same IDs, and removal is now refused in every unit test.
    - A `--fresh` scan stored nothing.
    - An import cycle through `doctor`.
    - N3.4 and N3.5 were cited but never defined.
    - The release commit first missed the pipeline examples.

**Exit:** the Score recorded on both lanes against the baseline, the rehearsal green, and
both schedules deleted.

**Exit STATUS 2026-09-30** (`docs/acceptance/r16.md`):
- **The Score:** ✅ 64.9 on both lanes against the baseline's 64.9. `--compare` passes,
  and every judged gate is green. Linux run 36679307452.
- **The rehearsal:** ✅ run 36679347319, green to the brake and cancelled there.
- **The schedules:** ✅ both deleted: the in-session hourly resume and the desktop task
  `valvur-build-resume`.
- **The acceptance set and the suites:** ✅ both lanes at `14692b9`, and the Mac's e2e
  on the 1.2.0 image.
