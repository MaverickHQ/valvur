# The self-healing supply chain: design

**Status:** proposed 2026-10-21, for the owner's approval · answers
[requirements.md](requirements.md) · built by [tasks.md](tasks.md)

## Overview

Four changes together make the mechanical case heal itself.

- **The nightly judges valvur.** `6-self` scans the latest release instead of a hand-moved
  pin. A dependency advisory younger than the 48-hour healing window is reported as
  `healing` and blocks nothing.
- **The Checkov lock has one writer.** Dependabot leaves it alone, and a check holds every
  pull request to its recipe.
- **A heal workflow fixes the lock from valvur's own data.** Every six hours it scans `main`
  and the latest release with the image built from `main`, using the gate's Profile and the
  databases the gate reads. It re-locks only the flagged packages, by the recipe, and opens a
  signed pull request through a GitHub App. A policy run from the base branch lets that pull
  request merge itself only when re-running the recipe proves it.
- **A security patch releases itself.** When the latest release is affected and `main` is
  not, the heal prepares the next patch release, lands it by the same policy, and tags it
  with its own key. `release.yml` recognises that key, checks the release again, and
  promotes after a 12-hour timer the owner can cancel, instead of after the owner's
  approval.

The owner's queue then holds only decisions (the escalation table below).

```
advisory published (T)
  │
  ├─► heal.yml, every 6 h: build valvur:dev from main · valvur update
  │     scan main, and the latest tag's tree (Profile full)
  │     │
  │     ├─ heal mode: heal.py plan ─► heal.py apply ─► heal/<date> branch (signed by GitHub)
  │     │     └─ App opens the PR ─► heal-auto-merge.yml: the recipe re-run on base, byte-identical?
  │     │           └─ required checks pass ─► GitHub squashes it onto main          (≈ T + 7 h)
  │     │
  │     ├─ release mode: heal_release.py check ─► prepare_release.py X.Y.(Z+1) ─► release/ branch
  │     │     └─ App opens the PR ─► policy: prepare_release.py re-run on base, same tree? ─► merged
  │     │
  │     └─ tag mode: annotated tag vX.Y.(Z+1), signed by the heal's key, pushed with the App's token
  │
  └─► release.yml: signer = heal ─► the security-patch checks again ─► every gate as today
        └─ promote in `release-security`: notice issue, 12 h timer, the owner may cancel  (≈ T + 21 h)
              └─ :X.Y.(Z+1), :latest, PyPI, the GitHub release
nightly 6-self scans the new tag ─► green.  Past T + 48 h, an unhealed advisory blocks: a real incident.
```

---

## What changes, file by file

| file | change | task |
|---|---|---|
| `scripts/build_status.py`, `scripts/acceptance.py` (`ticked`) | read every `.kiro/specs/*/tasks.md`, the main list first | R42.1 |
| `.kiro/specs/valvur/tasks.md` | names this spec in its header, §5 (D81) and §6 | R42.1 |
| `requirements-checkov.txt`, `CHANGELOG.md` | the incident's re-lock, already made as `698b21e` | R42.2 |
| `.github/dependabot.yml` | `exclude-paths` for the Checkov recipe's three files on the `pip` and `uv` entries | R42.3 |
| `scripts/dependabot_auto_merge.py` | leaves any change to `requirements-checkov.*` for the owner | R42.3 |
| `scripts/lock-checkov.sh` | passes extra arguments through; `--no-build`; one uv version | R42.4 |
| `.github/workflows/lock.yml` (new) | the recipe, run again on a pull request, must reproduce the lock byte for byte | R42.4 |
| `src/valvur/findings.py`, `adapters/trivy.py`, `adapters/osv.py` | `Dependency.advisory_published` | R43.1 |
| `scripts/acceptance/generate.py` | `6-self` is the latest `v*` tag; `SELF_PIN` removed | R43.2 |
| `scripts/acceptance.py` | `healing_window_hours` in `expected.toml`; a `healing` column | R43.3 |
| `scripts/heal.py` (new) | `plan`, `apply`, `verify`, `escalations` | R44.2, R44.3, R44.5 |
| `scripts/pypi_facts.py` (new) | upload times, yanks and provenance from PyPI's JSON and integrity APIs | R44.2 |
| `scripts/heal_policy.py` (new) | `lock` and `release` policies; exits 0, 1 or 2 as `dependabot_auto_merge.py` does | R44.4, R45.2 |
| `scripts/signed_push.py` | also accepts `heal/<date>-<hash>` branches | R44.3 |
| `.github/workflows/heal.yml` (new) | the observe, plan, propose, release and tag jobs | R44.6, R45.4 |
| `.github/workflows/heal-auto-merge.yml` (new) | the policy's `judge` job, then `merge` | R44.6 |
| `scripts/heal_release.py` (new) | release eligibility, the CHANGELOG opening's template, `verify` for `release.yml` | R45.2 |
| `.github/workflows/release.yml` | the signer chooses the brake; the security-patch checks; the notice | R45.3 |
| `.github/allowed_signers` | the heal's principal, `valvur-heal` | R45.3 |
| `docs/adr/0032-security-patches-promote-after-a-delay.md` (new) | D81h and D81i | R45.1 |
| `scripts/heal_report.py` (new) | time to heal, from GitHub's API | R46.1 |
| `docs/RELEASING.md`, `docs/MAINTENANCE.md`, `SECURITY.md`, `CLAUDE.md` | the security patch path, its veto, and the window | R46.2 |
| `scripts/watchdog.py`, `.github/workflows/watchdog.yml` (new) | every scheduled workflow's last run, judged daily (amendment 1) | R42.5 |
| `.github/workflows/acceptance.yml` | the nightly checks the watchdog's own last run | R42.5 |
| `scripts/image_gate.py` (new), `.github/image-accepted.yaml` (new, the owner's) | the image's own Trivy over its root filesystem, judged (amendment 2) | R43.4 |
| `.github/workflows/ci.yml`, `release.yml`, `acceptance.yml` | the image check after the build, before `promote`, and against the published image | R43.4 |
| `scripts/base_heal.py` (new) | a dead base tag found and moved (amendment 3) | R44.9 |
| `scripts/scanner_upgrade.py` (new), `.github/workflows/scanner-upgrade.yml` (new) | a Scanner's upgrade completed, measured and judged (amendment 4) | R47.2 to R47.4 |

---

## Components

### 1. The nightly: `6-self` and its judge

`self_at_pin` becomes `self_at_release`. It runs `git describe --tags --abbrev=0 --match
'v[0-9]*'` from `REPO`, then `git archive <tag>` as today, and writes the tag and its commit
into `expected.toml`'s `[run]` so the report can name them. With no tag, generation raises
and names the cause. The acceptance workflow already checks out with `fetch-depth: 0`, so
the tags are there.

`expected.toml` for `6-self`:

```toml
[run]
complete = true
healing_window_hours = 48
```

`judge` gains a `healing` list. When it sees a Finding that is unexpected and blocking, it
asks one question before it counts the Finding as blocking:

- Does the repository set a window?
- Is `finding.dependency.advisory_published` readable?
- Is the advisory's ID not `MAL-`?
- Is the advisory younger than the window, measured against the Scan Run's start in
  `run.json`?

If every answer is yes, the Finding goes to `healing` with its age in hours, and not to
`blocking`. `ok` is unchanged in shape: `healing` never makes a repository fail. The report
gains a `healing` column. `report.json` gains the field, which is an addition.

**Why the advisory's own date and not a first-seen ledger:** the date is already in both
Scanners' output, so no state can be lost. An advisory that reaches the database late leaves
less of the window. The nightly then turns red sooner, which is loud, never silent.

### 2. The advisory date on a Finding

`Dependency` gains `advisory_published: str = ""`. It is enrichment, so it stays out of the
Fingerprint and the Status diff, as the comment on `Finding` requires.

- **Trivy's adapter** reads `PublishedDate`.
- **OSV-Scanner's adapter** reads `published`.
- **Where both Scanners report the Finding**, the merge keeps the earlier date.
- **The date is normalised** to `YYYY-MM-DDTHH:MM:SSZ`. An unparseable date becomes `""`.

`findings.json` gains the field, and its `schema` stays 1 unless the contract tests say an
addition bumps it. That is measured in R43.1, and the result is recorded there.

### 3. The recipe and its check

`scripts/lock-checkov.sh` keeps its flags and adds `--no-build`, then `"$@"`. The heal
calls it as:

```
scripts/lock-checkov.sh --upgrade-package aiohttp --upgrade-package certifi \
    --upgrade-package yarl --constraint "$RUNNER_TEMP/heal-pins.txt"
```

`heal-pins.txt` holds one `package==version` line per moved package. `uv pip compile` reads
the existing lock as its preferences, so every package the pins do not force stays where it
is. That is how `698b21e` moved three packages and nothing else.

The uv version is named in one place that the Mac, CI and the heal all read. R42.4 measures
where `astral-sh/setup-uv` takes its version from, and pins it there.

`.github/workflows/lock.yml` runs on `pull_request` for the paths `requirements-checkov.*`
and `scripts/lock-checkov.sh`. It runs the recipe with no arguments, then
`git diff --exit-code requirements-checkov.txt`. A lock is accepted only if the recipe leaves
it unchanged, which means:

- the overrides hold, since asteval at 1.0.6 would be rewritten;
- the markers are there, since a lock without them would be rewritten;
- the hashes are complete.

One more case fails it: a new distribution uploaded to an old version. The recipe's hash set
then differs, which is itself worth a look.

### 4. The heal workflow, `heal.yml`

Triggers: `schedule: "41 */6 * * *"` and `workflow_dispatch`. The dispatch takes two inputs:
`mode` (`auto`, `heal`, `release` or `tag`) and `dry_run`.

- **`concurrency: heal`** with `cancel-in-progress: false`, so a run is never cut between
  writing a branch and opening its pull request.
- **Top-level `permissions: {}`**, with each job's grant listed below.

| job | runs when | grants | secrets | package code |
|---|---|---|---|---|
| `observe` | always | `contents: read` | none | the image's Scanners, in their containers |
| `plan` | mode `heal` or `checkov` | `contents: read` | none | uv resolution with `--no-build`, which reads metadata only |
| `propose` | `plan` wrote a non-empty plan | none beyond the App token | environment `heal`: `HEAL_APP_ID`, `HEAL_APP_KEY` | none: it checks the artifact in Python and pushes |
| `release-plan` | mode `release` | `contents: read` | none | `prepare_release.py` and `uv lock`, from `main`'s own code |
| `release-propose` | `release-plan` succeeded | none beyond the App token | environment `heal` | none |
| `tag` | mode `tag` | none beyond the App token | environment `heal`, plus `HEAL_TAG_KEY` | none |
| `escalate` | always, last | `issues: write` | none | none |

**`observe`** builds `valvur:dev` from `main`, as `acceptance.yml` does, with its Actions
cache. It runs `valvur update`, then `valvur scan --profile full --fresh` on two trees: the
checkout, and the latest tag's tree archived into `$RUNNER_TEMP`. It uploads both
`findings.json` files and writes the mode as its output.

- **Always `--profile full`, measured.** On 2026-10-23, after `valvur update` and a forced
  database refresh, the `offline` profile still did not know GitPython's advisory of the day
  before; only `--profile full`, which asks OSV.dev, found it (R42.2's STATUS). A heal never
  plans from the `offline` profile.
- **Always `--fresh`** (decided 2026-10-24). ADR-0030 reuses Trivy's and OSV-Scanner's last
  results when their inputs and data look unchanged, and `observe` exists to see what was
  published since the last run. One full scan of two trees every six hours is the cost; a
  heal that misses an advisory because a result was reused is the cost it removes.

The mode comes from data, never from the event:

1. **`heal`**, when `main` has an active dependency vulnerability Finding at
   `requirements-checkov.txt`;
2. else **`tag`**, when `main` holds a release commit made by the App whose tag does not
   exist;
3. else **`release`**, when the latest tag's tree has a dependency vulnerability Finding that
   `main`'s does not, and no App release pull request is open;
4. else **`checkov`**, on the first run of a Monday, when PyPI's newest Checkov past the
   cooldown is newer than the lock's (D81q);
5. else **`none`**.

Heal comes first, because the release gate would fail on `main`'s own Findings anyway.

**`propose`** downloads the plan's artifact and treats it as data. `heal.py verify` checks:

- only the two files are present;
- the lock parses;
- every moved package is in the plan's `pins`, read by Python's parser, with no uv involved.

It then commits locally with the trailers, restates that commit through `signed_push.py
<repo> heal/<date>-<hash>` with the App's token, and opens the pull request with `gh pr
create`, or rebuilds the open one with `gh pr edit`. It then waits up to 90 minutes for the
merge. On a merge it dispatches `heal.yml` again with the workflow's token, which starts a
run, as `refresh.yml`'s dispatch of the rehearsal does. Otherwise the schedule picks the
pull request up.

**`release-propose`** does the same with `release/vX.Y.Z`. **`tag`** checks that the
release commit is on `main` and that no tag `vX.Y.Z` exists. It then writes the key to a file
the job deletes on exit, with mode 600, and runs `git -c gpg.format=ssh -c
user.signingkey=<file> tag -s vX.Y.Z -m "valvur X.Y.Z, a security patch (ADR-0032)" <sha>`.
It pushes the tag over HTTPS with the App's token.

### 5. `scripts/heal.py`: plan, apply, verify, escalations

It uses the standard library and calls `uv` and `valvur check` as subprocesses. It reads
PyPI through `scripts/pypi_facts.py`, whose base URL the tests point at
`tests/fake_registry.py`. `pypi.org` is already named in `src/valvur/egress.py`.

`plan --findings <findings.json> --lock requirements-checkov.txt --now <ISO> --out plan.json`:

1. Take the active Findings whose `dependency` is set and whose `path` is the lock. Group
   them by package.
2. For each package, the floor is the highest `fixed_version` among its Findings, as
   `remediation.py` computes it. With no floor, the package is escalated as `no-fix`.
3. List the package's releases from PyPI's JSON: not yanked, at or above the floor, and in the
   same major version as the locked one. With none in the major, it is escalated as `major`.
4. Choose:
   - the newest release older than the cooldown;
   - otherwise the lowest one, which must be at least 24 hours old and must pass the
     provenance rule;
   - otherwise escalate as `young-unattested`.
5. Run the recipe in `$RUNNER_TEMP` with the chosen pins. Every package that moved and is not
   pinned is a floor that the resolution forced. Each one is chosen by step 4's rule, then
   pinned, and the recipe runs again, until nothing moves that the pins do not name. If a
   package is added or removed, escalate as `new-package`. If the recipe fails, escalate as
   `resolution-failed`. If Checkov would move, escalate as `checkov`.
6. Run `valvur check pypi <name> <version>` for every moved version. A version it flags is
   escalated as `check-failed`.
7. Write `plan.json` (the data model below). Escalated packages are listed and not pinned. A
   partial heal still lands, because each fix removes risk on its own.

**The provenance rule.** For each distribution of the young version, read
`/integrity/<project>/<version>/<filename>/provenance`. Each must exist, and its publisher's
`kind`, `repository` and `workflow` must equal those on the replaced version's distributions.
If the replaced version has no attestation, the rule fails.

`apply --plan plan.json --out <dir>` runs the recipe with the plan's pins and refuses a
result that moves anything else. It adds the CHANGELOG's `### Security` items, and prints the
commit message with its trailers.

`escalations --plan … --observed … --issues <gh issue list json>` prints the issues to open,
to comment on and to close. `escalate` applies them through `.github/actions/file-issue`,
one call per title.

### 6. The policy: `heal_policy.py` and `heal-auto-merge.yml`

`heal-auto-merge.yml` runs on `pull_request` (`opened`, `reopened`, `synchronize`), gated on
two conditions: `github.event.pull_request.user.login == 'valvur-heal[bot]'`, and the head
repository being this one. There is one run per pull request, `cancel-in-progress: true`, as
in R28.2.

- **`judge`** (`contents: read`, `pull-requests: read`, no secret):
  1. Check out the base SHA without credentials and set up the pinned uv.
  2. Read `gh pr view --json files,commits,body,headRefOid`.
  3. Read the pull request's `requirements-checkov.txt` and `CHANGELOG.md` at
     `headRefOid` through the contents API, into `$RUNNER_TEMP`, as data.
  4. Run `python3 scripts/heal_policy.py lock` (or `release`, for a `release/` head). Its
     output is `eligible` and `why`.
- **`merge`** (`needs: judge`; `contents: write`, `pull-requests: write`): runs
  `gh pr merge --auto --squash` when eligible, and `gh pr merge --disable-auto` otherwise. It
  checks nothing out and runs no package code.

**`heal_policy.py lock`** checks Requirement 8.1 in order and stops at the first that fails,
naming it:

1. the file list;
2. each commit's author is the App, its committer is GitHub, its signature is verified, and
   it carries `Heal-Pin` trailers;
3. the recipe, run on the base lock with exactly those pins (written to a constraints file),
   gives a byte-identical lock;
4. the lock's package-name sets are equal, no major version moved, `checkov` did not move,
   and every override's line is unchanged;
5. the CHANGELOG diff only adds lines, and only inside `[Unreleased]`.

**`heal_policy.py release`** does three things:

- it checks that the version is the latest tag's patch plus one;
- it runs `heal_release.py check` against `main`;
- it runs `prepare_release.py X.Y.Z --date <Release-Date trailer>` on a scratch branch from
  the base, then compares that tree with the pull request's head, fetched as objects only.

Exit codes follow `dependabot_auto_merge.py`: 0 eligible, 1 left for the owner, 2
unreadable.

### 7. The security release

`scripts/heal_release.py`:

- **`check --since <tag>`** checks two things. Every commit in `<tag>..main` must be a heal
  commit, a Dependabot commit squashed by R28.2's workflow, or of an allowed Conventional
  Commits type without `!`. `prepare_release.machinery()` must name only
  `requirements-checkov.txt`.
- **`opening <plan…>`** writes the CHANGELOG's opening from one template: *"A security patch,
  released by the heal (ADR-0032): <package> <from> to <to> in the Checkov lock, past
  <advisories>."*
- **`verify --tag <tag>`** is `check` plus the patch-plus-one rule, for `release.yml`.

**`release.yml`**, in `verify`:

- The step *"A real tag is signed by a known key and sits on main"* also writes the
  principal `git tag -v` names, as the `signer` output. Its checks are unchanged.
- A new step runs for `signer == valvur-heal`: *"A security patch is only a security
  patch"*, which runs `python3 scripts/heal_release.py verify --tag "$GITHUB_REF_NAME"`.
- The step's output `brake` is `release-security` for a heal-signed tag that passed, and
  `release` for everything else.
- A rehearsal takes `brake` from a dispatch input, `security_patch`, so the path can be
  proven without a tag.

A new job, **`notice`**, runs only when `brake == 'release-security'`, after `verify`, with
`issues: write`. It opens *"security patch vX.Y.Z promotes about <time> UTC unless you cancel
<run>"*, where the time is the verify time plus the timer plus the measured length of the
release (about 50 minutes).

**`promote`** gets `environment: ${{ needs.verify.outputs.brake }}`. Nothing else in the
release changes.

**The environment `release-security`** (an owner setting) has a wait timer of 720 minutes, no
required reviewers, and deployments from tags `v*` and branches `release/*` (the second for
the rehearsal). A cancelled run publishes nothing. The next heal run sees a tag with no
release and escalates `release-stopped`, which is where the owner's cancel lands: one issue,
and no retry.

**Rehearsal.** `prepare_release.py` names `requirements-checkov.txt` as release machinery, so
D62a would ask for a rehearsal before every heal release. D81i skips it for this class. The
real run's `stage` and `artifact` jobs validate exactly what a rehearsal would, before
`promote`, and a failure there leaves only a `-candidate` tag, so no version number is burned
(ADR-0020).

### 8. Escalations

One issue per title, through `.github/actions/file-issue`: the first run opens it, later runs
comment, and the run that finds the cause gone closes it (`passed: "true"`). Titles are
`heal: <reason>: <package or version>`.

| reason | when | what the owner decides |
|---|---|---|
| `no-fix` | no fixed version exists | wait, replace the package, or accept the risk with a Suppression (the issue describes it; it never writes one) |
| `major` | the only fixes are in a new major version | whether to take the major, with whatever else it moves |
| `new-package` | the resolution adds or removes a package | whether the new package is acceptable (`check_package` first) |
| `checkov` | the fix needs a Checkov release, or Checkov itself is affected | the Checkov bump, with its adapter, fixtures and goldens (the weekly routine, D64d, can prepare it) |
| `check-failed` | `valvur check` flags a moved version | never take it; choose another version or wait |
| `young-unattested` | the fix is younger than the cooldown without matching provenance | take it now, or let the cooldown pass |
| `resolution-failed` | the recipe cannot resolve the pins, or needs a build | read the log; re-lock by hand |
| `policy-refused` | the policy refused a heal pull request | read the reason; the PR stays open |
| `checks-red` | a heal or release pull request's required checks failed twice on the same plan | fix forward, or close it |
| `release-needs-owner` | commits since the tag are not patch-class, or other machinery changed | cut the release as `docs/RELEASING.md` says |
| `release-stopped` | a tag the heal pushed has no published release (a gate failed, or the owner cancelled) | re-run the release run, or cut the next patch |
| `dependabot-stalled` | a dependency vulnerability Finding outside the Checkov lock has no fix on `main` after half the window | land or fix Dependabot's pull request |

---

### 9. The watchdog (amendment 1, Requirement 15)

`scripts/watchdog.py` reads each workflow's `on.schedule` crons with the repository's
line-based reader (`tests/test_ci_builds_once.py`'s shape: no YAML parser among the
dependencies), and each one's last runs from `GET /repos/{repo}/actions/workflows/{file}/runs
?event=schedule&branch=main`. A workflow is **failed** when its last scheduled run concluded
`failure`, `timed_out` or `startup_failure`, and **overdue** when no scheduled run started
within its longest gap between two cron times plus the margin (D81s). Each finding goes
through `file-issue`, titled `watchdog: <workflow file>`, so a second finding comments and a
pass closes it. `watchdog.yml` runs daily at 06:47 UTC, after the nightly's usual start, with
a checkout that always runs. The nightly's job reads the watchdog's last run by the same
rule, so neither can stop unseen.

### 10. The image, scanned as it ships (amendment 2, Requirement 16)

The image already holds Trivy. The check runs it on the image's own root filesystem:

```
docker run --rm --network none -v <run's database>:/db:ro --entrypoint trivy valvur:dev \
  rootfs --cache-dir /db --skip-db-update --offline-scan --format json --scanners vuln /
```

`scripts/image_gate.py` reads that JSON. A vulnerability with a fixed version blocks unless
`.github/image-accepted.yaml` lists its ID and package with an `expires` date still ahead; one
with no fixed version is listed and does not block. The file is the owner's: nothing
automated writes it, as with every Suppression (Requirement 16.3). It lives under `.github/`,
out of the sdist's top level, which `tests/test_build_hash.py` pins.

- **In `ci.yml`,** a job after "the image, built once", on both architectures, loads the
  run's image and runs the check, with the database from the run's cache. It is not a
  required check until the owner makes it one (§3 of tasks.md).
- **In `release.yml`,** before `promote`, on the staged image.
- **In the nightly,** against the latest published image.
- **For the heal,** its JSON is `observe`'s second input, so `heal` mode can also start
  from an image Finding. Only the lock is healed by R44; an image Finding is escalated, or
  healed by R44.9 when its cause is the base.

### 11. The base-image heal (amendment 3, Requirement 17)

`scripts/base_heal.py plan` reads the Dockerfile's `FROM` lines and, for each, the tag's
`last_updated` from `https://hub.docker.com/v2/repositories/library/<image>/tags/<tag>`. A
tag is **dead** when it has not moved for 30 days. Its replacement is the tag of the same
image and Python minor with the newest Alpine suffix that moved within 30 days, such as
`3.12-alpine3.24` for `3.12-alpine3.22`. `apply` rewrites every place 1.5.4's move rewrote:
the Dockerfile's two stages, the base `check_image_licences.py` diffs against in `ci.yml` and
`release.yml`, the script itself and its test, each pinned by the index digest from `docker
buildx imagetools inspect`, the tag beside it. The pull request carries the image check's
verdict on both images. It runs weekly in `heal.yml`, in `plan`'s grant, and `propose` opens
the pull request. Docker Hub's API, `hub.docker.com`, is named by neither
`src/valvur/egress.py` nor ADR-0027, and the product has no reason to name it. So the build's
own fetch of it, R44.9's measurement, waits for the owner's word (tasks.md §3), under the main
list's stop condition 5; the tests fake it.

### 12. Scanner upgrades that prepare themselves (amendment 4, Requirement 18)

`scanner-upgrade.yml` runs on a Dependabot pull request that moves a Scanner's stage in the
`Dockerfile`, and on nothing else. Its jobs:
1. **`prepare`,** with `contents: read`: `scripts/scanner_upgrade.py` reads which Scanner
   moved and to which version, updates every other pin R47.1 lists, recaptures that
   Scanner's fixtures twice and compares them, runs the Score, and reads the new binary's Go
   toolchain.
2. **`propose`,** in the `heal` environment, pushes the result to the pull request's branch
   as the App, with `Heal-Pin`-style trailers giving each track's delta.

The policy (`heal_policy.py scanner`) lets it merge only when every track is unchanged;
anything else is left for the owner, with the deltas in the body. Package code from the
Scanner runs only in `prepare`, which holds no secret, as D81k requires.

## Data models

### `plan.json`

```json
{
  "schema": 1,
  "made": "2026-10-21T06:41:00Z",
  "tree": "<main's commit>",
  "lock": "requirements-checkov.txt",
  "findings": [
    {"rule": "CVE-2026-111064", "fingerprint": "…", "package": "aiohttp", "version": "3.14.3",
     "fixed_version": "3.14.4", "severity": "high", "advisory_published": "2026-10-19T…Z"}
  ],
  "pins": [
    {"package": "aiohttp", "from": "3.14.3", "to": "3.14.5", "why": "fix",
     "rule": "cooldown", "uploaded": "2026-10-11T…Z"},
    {"package": "certifi", "from": "2026.7.22", "to": "2026.10.19", "why": "fix",
     "rule": "young-attested", "uploaded": "2026-10-20T…Z",
     "publisher": {"kind": "GitHub", "repository": "…", "workflow": "…"}},
    {"package": "yarl", "from": "1.24.5", "to": "1.25.1", "why": "floor of aiohttp 3.14.5",
     "rule": "cooldown", "uploaded": "2026-09-15T…Z"}
  ],
  "escalations": [{"package": "…", "reason": "no-fix", "findings": ["<fingerprint>"]}]
}
```

`rule` is one of `cooldown` or `young-attested`. `why` is `fix` or `floor of <package>
<version>`.

### Trailers

The heal commit:

```
fix: aiohttp 3.14.5 and certifi 2026.10.19 in the Checkov lock, by the heal

Heal-Pin: aiohttp==3.14.5
Heal-Pin: certifi==2026.10.19
Heal-Pin: yarl==1.25.1
Heal-Advisory: CVE-2026-111064 aiohttp published 2026-10-19T…Z
Heal-Run: https://github.com/MaverickHQ/valvur/actions/runs/<id>
```

The release commit carries `Release-Date: <YYYY-MM-DD>` and `Heal-Run:`. These trailers are
what `heal_report.py` reads.

---

## Decisions: D81

Proposed 2026-10-21; D81s to D81v added 2026-10-24. They are accepted with the half of the
spec they serve (tasks.md §0, item 7): those R42 and R43 use on 2026-10-24, the rest when the
owner starts the second half. R42.1 records the dates in the main `tasks.md` §5.

| # | decision | fallback when a measurement disagrees |
|---|---|---|
| D81a | **Scope: the Checkov lock alone.** `uv.lock`, the zizmor lock and the Docker digests stay with Dependabot and R28.2, and the Actions stay with the owner. The heal watches them only for `dependabot-stalled`. | none needed |
| D81b | **The healing window is 48 hours from the advisory's publication.** Only `6-self` uses it. | if the first month's median time to heal is over 24 hours, the cadence shortens; the window never widens without the owner |
| D81c | **`6-self` is the latest `v*` tag reachable from HEAD.** | none |
| D81d | **The cooldown is 7 days**, as `.github/dependabot.yml` has it. | none |
| D81e | **A young version needs 24 hours and the same publisher's attestation** on every distribution. | if R44.1 finds the four 2026-10 fixes unattested, the rule stands; such fixes wait for the cooldown, or the owner, as `young-unattested` |
| D81f | **The envelope** is Requirement 8.1: two files, the App's signed commits, byte-identical to the recipe, no new names, no major, no Checkov, overrides intact. | none |
| D81g | **A patch release is automatic** only when everything since the tag is patch-class (Requirement 9.2) and the only machinery change is the Checkov lock. | `release-needs-owner` |
| D81h | **The security brake is a 12-hour wait timer** in a `release-security` environment, with no reviewer and a notice issue. It amends ADR-0020 and D64(e) for this class, as ADR-0032. | if the owner declines the timer, `release-security` gets the owner as its required reviewer: everything up to that one approval is automatic |
| D81i | **No rehearsal for a heal release** whose only machinery change is the Checkov lock. This amends D62a for this class. | the heal dispatches a rehearsal and waits for its `artifact` jobs, then cancels it at the brake, as `refresh.yml` does (about 31 minutes) |
| D81j | **The identity is a GitHub App, `valvur-heal`**, which the owner creates, plus an SSH key for the heal's tags with the principal `valvur-heal` in `.github/allowed_signers`. Both live in the `heal` environment, deployed from `main` only. Auto-merge uses the workflow's token, as in R28.2. | without the App, pull requests are opened with the workflow's token and must be closed and reopened, as `refresh.yml`'s are. The heal is then not hands-off, and that is recorded |
| D81k | **Package code never runs where a secret is.** Resolution runs with `--no-build`, in jobs that hold no secret and no write permission. | if R44.1 finds a package that needs a build, its job still holds nothing, and the package is named in the plan |
| D81l | **No language model on the path.** The weekly routine (D64d) may work on escalations, under its own limits. | none |
| D81m | **Escalations** follow the table above: one issue each, and each closes itself. | none |
| D81n | **The cadence is every 6 hours** at minute 41, plus a dispatch after each merge the heal sees. | none |
| D81o | **`advisory_published` is an addition** to the dependency vulnerability Finding, kept out of the Fingerprint, with the Score unchanged. | if the contract tests or the Score refuse it, the judge reads `PublishedDate` from Trivy's output in `raw/`, and the product is unchanged |
| D81p | **Dependabot is excluded from the Checkov recipe's files** by `exclude-paths` on its `pip` and `uv` entries, because both wrote the lock (#231 and #232). | if Dependabot ignores `exclude-paths` for either updater, the three files move to `locks/checkov/`, a directory no Dependabot entry names |
| D81q | **Checkov's new versions arrive by the recipe, for the owner.** On the first heal run of a Monday, a newer Checkov past the cooldown is re-locked by the recipe as one pull request, which the policy leaves for the owner because Checkov moved. It replaces what Dependabot did. | none |
| D81r | **Time to heal is the health measure**, with a target under 48 hours, from `heal_report.py`. | none |
| D81s | **A watchdog over the scheduled workflows** (amendment 1, 2026-10-24): daily, with a checkout that always runs. A workflow is overdue past its longest cron gap plus a margin of twice the longest start delay R42.5 measures, and never less than 12 hours. The nightly watches the watchdog. | if the Actions API cannot filter runs by `event`, it reads every run and filters itself |
| D81t | **The image is scanned with its own Trivy** over its root filesystem, with no network and the run's database (amendment 2, 2026-10-24). Accepted risks are in `.github/image-accepted.yaml`, each with an expiry, written by the owner alone. It is not a required check until the owner makes it one. | if R43.4's positive control misses any of its five, the check runs `trivy image` on the saved tarball instead; if that misses too, Syft's SBOM of the image through OSV-Scanner |
| D81u | **A base tag unmoved for 30 days is dead** (amendment 3, 2026-10-24), and is replaced by the same image and Python minor with the newest Alpine suffix that moved within 30 days, pinned by digest. The Python minor is never changed. | if Docker Hub's API stops giving `last_updated`, the age is read from the image configuration's `created` |
| D81v | **A Scanner upgrade lands by itself only when every Score track is unchanged** (amendment 4, 2026-10-24). Anything else waits for the owner with the deltas. | if a Scanner's fixtures do not recapture deterministically, its pull requests always wait for the owner, with the fixture named |

---

## Error handling

| what fails | what happens |
|---|---|
| `valvur update`, or a Scan Run that is incomplete or `inconclusive` | `observe` fails and is filed (`file-issue`); nothing changes. A stale database is never planned from |
| PyPI cannot be reached | `plan` fails and is filed; the next run tries again |
| the recipe cannot resolve | `resolution-failed`, with the log in the issue |
| a heal pull request's checks are red | auto-merge waits; the next run rebuilds it from `main`; red twice on the same plan is `checks-red` |
| the policy refuses | `policy-refused`; the pull request stays open |
| the CHANGELOG moved on `main` and conflicts | the next run rebuilds the branch from `main`'s head |
| a new advisory while a release is pending | heal mode comes first; the release waits for a clean `main` |
| `release.yml` refuses the security checks | the release stops in `verify`, before anything is built; the next run escalates `release-stopped` |
| the self-scan gate, the Score or `artifact` fails | the release stops before `promote`, leaving only `-candidate` (ADR-0020); `release-stopped` |
| the owner cancels during the timer | nothing is published; `release-stopped`, as the owner's decision, with no retry |
| two runs overlap | `concurrency: heal` queues the second |

---

## Security of the automation

| threat | what stops it |
|---|---|
| a malicious release of a dependency | the 7-day cooldown by default; a younger version needs 24 hours and its publisher's attestation; `valvur check` and its malicious list; the pull request's self-scan; the 12-hour timer before users get it |
| a compromised publisher workflow, which yields a valid attestation (Ultralytics, 2024) | the 24-hour minimum, the timer and the owner's veto. The residual risk is stated here and in `SECURITY.md`; it is why D81e is not the attestation alone |
| package code run during resolution | `--no-build`, and resolution only in jobs with no secret and no write token (D81k) |
| a stolen App key | the App can push branches and open pull requests. It cannot change workflows, merge outside the envelope, or make a release tag verify. The key exists only in `heal`, deployed from `main` only |
| a stolen tag-signing key | a tag must sit on `main` and pass `release.yml`'s security-patch checks again: patch plus one, patch-class commits, Checkov-lock machinery only. Then every gate runs, and the notice and the timer give the owner 12 hours |
| a spoofed author | the policy checks the pull request's author and each commit's author, committer and verified signature. Fork pull requests never reach a secret |
| template injection | no expression inside `run:`, values passed through `env:`; zizmor at the auditor persona |
| the heal triggering itself | `schedule` and `workflow_dispatch` only, a dispatch only after a merge it saw, and one concurrency group |
| a poisoned advisory that pushes an upgrade | the target passes the same vetting: an existing package, the same major, the cooldown or its provenance |
| the veto lost silently | the notice issue when the timer starts; `RELEASING.md` documents cancelling; the environment is visible in Settings |

---

## Testing strategy

- **Through public interfaces**, as the main `tasks.md` §3 requires: each script's `main()`
  with its arguments and stdin, as `tests/test_dependabot_auto_merge.py` tests R28.2.
- **Only two boundaries are faked.** The network goes through `tests/fake_registry.py`,
  extended with PyPI's JSON and integrity endpoints. The container runtime goes through
  `LocalRuntime`, for R43.1.
- **Resolution is real and hermetic.** The tests build small wheels in `tmp_path`, then run
  the recipe through its pass-through with `--no-index --find-links <dir>`. uv and git are
  real.
- **The workflows' shape is tested:**
  - triggers;
  - top-level and per-job permissions;
  - pinned actions;
  - which job names which environment;
  - that only `tag` reads `HEAL_TAG_KEY`;
  - that `promote`'s environment is the expression;
  - that no `run:` holds an expression.
- **zizmor** runs over `.github/` at the auditor persona, as R28.2 did.
- **The Score:** R43.1 runs `scripts/eval.py --tracks … --compare` for the tracks Trivy's and
  OSV-Scanner's Findings reach.
- **Live proofs:**
  - R44.8 is the first real heal, or a dispatch with `dry_run` against `v1.5.3`'s tree;
  - R45.5 is a rehearsal with `security_patch`, cancelled at the timer, then the first real
    security release.
- **New tests go in new files.** The constraint suite stays at 54.

---

## Alternatives considered

- **Keep moving `SELF_PIN` by hand.** That is the incident, twice in three weeks.
- **A frozen database for the acceptance set**, pinned through `VALVUR_DB_REPOSITORY` and
  `VALVUR_OSV_URL`. It is deterministic, but the nightly would then say nothing about today's
  advisories, and moving the snapshot is one more manual step. The window keeps the nightly
  strict on code and current on dependencies.
- **A first-seen ledger** in place of the advisory's date. It is state that a cache eviction
  can lose, and a second source of truth.
- **Renovate, or Dependabot configured harder.** Both read another advisory database through
  another model of the manifests, which is root cause 2. Renovate would also be a third-party
  App with wide permissions.
- **A maintenance branch per minor version** (`maint/1.5`). It would ship only the fix, but
  `release.yml` requires the tag to sit on `main` (28.0.2), and widening that adds more risk
  than the patch-class rule does. It stays the owner's option in a `release-needs-owner`
  issue.
- **Keyless tags with gitsign.** There would be no key to steal, but verification would move
  away from `git tag -v` and `allowed_signers`, the release's root of trust. It can be
  revisited later, as a backlog item.
- **Auto-merge with the App's token,** so that `main`'s push checks run. That would give the
  App merge power. With the workflow's token, as in R28.2, `release.yml` reads CI's verdict on
  the squash commit as `unreadable` and runs the suites again, R26.3's path, which adds about
  10 minutes.
- **An agent in the loop.** Rejected for the hands-off path (D81l).

---

## ADR-0032, as R45.1 writes it

> **Security patches promote after a delay the owner can cancel.**
>
> *Context:* ADR-0020 put the owner's approval after the evidence and before the
> irreversible step, and D64(e) kept the signed tag and the brake with the owner. On
> 2026-10-20 four advisories reached the Checkov lock with fixes on PyPI. The published image
> stayed vulnerable for as long as each step waited for the owner.
>
> *Decision:* a release whose tag the heal signed, which `release.yml` verifies as a patch
> release of patch-class commits whose only machinery change is the Checkov lock, promotes
> in the `release-security` environment. That environment has a 12-hour wait timer and no
> reviewer. A notice issue names the time, and the owner can cancel the run until then. Every
> other release keeps the `release` environment and its reviewer, and every gate runs for
> both.
>
> *Consequences:* the owner's veto becomes passive for one narrow class of release. A
> stolen heal key can at most start a patch release of `main` that every gate and the timer
> still judge. D62a's rehearsal is skipped for this class, because the run's own `artifact`
> validates before `promote`.
>
> *Alternatives:* the owner's approval kept (D81h's fallback); a maintenance branch; keyless
> tags.

---

## What it costs

- **Runner time.** Four runs a day at about 15 minutes each when nothing changed (the image
  build with its cache, the update, two scans): about an hour of runner time a day, which is
  free for a public repository.
- **A heal** adds one pull request's required checks, about 40 minutes.
- **A security release** adds one more pull request and the release run, about 50 minutes,
  plus the timer.
