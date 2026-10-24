# The self-healing supply chain: requirements

**Status:** proposed 2026-10-21, for the owner's approval · **Phases:** R42 to R46, in
[tasks.md](tasks.md) · **Decisions:** D81, in [design.md](design.md)

This spec extends [the main spec](../valvur/requirements.md) and uses
[CONTEXT.md](../../../CONTEXT.md)'s terms exactly. It changes how valvur's own repository
keeps its dependencies current and how a security patch is released. The product gains
one field (Requirement 3). Nothing here lets valvur change a Workspace: the
human-in-the-loop property for users (`CLAUDE.md` §4, ADR-0009) is untouched. This is the
repository's own upkeep, as Phase R28 was.

**IDs.** Requirements here are numbered 1 to 14, as Kiro numbers them, and their criteria
`1.1`, `1.2` and so on. `scripts/check_traceability.py` reads every file under `.kiro` for
the main spec's requirement IDs and fails on one that the main spec does not define. So this
file names none of its own. When a task builds a criterion, it adds that criterion to
`.kiro/specs/valvur/requirements.md` as the next ID of a new section, N5 *Self-maintenance*,
in the same commit as the test that cites it, as the main `tasks.md` §3 requires. It then
writes that ID in this file's last table.

---

## Introduction

### The incident this answers

On 2026-10-19 the nightly `acceptance` run passed at `1434c44`. On 2026-10-20 and
2026-10-21 it failed at the same commit (#234). Only `6-self` failed. It had four blocking
Findings, all in `requirements-checkov.txt` of the tree `SELF_PIN` names, 1.2.0's
`d0417c4`:

| Advisory | Package | Severity | Fixed in |
|---|---|---|---|
| CVE-2026-111064 (GHSA-5wr8-gcqf-gqf3) | aiohttp 3.14.3 | high | 3.14.4 |
| CVE-2026-111066 (GHSA-9xw5-w5jj-pvcg) | aiohttp 3.14.3 | high | 3.14.4 |
| GHSA-2g87-pp6c-29x5 | aiohttp 3.14.3 | high | 3.14.4 |
| GHSA-6q48-6c7w-9gw2 | certifi 2026.7.22 | critical | 2026.10.19 |

**Found after this table was written** (added 2026-10-24):

| Advisory | Package | Severity | Fixed in | How it was found |
|---|---|---|---|---|
| CVE-2026-114145 (GHSA-83vg-56qc-22m7) | gitpython 3.1.62 | high | 3.2.1 | published 2026-10-22; the lock fix's own pull request, #235, by its self-scan gate (N2.5) on 2026-10-23 |
| CVE-2026-111065 (GHSA-6cjc-53gc-5rqm) | aiohttp 3.14.3 | medium | 3.14.4 | published 2026-10-20; raised as a Dependabot alert on 2026-10-22 |
| CVE-2026-111748 (GHSA-f9xw-jh8m-3mwq) | aiohttp 3.14.3 | medium | 3.14.4 | the same |
| CVE-2026-111750 (GHSA-pqxq-w44r-73xw) | aiohttp 3.14.3 | medium | 3.14.4 | the same |
| CVE-2026-111749 (GHSA-gx76-c99x-2c96) | aiohttp 3.14.3 | low | 3.14.4 | the same |

The aiohttp four are medium and low, so they would not have blocked `6-self`; the same
upgrade to 3.14.5 fixes them. GitPython's would have, once published. 1.5.4 ships all ten
fixes, with GHSA-494j-54xm-rwp3 (CVE-2026-111063, low), which the same aiohttp release fixes.

- **`main` and the published 1.5.3 image have the same versions.** The fixes were on PyPI
  before the first red night: aiohttp 3.14.5 since 2026-10-11, certifi 2026.10.19 since
  2026-10-20.
- **Dependabot did not fix the lock.**
  - Its aiohttp security update went to the `uv` updater. That updater failed with
    "Expected lockfile to change!", because aiohttp is in the Checkov lock, not in
    `uv.lock`.
  - Both of Dependabot's updaters also write the Checkov lock without its recipe. They
    leave out `--override` and `--universal`, so asteval goes back to 1.0.6, which has two
    sandbox-escape advisories, and the environment markers are dropped. #232 was made by
    the `pip` updater and #231 by the `uv` updater.
  - `scripts/dependabot_auto_merge.py` finds both eligible. Only their red checks keep them
    from merging.
- **It is the second time in three weeks.** urllib3's advisories of 2026-09-30 moved
  `SELF_PIN` from `eb3a199` to `d0417c4`.

### Why it happened

1. **The nightly judges a frozen tree against a database that moves every day.** A pinned
   tree ages as its dependencies do, as the comment on `SELF_PIN` says. Every new advisory
   against that tree turns the nightly red, whatever valvur's code does.
2. **The gate and the fixer read different data.** The gate reads valvur's own Trivy and
   OSV databases. Dependabot reads GitHub's advisory database and sorts alerts by its own
   model of manifests, and that model does not know the Checkov lock's recipe.
3. **Three things write one file:** Dependabot's `pip` updater, its `uv` updater, and
   `scripts/lock-checkov.sh`.
4. **Every step after detection waits for the owner:** the re-lock, the release (the signed
   tag and the brake at `promote`, ADR-0020 and D64e) and the pin.
5. **The acceptance set is the Linux half of every phase exit.** So a red `6-self` stops
   the build as well.

### The goal

Suppose a new advisory reaches a package in the Checkov lock and a fixed version exists.
Then the fix lands on `main` within hours and ships in a published release within the
**healing window**: 48 hours from the advisory's publication. The owner does nothing.

The nightly goes red only when that failed. The owner hears only about decisions that are
theirs:

- no fix exists;
- the fix needs a major version, a new package or a Checkov release;
- a young fix cannot show where it came from;
- a check fails;
- the policy refuses;
- the release gate fails.

### Not goals

- **No language model on the path.** Re-locking is mechanical, and an agent reading
  advisories, release notes and pull requests is a prompt-injection surface with cheaper
  ways to clear a Finding than fixing it.
- **Nothing automated ever writes a Suppression, an override or a scan configuration.**
  Accepting a risk is the owner's.
- **`uv.lock`, the Docker digests, the zizmor lock and the Actions stay where they are.**
  The first three stay with Dependabot and R28.2's auto-merge, and the Actions with the
  owner. The heal escalates any of them only when they stall (Requirement 11).
- **Zero incidents is not promised.** The mechanical case heals itself, and every other case
  reaches the owner once, as a decision.

---

## Requirements

### Requirement 1: The nightly scans the latest release

**User Story:** As the owner, I want the nightly self-scan to judge the latest release, so
that it reports on what users run, not on a tree I pinned by hand.

#### Acceptance Criteria

1. WHEN `scripts/acceptance.py` generates `6-self` THEN it SHALL archive the newest tag
   matching `v[0-9]*` reachable from HEAD, found as `refresh.yml` finds it
   (`git describe --tags --abbrev=0 --match 'v[0-9]*'`).
2. IF no such tag is reachable THEN generation SHALL fail and say why. It SHALL NOT fall back
   to a fixed commit.
3. The report SHALL name the tag `6-self` scanned and its commit.
4. `SELF_PIN` SHALL be removed, and a test SHALL refuse a commit hard-coded for `6-self`.

### Requirement 2: A healing window for advisories

**User Story:** As the owner, I want a dependency advisory younger than the healing window
to be reported without failing the nightly, so that the nightly is red only when
self-healing failed.

#### Acceptance Criteria

1. WHEN a repository's `expected.toml` sets a healing window, and an active dependency
   vulnerability Finding's advisory was published less than that window before the Scan
   Run, THEN the judge SHALL list it as `healing`, with its age, and SHALL NOT count it as
   blocking.
2. WHEN the advisory is older than the window THEN the Finding SHALL block, as it does today.
3. IF the Finding has no publication date, or one that cannot be read, THEN it SHALL block.
   Missing data never widens the window.
4. A Finding whose advisory is a `MAL-` entry, a package published as malicious, SHALL never
   be `healing`.
5. Every other Finding Class SHALL be judged as today: any unexpected Finding at high or
   critical blocks.
6. Only `6-self`'s `expected.toml` SHALL set a window: 48 hours (D81b).
7. The report SHALL count `healing` Findings in a column of their own.

### Requirement 3: An advisory's publication date on its Finding

**User Story:** As the nightly's judge, as the heal, and as a user reading `findings.json`,
I want each dependency vulnerability Finding to carry its advisory's publication date, so
that the advisory's age can be judged from the Results Folder alone.

#### Acceptance Criteria

1. WHEN Trivy reports a vulnerability with a `PublishedDate` THEN the Finding's dependency
   SHALL carry it as `advisory_published`, an ISO 8601 date-time in UTC.
2. WHEN OSV-Scanner reports one with `published` THEN the same SHALL hold. When both Scanners
   report the Finding, the earlier date SHALL be kept.
3. WHEN neither Scanner gives a date THEN the field SHALL be empty.
4. The field SHALL NOT feed the Fingerprint (ADR-0003). It SHALL be an addition to
   `findings.json`, documented where the rest of that schema is.
5. Every track of the Score SHALL be unchanged (`scripts/eval.py --compare`).

### Requirement 4: One writer for the Checkov lock

**User Story:** As the owner, I want exactly one recipe to write `requirements-checkov.txt`,
so that no lock made any other way can reach `main`.

#### Acceptance Criteria

1. Dependabot's `pip` and `uv` updates SHALL leave `requirements-checkov.in`,
   `requirements-checkov.overrides` and `requirements-checkov.txt` alone, and a test SHALL
   hold that.
2. `scripts/dependabot_auto_merge.py` SHALL leave for the owner any pull request that
   changes those files.
3. `scripts/lock-checkov.sh` SHALL pass any extra arguments to `uv pip compile` after its
   own, so that the heal re-locks with the same recipe.
4. The recipe SHALL name the uv version it runs with, and CI and the heal SHALL run that
   version.
5. WHEN a pull request changes `requirements-checkov.*` THEN a check SHALL run the recipe
   again with no upgrades. It SHALL fail if the lock it writes differs by a byte from the
   committed one.
6. The recipe SHALL resolve without building a source distribution (`--no-build`). IF a
   package needs a build to resolve THEN the check SHALL name it (R44.1 measures this).

### Requirement 5: A heal plan made from valvur's own data

**User Story:** As the owner, I want the heal to act on what valvur's gate sees, from
valvur's own databases, so that the gate never knows about an advisory the fixer has not
seen.

#### Acceptance Criteria

1. WHEN the heal runs THEN it SHALL build the image from `main`, run `valvur update`, and
   scan `main`'s tree with the gate's Profile, `full`. It SHALL plan from that Scan Run's
   `findings.json`.
2. The plan SHALL cover every active dependency vulnerability Finding at
   `requirements-checkov.txt`, at any severity, because the release gate fails on any
   (`--fail-on any`).
3. For each such package, the target SHALL fix every one of the package's Findings: at least
   the highest `fixed_version` among them, as `remediation.py` takes it. It SHALL be in the
   same major version and not yanked. Among such versions it SHALL be:
   - the newest one past the cooldown (7 days, D81d), when one exists;
   - otherwise the lowest one, and only under Requirement 6.
4. The plan SHALL include every other package the resolution must move, such as yarl's floor
   under aiohttp 3.14.5. Each SHALL be chosen by the same rule.
5. Every moved version SHALL pass `valvur check` against today's Name Index and malicious
   list.
6. The plan SHALL escalate a package, and not heal it, when any of these holds:
   - no fixed version exists;
   - the fix needs a major version;
   - the resolution would add or remove a package;
   - the package is Checkov itself, whose release moves its adapter, fixtures and goldens;
   - a moved version fails criterion 5;
   - a young version fails Requirement 6.
7. The plan SHALL be one JSON document, written before anything changes. It SHALL name each
   Finding, each target and the rule that chose it.
8. WHEN the plan is empty THEN the run SHALL change nothing and open nothing.

### Requirement 6: A young version is trusted only by its provenance

**User Story:** As the owner, I want a fix younger than the cooldown to land without me only
when PyPI shows it came from where the version it replaces came from, so that speed never
buys a compromised release.

#### Acceptance Criteria

1. WHEN a target is younger than the cooldown THEN it SHALL heal only if both of these hold:
   - it is at least 24 hours old (D81e);
   - every one of its distributions has a PyPI provenance attestation whose publisher, the
     repository and the workflow, is the publisher of the version it replaces.
2. IF the replaced version has no attestation, or any of the young version's distributions
   has none or a different publisher, THEN the package SHALL wait for the cooldown or the
   owner, escalated as `young-unattested`.
3. The plan SHALL record, for each young version, its upload time and the publisher read
   from each attestation.

### Requirement 7: A heal proposal anyone can check

**User Story:** As the owner, I want each heal to arrive as a signed pull request that carries
its own evidence, so that checking it needs nothing but the pull request.

#### Acceptance Criteria

1. WHEN the plan is not empty THEN the heal SHALL re-lock with `scripts/lock-checkov.sh`, with
   every moved package pinned exactly. It SHALL refuse its own result if any package moved
   that the plan does not name.
2. It SHALL add one `### Security` item per package under the CHANGELOG's `[Unreleased]`. The
   item names the advisories and the two versions.
3. It SHALL commit on a branch `heal/<UTC date>-<short tree hash>` through GitHub's
   `createCommitOnBranch`, which GitHub signs. The commit SHALL carry:
   - one `Heal-Pin: <package>==<version>` trailer per moved package;
   - one `Heal-Advisory:` trailer per Finding;
   - a `Heal-Run:` trailer naming the run.
4. It SHALL open the pull request with the heal App's token, so that the required checks run.
   A pull request opened with the workflow's token starts none.
5. IF a heal pull request is already open THEN the run SHALL rebuild that branch from
   `main`'s head with the new plan. It SHALL NOT open a second.
6. The pull request's body SHALL carry the plan: each advisory and its severity, each version
   chosen and why, and the evidence for it (the cooldown age, or the attestation).

### Requirement 8: A heal merges itself only inside its envelope

**User Story:** As the owner, I want a heal pull request to merge without me only when a check
I trust has proved it is exactly what the recipe makes, so that the automation can move
versions forward but can never change what valvur accepts.

#### Acceptance Criteria

1. WHEN a pull request's author is the heal App THEN a policy run from the base branch SHALL
   turn on auto-merge, by squash, only if all of these hold:
   1. every changed file is `requirements-checkov.txt` or `CHANGELOG.md`;
   2. every commit was made by the App, is signed by GitHub, and carries `Heal-Pin` trailers;
   3. the recipe, run on the base branch's lock with exactly those pins, writes a lock
      byte-identical to the pull request's;
   4. no package was added or removed, no major version moved, Checkov did not move, and
      every override holds;
   5. the CHANGELOG's diff only adds lines, and only under `[Unreleased]`.
2. The policy SHALL never check out or run the pull request's code. It SHALL read the pull
   request's lock as data.
3. Package resolution SHALL run in a job that holds no secret and no write permission. The job
   that turns on auto-merge SHALL run no package code.
4. WHEN a later push no longer qualifies THEN auto-merge SHALL be turned off, as R28.2's
   workflow does.
5. GitHub SHALL merge only once every required check passes, the self-scan gate on the pull
   request's tree among them.
6. IF the policy refuses THEN the pull request SHALL stay open, and the refusal SHALL be
   escalated as `policy-refused`.

### Requirement 9: A security patch prepares and tags itself

**User Story:** As the owner, I want a release of the heal to be prepared, landed and tagged
without me when nothing else in it needs my judgement, so that users get the fix within the
window.

#### Acceptance Criteria

1. WHEN the latest release's tree has an active dependency vulnerability Finding that `main`'s
   tree does not, and a heal commit since the tag removed it, THEN the heal SHALL prepare the
   next patch release.
2. It SHALL go ahead only when every commit since the tag is one of these:
   - a heal commit;
   - a Dependabot update merged by R28.2's workflow;
   - a Conventional Commit of type `fix`, `docs`, `test`, `chore`, `ci`, `build`,
     `refactor`, `perf` or `style`, without `!`.

   Otherwise it SHALL escalate as `release-needs-owner`. A feature or a breaking change makes
   the release minor or major, which is the owner's choice.
3. It SHALL go ahead only when `prepare_release.py`'s first line names
   `requirements-checkov.txt` as the only release machinery changed since the tag.
   Otherwise it SHALL escalate as `release-needs-owner`.
4. It SHALL run `prepare_release.py` at the latest release's patch plus one. The CHANGELOG's
   opening comes from a fixed template. The heal SHALL restate the result as a signed commit
   on `release/vX.Y.Z` and open the pull request with the App's token. The release policy
   SHALL turn on auto-merge only if `prepare_release.py`, run again on the base branch,
   reproduces the pull request's tree.
5. WHEN the release pull request has merged THEN the heal SHALL make an annotated tag
   `vX.Y.Z` on the merged commit, sign it with the heal's key, and push it with the App's
   token, so that `release.yml` runs.
6. IF the tag exists already THEN the heal SHALL NOT tag. It SHALL escalate as
   `release-gate-failed` when no release of that version was published.
7. Nothing in the heal SHALL publish. Publishing stays `release.yml`'s.

### Requirement 10: The brake for a security patch is a delay the owner can cancel

**User Story:** As the owner, I want a security patch to promote after a delay I can cancel,
rather than after my approval, so that I keep a veto without having to act.

#### Acceptance Criteria

1. WHEN `release.yml` verifies a tag signed by the heal's principal THEN it SHALL check
   criteria 9.2 and 9.3 again, and that the version is the previous tag's patch plus one. It
   SHALL stop the release, naming the check, if any fails.
2. WHEN all hold THEN `promote` SHALL run in the `release-security` environment: a wait
   timer (12 hours, D81h) and no required reviewer. Every other release SHALL keep the
   `release` environment and its reviewer.
3. WHEN the timer starts THEN one issue SHALL name:
   - the version;
   - the advisories;
   - the run;
   - the time it promotes unless the owner cancels the run.
4. Every other gate SHALL run unchanged: CI's verdict, the self-scan gate on the tree and on
   the artifact (N2.5), the Score (N4.3), the signature and the attestation.
5. A tag signed by a key that `.github/allowed_signers` does not name SHALL be refused, as
   today.
6. The decision SHALL be recorded as ADR-0032. It amends ADR-0020 and D64(e) for this class
   of release only.

### Requirement 11: Escalations are few, single, and close themselves

**User Story:** As the owner, I want each thing the heal cannot do to reach me once, as one
issue that closes itself when its cause has passed, so that my queue holds decisions and not
noise.

#### Acceptance Criteria

1. WHEN the heal cannot heal or release THEN it SHALL open one issue per package and reason,
   titled from them. At each later run it SHALL comment on that issue with any new evidence,
   and it SHALL never open a second.
2. The reasons SHALL be the closed list in design.md's escalation table, and a test SHALL hold
   the list.
3. WHEN a later run finds the cause gone THEN it SHALL close the issue with a comment naming
   that run, as R28.3's issues do.
4. An issue for `no-fix` SHALL describe the Suppression the owner could write: its
   Fingerprint, what it accepts, and an expiry. It SHALL NOT write it.
5. A dependency vulnerability Finding outside the Checkov lock SHALL be escalated as
   `dependabot-stalled` once half the healing window has passed without a fix on `main`.
6. WHEN the heal's own machinery breaks THEN its run SHALL fail and be filed as the scheduled
   workflows' failures are (`.github/actions/file-issue`).

### Requirement 12: The automation is safe to leave running

**User Story:** As the owner, I want the heal to hold no more power than it uses, and to hold
its secrets only where no package code runs, so that a compromised dependency or a stolen key
buys an attacker as little as possible.

#### Acceptance Criteria

1. The heal App SHALL be installed on this repository only. Its permissions SHALL be Contents
   and Pull requests write and Metadata read, and nothing else: no Workflows, Administration,
   Secrets or Actions.
2. The App's private key and the heal's tag-signing key SHALL live in the `heal` environment,
   whose deployment branches are `main` alone. A job that resolves packages or scans SHALL NOT
   use that environment.
3. The heal's workflows SHALL run on `schedule`, `workflow_dispatch` and `pull_request` only,
   never `pull_request_target` or `workflow_run`. Their actions SHALL be pinned by SHA, their
   top-level `permissions` SHALL be `{}`, and zizmor SHALL find nothing, at the auditor
   persona too.
4. No expression from an event or a pull request SHALL be written into a `run:` script.
5. The heal SHALL write `requirements-checkov.txt`, `CHANGELOG.md`, the files
   `prepare_release.py` writes, `heal/` and `release/` branches, `v*` tags and issues, and
   nothing else.
6. Only the job that tags SHALL read the tag-signing key, and a test SHALL hold that.

### Requirement 13: Time to heal is measured

**User Story:** As the owner, I want to know how long each advisory took from publication to
a published fix, so that the window is a measured target and not a hope.

#### Acceptance Criteria

1. Each heal pull request and each security release SHALL record the advisory's publication
   time, when the heal opened its pull request, when that pull request merged, and when the
   release was promoted.
2. `scripts/heal_report.py` SHALL compute, from GitHub's API alone, each advisory's time from
   publication to promotion over a month, against the 48-hour target.
3. The first live heal and the first live security release SHALL each be recorded with their
   run IDs.

### Requirement 14: The build runs this spec

**User Story:** As the owner, I want the unattended build and its resuming to find this spec's
tasks, so that it runs as every other phase does.

#### Acceptance Criteria

1. `scripts/build_status.py` SHALL read every `.kiro/specs/*/tasks.md`, the main list first.
   Its shape check SHALL read each of them.
2. `scripts/acceptance.py`'s `ticked()` SHALL read them too, so that an `until` naming a task
   here resolves.
3. The main `tasks.md` SHALL name this spec in its header and in its §5 and §6.

---

## Where each criterion is defined in the main spec

Filled by the task that builds each criterion (main `tasks.md` §3), in the commit whose test
cites it.

| criterion here | main spec ID | task |
|---|---|---|
| 1.1 to 1.4 | | R43.2 |
| 2.1 to 2.7 | | R43.3 |
| 3.1 to 3.5 | | R43.1 |
| 4.1 to 4.6 | | R42.3, R42.4 |
| 5.1 to 5.8, 6.1 to 6.3 | | R44.2 |
| 7.1 to 7.6 | | R44.3 |
| 8.1 to 8.6 | | R44.4, R44.6 |
| 9.1 to 9.7 | | R45.2, R45.4 |
| 10.1 to 10.6 | | R45.1, R45.3 |
| 11.1 to 11.6 | | R44.5 |
| 12.1 to 12.6 | | R44.6, R45.4 |
| 13.1 to 13.3 | | R46.1 |
| 14.1 to 14.3 | | R42.1 |
