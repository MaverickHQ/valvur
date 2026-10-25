# The weekly maintenance routine

valvur keeps itself current through scheduled workflows, Dependabot and the monthly
refresh. What none of them does is look across the week and fix what broke. This is the
prompt and procedure of a scheduled Claude Code cloud routine that does (D64d). It reads
the week's failed scheduled runs, the open issues and the stalled Dependabot pull
requests, and fixes what it can on a branch, with a pull request, for the owner to land.

It never lands anything. Landing on `main`, the signed tag and the approval at the
release's brake are the owner's by design (D64e, ADR-0020). Creating the routine, and
its monthly cap, are the owner's too (`tasks.md` §8).

## The prompt

The routine runs this, weekly, in a fresh cloud session with this repository:

```text
You are valvur's weekly maintenance routine. Read CLAUDE.md, then docs/MAINTENANCE.md,
and follow its procedure for the seven days to now.

Read, through the GitHub connector: the failed scheduled runs of the workflows the
procedure names, the open issues, and the open Dependabot pull requests older than
seven days or with a failing check.

For each, find the cause from the evidence: the run's log, the issue's runs, the pull
request's checks. Fix what you can, test-first as CLAUDE.md says, on one branch named
maintenance/<date>, with one pull request that lists each item: fixed, with the commit,
or left, with why. Gate every commit with scripts/verify.sh. When nothing needs
fixing, open no pull request, and say so in your final message.

Never push to `main`, never tag, never approve a review or the release's brake, never
merge or enable auto-merge, and never close an issue whose cause you have not seen
pass. Never suppress, skip or disable a test, a finding or a check to make a run green:
a finding that disappeared is not a vulnerability that was fixed. A change that would
cross CLAUDE.md section 10, or that you cannot test, is left in the pull request's list
for the owner with what it needs.

In this cloud session, `.kiro/specs/valvur/tasks.md` decision D61 says how to reach GitHub
(`gh` over REST, not GraphQL) and how to build and run the image. An item that an open pull
request already addresses, such as a Scanner update a `build/` branch carries, is listed as
covered by that pull request, never fixed a second time.
```

The routine was created on 2026-10-25 as `valvur weekly maintenance (D64d)`, Thursdays at
06:00 UTC, with this prompt. Its last paragraph came from running two cloud slots at once
for 1.6.0: without it, the routine would redo a Scanner update that a build branch already
carries.

## The procedure

1. **The week's failed scheduled runs.** These workflows run on a schedule, and each
   files one issue on a failure and closes it when a later run passes (R28.3):
   `acceptance.yml` (daily), `fuzz.yml` (nightly), `index.yml` (daily, two jobs),
   `corpus.yml`, `eval.yml`, `retention.yml` and `refresh.yml` (Mondays; the refresh
   acts on the first), `scorecard.yml` (Tuesdays), `mutation.yml` (Wednesdays; a fall
   is fixed by the test that notices a surviving hunk, never by lowering the baseline)
   and `watchdog.yml` (daily), which files `watchdog: <file>` for any of them that failed
   or stopped running (R42.5).
   For each failed run, read its log,
   and tell a cause in this repository from one outside it: a host down, a runner lost.
   The first is fixed on the branch. The second is listed, since the next run will say
   whether it passed. A failure that the base branch shares is one item, not one per run.
2. **The open issues.** An issue a scheduled run filed is closed by its next green run.
   One still open after a green run means the closing step did not run, and it is
   listed. Any other issue is read for a fix that is small, local and testable. If it
   has one, the fix goes on the branch; if not, the issue is listed for the owner.
3. **The stalled Dependabot pull requests.** Open over seven days, or red. Dependabot's
   patch or minor updates of dependency files merge themselves once their checks pass
   (R28.2's Dependabot workflow); the rest stay the owner's to land. A red one
   is usually a version pinned twice, as when a Scanner's pin moves without its adapter.
   That is fixed on the branch as the owner fixed Checkov 3.3.19 in #122: the adapter's
   version, the fixtures, the image. The Dependabot pull request is left for the owner
   to close once that lands.
4. **One pull request.** Base `main`, title `chore: maintenance, <date>`. Its body lists
   every item read, with its outcome. Its checks are the repository's required checks.
   The routine stops when it is open, or when nothing needed fixing.

## A Scanner's upgrade, completed

When a Scanner's stage moves (its `FROM` in the Dockerfile, Opengrep's release `ARG`s, or its
hash-locked requirements), its other pins move with it, and its golden is recaptured from the
new binary (R47.2, R47.3):

1. Build the image from the moved stage (`docker buildx bake`, or `scripts/cloud_image.py` in
   a cloud session).
2. `uv run python scripts/scanner_upgrade.py <scanner> <old> <new> --recapture`. It moves the
   adapter's `VERSION`, the golden's pin in `tests/conftest.py`, `docs/PROTOCOL.md`'s row and,
   for Opengrep, `scripts/verify-opengrep.sh`. Then it captures the Scanner's report twice,
   with the adapter's `offline` command in one Scan Container fed a Snapshot of its fixture:
   `broken-repo` for Opengrep, Checkov and OSV-Scanner (after OSV's offline databases); its
   `package-lock.json` and `requirements.txt` for Trivy; its `requirements.txt` for Syft;
   `workflows-repo` for zizmor. Gitleaks has no golden.
3. The two captures must agree, apart from what R47.1 measured differs on every run: Trivy's
   `ReportID` and `CreatedAt`, Syft's `serialNumber` and `metadata.timestamp`, and the order
   of Checkov's failed checks. Then the first is the new golden. Otherwise nothing is
   written, the exit is 3, and the upgrade is the owner's.
4. Review the golden's diff, and run the Score (`scripts/eval.py --compare
   tests/eval/baseline.json`).

## What it costs

One session a week, bounded by the cap the owner sets when creating the routine (§8).
The routine runs no `claude -p` agent of its own, so D36's caps on agent runs are not
spent by it.
