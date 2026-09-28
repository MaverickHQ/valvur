# valvur 1.0.0 (worktree build) tested from Claude Code on occams-test-lab — 2026-09-27

**Second gate, one day after the first.** The same participant (a Claude Code
agent, Claude Fable 5.1, desktop app), the same project, the build the author
wired into the project's `.mcp.json`: `uv run --project
~/security-scanner-worktrees/second-session valvur-mcp` at commit `23be2e2`
(version 1.0.0, "release in progress"), with `VALVUR_IMAGE=valvur:dev` (built
from `87e760ea`) and an empty `VALVUR_CACHE`, so the run below is cold. PyPI
served 0.5.0 at the time; GHCR has 0.3.0 and 0.4.0; the release brake holds
1.0.0. Docker Desktop 29.2.1, a 3.8 GiB VM, 8 CPUs.

**Two instruments.** The real one: a headless Claude Code session (`claude -p`)
given one sentence, *Scan this project with valvur and tell me what it found*,
the six valvur tools plus `Read`, forty turns. The other: a stdio client that
speaks the protocol exactly as Claude Code does, for the paths a model would
not take on its own — a 20 s budget, bad inputs, a cancel watched for 75 s, a
client disconnect mid-scan, the tree with its exclude removed, the
`honour_gitignore` opt-in, and a full unexcluded run to reach a Scanner's
timeout. Every reply is in the transcripts listed in §8.

## 1. Goal 1 — what valvur found in occams-test-lab

The scan is complete (`complete: true`, all eight Scanners ok, `left this
machine: nothing`). **Eight active findings, all low, all one rule**, and one
coverage note:

| # | file | line | finding | fix |
|---|---|---|---|---|
| 1–4 | `.github/workflows/check.yml` | 19, 20, 67, 68 | `actions/checkout@v4` and `actions/setup-python@v5` pinned to a mutable tag (`valvur.pinning.mutable-action-ref`) | pin to the full commit SHA, keep the tag in a trailing comment so Dependabot still tracks it |
| 5–8 | `.github/workflows/pages.yml` | 21, 28, 37, 48 | the same for checkout, setup-python, `upload-pages-artifact`, `deploy-pages` — the workflow that will publish the site | the same |
| — | `pyproject.toml` | — | *coverage note:* Python dependencies were not checked for known vulnerabilities — no lockfile or pinned requirements beside the manifest, and Trivy reads only those | commit a lockfile (`uv.lock` or a pinned `requirements.txt`) and rescan; until then the run is honest that it did not look |

No exploitation evidence on any of them (KEV none, EPSS none): hygiene, not an
active vulnerability. **What came back clean:** no secret in the tree or its
git history (gitleaks), no injected directive or hidden Unicode in `CLAUDE.md`
(the AI-artifact Check), no infrastructure misconfiguration (Checkov ran: the
workflows are its input), nothing from the code-pattern rules, no licence
problem. With `[scan] honour_gitignore = true` the gitignored `configs/`,
`archive`, `.clu` and `occams.egg-info` are hidden as well; `.claude/` is
still read, as documented, and the result is the same eight findings.

Whether to pin the actions by SHA is the author's decision; it touches the
publication workflow.

## 2. Time to a correct report — the agent path, cold cache

| elapsed | what happened |
|---:|---|
| 0 s | `claude -p` starts; the harness connects to the worktree server from `.mcp.json` |
| 16 s | first `scan_status`: the database is being fetched (123 MB, 13 s), then the index (36 MB, 8.7 s, signature verified) |
| 33 s | *workspace: 328 files to scan; largest: docs 108, occams 105, tests 64* · *fleet: 8 Scanners, 2 at a time* · gitleaks ok 1.3 s |
| 86 s | seven of eight finished: trivy 24.1 s, opengrep 26.8 s, syft 1.7 s, the three Checks 1.1 s each; Checkov running |
| ~95 s | `DONE`, complete, 8 active, 1 not covered; Checkov 35.9 s |
| 148 s | **a correct report**, 16 turns, $1.08; no question asked, nothing changed in the repository, no container left |

Yesterday the same tree, same machine, failed at 300 s and reached a first
finding after 30 minutes and a read of the source. The agent read the
structured `next` field and polled correctly from the first reply.

## 3. Yesterday's nine, verified on this build

| | finding of 2026-09-26 | observed today |
|---|---|---|
| B1 | first scan fails at the budget; failure points at `doctor` | **fixed** — 328 files after the exclude, complete in ~95 s; a 20 s cut names what ran, what was cut, what never started (*not started: the 20s budget was spent before its turn*), and `SUMMARY.md` names the three levers; the cut reply does not mention `doctor` |
| B2 | a scanner past its timeout is abandoned | **fixed** — see C8: both timed-out Scanners *stopped*, no container left |
| B3 | excludes filter findings after the walk | **fixed** — `[scan] exclude` drops `archive` before any Scanner reads: gitleaks 1.3 s (212 s yesterday), the Checks 1.1 s (403 s); `honour_gitignore` opt-in present and correct |
| B4 | README calls an unreleased version published | **fixed** — *release in progress … `pip install valvur` serves `0.5.0` until the run's `promote` completes* |
| B5 | no progress during the scanner phase | **fixed** — *Now: trivy 16s, opengrep 15s running — 1 of 8 finished: gitleaks: ok (1.3s)*, with `running`, `finished_scanners`, `fleet` as fields |
| B6 | failure record is argv with empty stderr | **fixed** — *cut by the 20s budget after 20s*; *timed out after 600s and was stopped — last stderr: …* (C8) |
| B7 | defaults do not fit Docker Desktop | **fixed** — `doctor`: *3.8 GiB, 8 CPUs — scans run 2 Scanners at a time*; the first status line says the width |
| B8 | Claude Code not named for the config | **fixed** — the README's client table; `doctor` reads every client's file |
| B9 | sizes, KEV wording, unfenced evidence, empty gate templates | **fixed** — *118 MB to fetch, about 1.4 GB on disk*; KEV line consistent; every evidence fenced `[UNTRUSTED CONTENT …]` in text and structured replies; the gate records exist under `docs/gates/` |

Also new and working: `instructions` at the handshake (1,800 chars, the
`SUMMARY.md` rules), `readOnlyHint: false` on `scan` and `scan_cancel`,
`outputSchema` and `structuredContent` on the two readers, `network.fetched`
in `run.json`, `not_rechecked` on a cut (the 20 s cut reported *0 active, 8
not re-checked* rather than 8 fixed), a client disconnect mid-scan on the
excluded tree stopping both containers within the server's 10 s exit.

## 4. Goal 2 — new defects in this build, ranked

### C1 — After `scan_cancel` the fleet keeps launching Scanners, and `CANCELLED` is reported with a container still running
Measured twice with the two-wide fleet. On the excluded tree: `scan_cancel`
at 11 s answered *stopped 2 container(s)*; at +18 s a new container was *Up
less than a second* and the job read `CANCELLING`; at +36 s it read
*CANCELLED after 46s — 6 of 8 Scanner(s) had finished; the rest were stopped*
— six finished after a cancel that met two running — with a container *Up 13
seconds* at that moment. On the unexcluded tree: cancel at 18 s, then at +55 s
two containers *Up 46 s* and *Up 53 s* (syft and the Checks, launched after the
cancel), and at +75 s a third pair *Up 19 s*. The server did not exit within
20 s of its stdin closing; when the probe killed the `uv` wrapper, the server's
own Python process survived, holding the workspace lock (`lsof` on
`.security-scan/.lock`) with two `docker run` children until those were killed
by hand — the next `scan` was refused *Busy: a scan is already running*.
**Fix:** the scheduler must check the cancel flag before every launch, the
`CANCELLED` state must wait for the last container to be gone (`docker wait`
by name), and the exit path must stop the queue before waiting on it.

### C2 — `scan` creates a workspace that does not exist, then reports on it
`scan` with `workspace: "relative/path"` resolved it against the server's
working directory, **created** `~/occams-test-lab/relative/path/.security-scan/`,
ran every Scanner over the empty directory, and answered *DONE in 5s … 1
active: No licence file found*. A typo in the path produces a directory in the
user's project and a confident, wrong report. An absolute nonexistent path
fails only because `/` is read-only (*OSError: [Errno 30] Read-only file
system: '/nonexistent'*); a path under `$HOME` would be created the same way.
**Fix:** refuse at the call, `isError`, when the workspace is not an existing
directory; require an absolute path or say what it was resolved against.

### C3 — Input errors fail asynchronously, in Python's words, and advise `doctor`
A file as workspace → *Started …* then `FAILED after 0s — NotADirectoryError:
[Errno 20] Not a directory: '…/README.md/.security-scan'*; `budget_s: -5` →
*Started …* then *FAILED after 0s — ValueError: the budget must be a positive
number of seconds; got -5.0*; each followed by *Run `doctor` … it names what
this machine is missing*. `budget_s: "ten"` and `profile: "bogus"` are refused
synchronously, which is right, but as *ValueError: could not convert string to
float: 'ten'* and *ValueError: unknown profile 'bogus'*. `explain_finding` on
an unknown fingerprint: *ValueError: No finding with fingerprint …*.
**Fix:** validate every argument where it arrives, one plain sentence each,
no exception class; `doctor` only when a precondition could be the cause.

### C4 — `doctor_may_help` is always `true`
It is `true` while RUNNING, on a clean DONE, on a budget cut, on a Busy refusal
and on every input error above. The text got this right (the 20 s cut did not
mention `doctor`); the field did not, and a client that reads fields — Claude
Code does — is told to run `doctor` after every scan. The Busy refusal's text
also says *Run `doctor`*, which cannot help. **Fix:** set it only when the
failure is a precondition (`runtime`, `image`, `database`, `index`, `selinux`,
`tls`), and give Busy its own `next`: *wait, then call `scan_status`*.

### C5 — The server a session is talking to can be an older build than `.mcp.json` names, and nothing says so
Claude Code keeps the server it spawned at session start; this session's
`mcp__valvur__*` tools were 0.3.0 from yesterday's config, while `.mcp.json`
had been changed to the 1.0.0 worktree. `doctor` (0.3.0) printed *mcp:
.mcp.json: valvur (uv run --project … valvur-mcp)* under a *valvur 0.3.0
doctor* header and drew no conclusion. Half a Claude Code fix, half valvur's:
`doctor` knows its own version and executable and reads the config's command;
when they differ it should say *this server is 0.3.0 at <path>; `.mcp.json`
names <command>; restart the client to use it*.

### C6 — The agent misreported the results folder as unignored
Its `git status` was refused by the harness; it then told the user *that
directory is not in `.gitignore`, so it now shows as untracked … adding one
line to `.gitignore` would settle it*. The folder contains its own `.gitignore`
(`*`) and git shows nothing. The instructions say *never commit it* and stop
there. **Fix:** one clause in the `scan` reply and the handshake instructions:
*the folder ignores itself; there is nothing to add*.

### C7 — Small things
- *Completed so far: starting* on every RUNNING reply even when Scanners have
  finished; `now: null` in the structured job while the text says *Now: trivy
  16s …* (the names are under `running` instead).
- `list_findings` with `limit: 500` answers 100 without saying it clamped.
- A partial budget cut's structured `job` carries no `budget` field; the
  levers are in `SUMMARY.md` only.
- `scan` accepts and ignores unknown arguments (`extra: "field"`).
- The server's exit after stdin closes took 10.4 s on a healthy scan; a client
  that kills after 5 s would orphan it (see C1 for what an orphan holds).

### C8 — The timeout path on a real Scanner
**Verified fixed.** With the exclude file removed (103,578 files, `archive`
103,251 of them) and no budget, the run reached both per-Scanner timeouts:
*opengrep: FAILED — timed out after 600s and was stopped (605.3s)* and
*checkov: FAILED — timed out after 600s and was stopped — last stderr: …
FutureWarning …* (609.1s). No container remained at any point after; the run
completed as `DONE in 993s`, `complete: False`, *not re-checked: 8* (the
previous findings belong to Opengrep, which did not finish), *INCOMPLETE. Do
not report it as clean*. Yesterday's 0.3.0 failed this tree outright at 300 s
and left containers behind. The other Scanners on the raw tree at two jobs:
gitleaks 214 s, trivy 59.5 s, syft 234 s, the three Checks 148.6 s. Small:
the *last stderr* excerpt is cut mid-word (*… exclud (609.1s)*) and runs into
the duration.

### C9 — A data directory becomes 3,890 identical secret findings, ranked first
On the same unexcluded run gitleaks reported **3,890 `generic-api-key` hits**,
one per hash-named JSON file under `archive/surveys/…/baselines/`, every one
*Detected a Generic API Key*, and the reply's `Next:` line and `REMEDIATION.md`
open with *Rotate the credentials in archive/…/0192e33b54ed76c8.json — action 1
of 3890*. `SUMMARY.md` is bounded (*Most urgent, 15 of 3890*), `list_findings`
clamps at 100, and the pre-scan line had already said *archive holds 103,251
of them — if it is not source, `[scan] exclude = ["archive"]`*; but the
ranking still puts 3,890 copies of one rule on one directory of numeric data
above the eight real findings, and tells the user to rotate 3,890 credentials.
**Fix:** collapse repeated hits of one rule under one directory into a single
finding with its count and the exclude line (*generic-api-key ×3,890 under
`archive/surveys/…` — machine-written data; verify one, or exclude the
directory*), and rank a collapsed flood below distinct findings; the raw list
stays in `findings.json`.

## 5. What was not tested
Kiro itself (the config table says which file; not driven here), `--profile
full`, Podman, `valvur gate`, suppressions, `valvur update`, the CLI's own
progress lines.

## 6. The gate's two questions
- *Before and after?* Before: yesterday's tool with nine known defects. After:
  a scanner that reaches a correct report on this tree in under three minutes
  from a cold cache through the agent path, stops what times out, and
  mishandles being told to stop.
- *What should the README say first?* Nothing new; it now says the right
  things. The `scan` reply should say the folder ignores itself.

## 7. State left in this project
`.mcp.json` (the author's worktree config), `.security-scan.toml` restored to
its two-line exclude, both untracked and in `.git/info/exclude`;
`.security-scan/` holds the agent pass's complete run (generation
`70f2d957…`); the probe's stray `relative/` directory removed; no valvur
container running; the memory file for this project updated.

## 8. Evidence
In the session scratchpad `…/scratchpad/valvur/`: `agent2.jsonl` (the headless
pass, whole), `agent2-security-scan/` (its results folder), `probe-*.jsonl`
and `probe2-*`, `probe3-*`, `probe4-*` transcripts (every JSON-RPC line, timed,
per probe), `full.log` and `full-security-scan/` (the unexcluded run's results folder), and the probe scripts `probe_new.py`, `probe2.py`,
`probe3.py`, `probe4.py`.
