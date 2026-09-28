# valvur tested as a new user, from Claude Code, on occams-test-lab — 2026-09-26

**Participant:** a Claude Code agent (Claude Fable 5.1, desktop app) given the
valvur README and this instruction: set it up on this project the MCP way and
report what breaks. **Project scanned:** `occams-test-lab` — 312 tracked files,
but a 1.4 GB working tree with 107,544 files on disk (103,251 of them in the
gitignored bar archive, 3,557 in `.venv`). **Machine:** Apple-silicon Mac,
Docker Desktop 29.2.1 with a 4 GB VM and 8 CPUs, Python 3.12.10 through `uv`;
no valvur image, cache or MCP configuration existed before the test.

**Path taken, in order:** README → `uvx --from valvur valvur-mcp --version` →
`valvur doctor` → the README's JSON block saved as `.mcp.json` → an MCP client
speaking newline JSON-RPC over stdio exactly as Kiro and Claude Code do
(`initialize`, `tools/list`, `scan`, `scan_status` polling, `list_findings`,
`explain_finding`, `doctor`, error paths) → a second scan the way the README
advises for Docker Desktop → a headless Claude Code session on the same
`.mcp.json` (blocked, see §5). Every reply, timing and Docker event is in the
files listed in §7.

## 1. Time to first useful result

| moment | clock | elapsed |
|---|---|---|
| README opened | 12:47 | 0 |
| shim installed from PyPI (`uvx`), 13 s; `valvur doctor`: "ready: a scan will run here" | 12:52:53 | 6 min |
| first `scan` over MCP (image, database, index all fetched: 17 s + 21 s + 7 s) | 12:54:33 | 7½ min |
| **first scan FAILED** — every scanner killed at the 300 s default budget, no report | 13:00:22 | 13 min |
| second scan, after reading the source: `VALVUR_JOBS=2`, `budget_s: 900`, `[scan] exclude` | 13:03:47 | 17 min |
| **first real finding read** (`DONE in 829s`, incomplete: Checkov timed out) | 13:17:36 | **30 min** |

The gate's target is five minutes. A newcomer who does not read the source stops
at 13:00: the failure text sends them to `doctor`, which says the machine is
ready, and nothing names the cause.

## 2. What worked, and deserves credit

- Install is one command and 13 seconds; the shim is stdlib-only as claimed.
- `doctor` is accurate on every precondition it checks, prints no secret, and
  names `.mcp.json` as the Claude Code file (the README does not).
- The stdio server is clean: `initialize` in 0.4 s, unknown tool → `-32602`
  listing the six tools, unknown method → `-32601`, nothing but JSON on stdout,
  exit 0 when stdin closes. Claude Code connected to it from the README's
  `.mcp.json` block in under eight seconds (`status: connected`).
- A first run fetches what is absent and says so live on `scan_status`
  ("Now: fetching the vulnerability database (123MB) — the first run only").
- The results folder ignores itself; `run.json` records `left this machine:
  nothing`; `SUMMARY.md` opens with the failed scanner, says **INCOMPLETE. Do
  not report it as clean**, counts the 3,890 findings the exclude file dropped,
  and lists the coverage gap (Python dependencies unchecked — correct: the
  project has no lockfile).
- The findings are real and explained with evidence: eight `mutable-action-ref`
  hits on `actions/checkout@v4` and friends in the two workflows, ranked low.

## 3. What is broken, ranked

### B1 — A first scan of a real project fails at the default budget, and the failure points the wrong way
Eight scanners on 107,544 files; at 300 s the budget SIGKILLed five (exit 137),
gitleaks hit its own timeout, none produced a report: *"ScannerFailed: Every
scanner failed. Refusing to report a scan."* The text then says *"Run `doctor`
… it names what this machine is missing and the fix"* — and `doctor` answers
*"ready: a scan will run here"*. Neither mentions the budget, the file count,
`budget_s`, `VALVUR_JOBS` or `[scan] exclude`. The same advice string is on
main (`operations.py:496`).
**Fix:** a budget cut is its own message: the elapsed budget, the workspace's
file count and largest directories, the scanners that did finish, and the three
levers by name. `doctor` should count files under the workspace and print
Docker Desktop's VM memory (4 GB here) with a warning above a threshold.

### B2 — A scanner past its subprocess timeout is abandoned, not killed
The shim runs gitleaks under `subprocess.run(timeout=300)` (`runner.py:846`)
and the others under 600 s; no code path catches `TimeoutExpired`, so Python
kills the `docker run` client and the container runs on with nobody to read it.
Measured twice from Docker's event log:
- run 1: the budget killed five containers at 13:00:23 and the server exited at
  13:00:26; the gitleaks container ran until 13:02:06 (401 s, exit 1).
- run 2: Checkov's timeout fired at ~13:17:21, the server exited at 13:17:36;
  the container was still at 92 % CPU at 13:18:52 when I stopped it by hand.
Main declares the same timeouts per adapter (`adapters/gitleaks.py:31` 300 s,
`trivy.py:55` 900 s, the rest 600 s; `runner.py:519`) and still catches
nothing. 27.1.1's sweep runs only when the *server* exits; the CLI has no
sweep, and over MCP a timeout mid-run leaks until the client disconnects.
**Fix:** catch `TimeoutExpired` at the launch, kill by `--name`, report *"timed
out after Ns and was stopped"*; a test that a scanner past its timeout leaves
no container behind.

### B3 — Excludes are applied after the scan, so they save no time and the noise is produced first
`[scan] exclude` and the built-in vendored list are finding filters
(`exclusions.filter_findings`); only Opengrep receives `--exclude`
(`runner.py:716`). Gitleaks produced **3,892 `generic-api-key` hits** inside
`archive/` (2.7 MB of raw output), all then dropped. Timings, valvur's own
container flags:

| scanner | 312 tracked files | the mounted tree |
|---|---|---|
| gitleaks | 1.5 s | 211.7 s |
| Checkov | 13.7 s | > 690 s, never finished |
| the three Checks (one container) | — | 403 s |

`.gitignore` is deliberately not honoured (the reason given: `.env` files).
**Fix:** pass excluded and vendored paths to every scanner at scan time
(gitleaks allowlist paths, `trivy --skip-dirs`, `syft --exclude`, `checkov
--skip-path`, the Checks' walk) — or mount only the wanted paths; and offer an
opt-in `honour_gitignore` that still always scans `.env*`. Without one of these
a project with a data directory cannot be scanned in the README's "6–24 s".

### B4 — The public README describes an unreleased version as published
`README.md` on `main` says **"Status: 0.4.0 — published and installable"**.
PyPI's latest is 0.3.0 (2026-09-20); GHCR has no `0.4.0` tag; the repository
has no `v0.4.0` tag and its latest release is `v0.3.0`; the last commit says
"the click is the owner's". Everything the README promises for MCP that 0.4.0
added is absent from what a new user installs, verified over the wire: no
`instructions` at `initialize`, no `structuredContent`, all six tools
`readOnlyHint: true` (`scan` and `scan_cancel` included), the server does not
stop its containers on exit, no `doctor --bundle`, no `cache --prune`.
RELEASING.md step 4 bumps the README before the tag, and the release brake sits
after it, so `main` overclaims for as long as the brake is held.
**Fix:** either bump the status line in the promote step, or word it "tagged,
release in progress" until PyPI serves it; a check on `main` that the README's
version is not ahead of PyPI's would have caught this today.

### B5 — No progress during the scanner phase
After the three fetches, sixteen consecutive polls over 290 s answered only
*"Completed so far: image pulled (17s), database fetched (21s), index fetched
(7s)"* — no `Now:` line, no scanner names, nothing an agent could use to tell a
running scan from a hung one. Unchanged on main (`operations.py:489`).
**Fix:** *"Now: gitleaks, trivy, checkov running (3 of 8 finished: syft 4s,
…)"*, from the same durations `run.json` already records.

### B6 — The failure record is argv without a diagnosis
Each failed scanner is reported as its full `docker run` command line
(1,500 characters) followed by `stderr:` and nothing — the scanners' stderr is
lost on the kill and timeout paths. **Fix:** keep partial stderr; say *killed at
the budget* versus *timed out* versus *OOM* (exit 137 is used for two of them).

### B7 — Budget and concurrency defaults do not fit Docker Desktop
The MCP default budget (300 s) equals gitleaks's own timeout and is below what
a real tree needs; the CLI has no budget; eight containers start at once inside
a 4 GB VM. The README's remedy (`VALVUR_JOBS=2`) is in the Platforms section,
after the point where a first-run user has already failed. **Fix:** derive the
default `--jobs` from the runtime's memory, or have `doctor` recommend one.

### B8 — Claude Code is not named where the config goes
The README's JSON block is correct but says nothing about where Claude Code
reads it (`.mcp.json` at the project root, then approve the server in an
interactive `claude`; headless and SDK sessions need `--mcp-config`).
`claude mcp list` shows the server as *Pending approval* until then.
EVALUATING.md covers Kiro's files; `doctor` names `.mcp.json`; the README
should, in one line.

### B9 — Small inconsistencies
- `valvur cache` reports the database at 1.45 GB and the index at 123 MB on
  disk; `doctor` and the README say 118 MB and 35 MB (transfer sizes). Say which.
- `valvur cache` says `kev: absent`; `doctor` says `kev: bundled snapshot from
  the image`. Both true, read as a contradiction.
- `explain_finding`'s evidence is not wrapped in the `[UNTRUSTED CONTENT …]`
  markers `SUMMARY.md` says quoted text carries (0.3.0).
- `docs/usability-gate.md` still holds empty Gate 1 and Gate 2 templates; this
  document is written to its format.

## 4. What valvur found on occams-test-lab
Eight low findings, all `valvur.pinning.mutable-action-ref`: `actions/checkout`
and `actions/setup-python` pinned by tag in `.github/workflows/check.yml`
(lines 19, 20, 67, 68) and `pages.yml` (21, 28, 37, 48). One coverage note:
Python dependencies unchecked because `pyproject.toml` has no lockfile beside
it. Nothing else — no secret, no injected directive in `CLAUDE.md`, no
dependency problem. Whether to pin by SHA is the author's call.

## 5. What could not be tested, and why
- **The agent-driven pass** — Claude Code's own model calling the tools. The
  harness loaded `.mcp.json` and connected, but the child `claude -p` answered
  *"Failed to authenticate: OAuth session expired and could not be refreshed"*:
  `claude auth status` reports `loggedIn: false`, and a child process cannot
  use the desktop app's host-side refresh. It needs `claude login` in a
  terminal, then:
  ```
  cd ~/occams-test-lab && claude -p "Scan this project with valvur and tell me what it found." \
    --mcp-config .mcp.json --strict-mcp-config --max-turns 40 \
    --allowedTools "mcp__valvur__scan,mcp__valvur__scan_status,mcp__valvur__list_findings,mcp__valvur__explain_finding,mcp__valvur__doctor,mcp__valvur__scan_cancel,Read"
  ```
  The interesting observation is what the model does when the first scan fails
  at the budget and `doctor` says ready.
- `valvur update`, `--profile full`, `gate`, suppressions, Podman.

## 6. The gate's two questions
- *What did you think it did, before and after?* Before: an offline scanner
  that would take a minute and hand an agent a ranked list. After: exactly
  that on a source-only tree; on a real working tree it needs the source read
  to get past its own defaults, and it leaves containers behind when it fails.
- *What should the README say first?* That it scans the working tree as
  mounted, not the git index; that a data or build directory must be excluded
  and that today an exclude filters findings rather than files; and which file
  each client reads.

## 7. Evidence
Under the session scratchpad `…/scratchpad/valvur/`: `transcript.jsonl` and
`run2-transcript.jsonl` (every JSON-RPC line, timed), `tools-list.json`,
`scan-status-final.json`, `run2-status.json`, `run2-findings.json`,
`run2-explain.json`, `run2-security-scan/` (the complete results folder),
`run2.log`, `agent.jsonl`, `occams-lite/` (the tracked-files timing tree),
`drive_mcp.py` and `drive_mcp2.py` (the client). In the project: `.mcp.json`
and `.security-scan.toml`, untracked and listed in `.git/info/exclude` so no
`git add -A` sweeps them in; `.security-scan/` restored from run 2.
