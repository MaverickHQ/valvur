# valvur

**A fully offline security scanner for AI-generated code. Your source never leaves your machine — and you can prove it.**

> **Status: `0.4.0`** — published and installable; `v1.0.0` follows the usability gate.
> `pip install valvur` · `ghcr.io/maverickhq/valvur`

---

## Why this exists

Every serious code-security scanner sends your code — or metadata about it — to
someone else's servers. For regulated industries and data-residency jurisdictions
that is not a preference to negotiate; it ends the procurement conversation. valvur
runs entirely on your machine, with networking switched off and your source mounted
read-only.

At the same time, AI now writes a fast-growing share of production code, and it fails
in ways classic scanners were never built to catch: hallucinated dependencies that
attackers pre-register, poisoned agent instruction files, hidden Unicode directives.

**Offline scanning, built for how AI-generated code actually breaks.**

## The three claims

This is the introduction. [`docs/EVALUATING.md`](docs/EVALUATING.md) is the audit —
the measured first run, the verification commands, the three statuses, and a plain
list of what valvur does **not** claim. Read that one sceptically.

### 1. It cannot exfiltrate your code — and you can verify it

No account, no API key, no telemetry: nothing to opt out of. On the default `offline`
profile the scanners run in containers with `--network=none`, and the host process
that launches them opens no socket either. Both halves are checked by one command:

```bash
python3 scripts/verify-offline.py /path/to/your/repo
```

On Linux the OS can deny the whole process tree the network, no privileges needed:
`unshare -rn valvur scan --profile offline`. Every run records in `run.json` exactly
what left the machine — on `offline`, the word `nothing`.

### 2. Security checks built for AI-generated code

- **Hallucinated dependencies (slopsquatting).** LLMs invent package names; attackers
  register them. No advisory database can catch it — the package is *new*, not
  known-bad. valvur checks that every declared dependency exists, **offline**, against
  a local index of every name on PyPI, npm, RubyGems, Packagist and crates.io (6.3
  million names, exact, published daily and signed). On `full` it also asks how old
  each one is, whether it is one edit from something popular, and — for npm, whose
  download counts are public — whether a package under 90 days old has under 1,000
  downloads a month: *new and unadopted*, the slopsquat signal itself, reported at
  high. PyPI publishes no counts without a third party, so there it is age alone.
- **Agent-config auditing.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`,
  skills and prompt files, and the clients' own folders — `.kiro/` (steering, MCP
  settings, hooks), `.claude/`, `.cursor/`, `.roo/`, `.continue/`, `.clinerules`,
  `.aider.conf.yml` — scanned for injected directives, hidden Unicode (zero-width,
  bidi, tag characters), unpinned `@main` MCP refs, blanket `autoApprove` and
  permission-bypass flags, and **hooks that run a shell command on an event**: a
  committed Kiro hook, Claude Code hook or aider `lint-cmd` makes every agent that
  opens the repository execute it, and is reported at high with the command as
  fenced evidence.
- **A small set of Opengrep rules, which are not the claim.** Two pinning rules
  (tag-pinned actions, mutable git refs) that fire on most real repositories; a
  **sink inventory** at INFO — `eval`, `exec`, `shell=True`, unsafe `yaml.load`,
  string-built SQL — which is what fires on real code; and four **taint rules**
  from a model call to those sinks and to `innerHTML`, with sources for the
  Anthropic, OpenAI (chat completions, Responses API, pre-1.0), Gemini, LangChain,
  litellm and ollama SDKs. The taint rules fire on every planted flow in our
  fixture (fifteen, across those six families) and **have never fired on real
  code**: measured on thirteen real repositories, including two that execute model
  output — smolagents and pandas-ai route it across a class boundary, and
  Opengrep's taint tracking is intra-procedural, so it does not see the flow while
  the inventory names both `exec` sites. They ship ranked `low`; the checks above
  carry this section.

What is covered, and what is not, is stated on every scan rather than left to infer:

| ecosystem | exists? | known CVEs? |
|---|---|---|
| Python, npm, Ruby, PHP, Rust | offline, from the index | needs `requirements*.txt`, `uv.lock`, `poetry.lock` / a lockfile |
| JVM, Go | `full` only — no offline index exists for either registry | `pom.xml`, `go.mod` on their own |

A manifest with no lockfile beside it, or a manifest nothing here reads (a lone
`Pipfile`, say), is a **coverage note**: the run reads `inconclusive` rather than
`clean`, and names why. That reporting is the part we consider non-optional. A
licence valvur *could not read* — dependency licences absent from a lockfile, a
`LICENSE` no signature matches — is a note too, listed and counted, but it casts no
doubt: a security verdict of `clean` stays `clean` over it, and no gate threshold
sees it.

### 3. Ten things that matter, not four hundred findings

Findings are ranked by **whether attackers are actually exploiting them** — CISA KEV
(including the ransomware-campaign flag) and FIRST EPSS — not by CVSS theatre.
Development-only dependencies are demoted; transitive vulnerabilities come with the
path and the direct package to bump.

| Finding | CVSS | EPSS | KEV | Severity-sorted | Ranked here |
|---|---|---|---|---|---|
| CVE in a dev-only test library | 9.8 CRITICAL | 0.04% | No | **#1** | #40 |
| CVE in your production web framework | 6.5 MEDIUM | 92% | **Yes** | #40 | **#1** |

## For AI coding agents — the primary way in

Add valvur to your agent's MCP configuration — one server, `uvx --from valvur valvur-mcp`,
no install step. Each client reads it from its own file, in its own shape. The two
marked *measured* were run here; the rest are the shape each client documents, dated,
and `valvur doctor` reads every one of these files.

<!-- clients:start — rendered from valvur.mcp.clients; a test holds this block to it -->

**Claude Code** — `.mcp.json` or `~/.claude.json`. Approve the project server once in an interactive `claude`; a headless or sdk session passes `--mcp-config .mcp.json --strict-mcp-config`. *Measured 2026-09-26 at the first gate: connected from this block in under eight seconds; `claude mcp list` health-checks a project server only once it is approved.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**Kiro** — `.kiro/settings/mcp.json` or `~/.kiro/settings/mcp.json`. `kiroagent.configuremcp` must be `enabled`; the server starts with the agent. *Measured 2026-09-12 (task 22.f.2), and `doctor` reads kiro's files.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Codex** — `~/.codex/config.toml`. Or `codex mcp add valvur -- uvx --from valvur valvur-mcp`; the server starts with the next session. *Documented shape, 2026-09-26; not run here.*

```toml
[mcp_servers.valvur]
command = "uvx"
args = ["--from", "valvur", "valvur-mcp"]
```

**Cursor** — `.cursor/mcp.json` or `~/.cursor/mcp.json`. Enable the server under settings → mcp; cursor starts it on demand. *Documented shape, 2026-09-26; not run here.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**VS Code (Copilot agent mode)** — `.vscode/mcp.json`. The key is `servers`, not `mcpservers`; start it from the file's inline *start* action or trust the workspace. *Documented shape, 2026-09-26; not run here.*

```json
{
  "servers": {
    "valvur": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**Windsurf** — `~/.codeium/windsurf/mcp_config.json`. Refresh the mcp panel; windsurf starts it on demand. *Documented shape, 2026-09-26; not run here.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**Cline** — `cline_mcp_settings.json (under the extension's global storage)`. Edit through the extension's mcp servers panel, which opens this file. *Documented shape, 2026-09-26; not run here.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**Roo Code** — `.roo/mcp.json`. The extension reloads the file on save. *Documented shape, 2026-09-26; not run here.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**Continue** — `.continue/config.yaml` or `~/.continue/config.yaml`. Yaml, under `mcpservers:`; reload the config from the extension. *Documented shape, 2026-09-26; not run here.*

```yaml
mcpServers:
  - name: valvur
    command: uvx
    args:
      - --from
      - valvur
      - valvur-mcp
```

**Gemini CLI** — `.gemini/settings.json` or `~/.gemini/settings.json`. `/mcp` in the cli lists it; the server starts with the session. *Documented shape, 2026-09-26; not run here.*

```json
{
  "mcpServers": {
    "valvur": {
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

**Zed** — `~/.config/zed/settings.json`. The key is `context_servers`; the assistant panel lists it. *Documented shape, 2026-09-26; not run here.*

```json
{
  "context_servers": {
    "valvur": {
      "source": "custom",
      "command": "uvx",
      "args": [
        "--from",
        "valvur",
        "valvur-mcp"
      ]
    }
  }
}
```

<!-- clients:end -->

Then ask it to scan. The server is **stdio only** — no listener, no port — and no
tool it exposes can change your code: your tree is mounted read-only and there is no
fix, apply or remediate tool to call. `scan` and `scan_cancel` do act on your machine
— a results folder, an image pull, containers started and stopped — and say so in
their MCP annotations, so a client that asks before running them is right to. Nothing has to run
first: a first `scan` pulls the image, the vulnerability database and the name index
itself and says so on `scan_status` — measured 2026-09-20 on `0.3.0` from an empty
machine, **58 seconds** to a complete result, one tool call (110s on `0.2.0`). A
scan after that, measured on GitHub's Linux runner across twelve real application
repositories: **6–9 seconds** (2026-09-26, after Checkov's startup was fixed in
the image; it had been 16–19).

**When a first scan does not finish.** Over MCP a scan has a 300-second budget
(`budget_s` on the `scan` call sets another; the CLI has none unless `--budget`
says so). Past it the running Scanners are stopped and the reply says which, for
how long, and what to turn: exclude what is not source (`[scan] exclude` in
`.security-scan.toml` — a data directory or a build tree costs a scan nothing
once named), give it longer, or run fewer Scanners at once (`VALVUR_JOBS`, or
`--jobs` on the CLI). On a runtime with less than 6 GiB — a default Docker Desktop
VM — valvur already runs two at a time: measured on a 3.8 GiB VM, eight at once
contend and finish no sooner (23.6 s against 20.3 s), and a container the VM cannot
fit is killed with exit 137 and reported as such. `valvur doctor` says what the
default here will be. A scan
counts what it will read before it starts — the first status line says how many
files and which directories are largest, and past 20,000 files names the one to
exclude — and while it runs, `scan_status` says which Scanners are running and for
how long, and how many have finished. `valvur doctor` says the same for a
directory before any scan.

The server's handshake carries the rules an agent needs — never commit the
folder, work from `REMEDIATION.md`, never add a suppression without a human, a
disappeared finding is not a fix — as MCP `instructions`, and `scan_status` and
`list_findings` answer structured content beside their text, so an agent reads
counts as fields rather than out of prose. For a client that does not show
`instructions`, add this to your project's `CLAUDE.md` or `AGENTS.md`, so the agent
uses what it has:

```markdown
## Security scanning
This project uses valvur. Scan with the `valvur` MCP tools if you have them:
call `scan`, then `scan_status` until it reports DONE, then follow its `Next:`
lines; if it reports FAILED, call `doctor` and relay what it says. Otherwise
run `valvur scan`. Results
appear in `.security-scan/`: read SUMMARY.md, then REMEDIATION.md. Never
commit `.security-scan/`. Never add suppressions without explicit human
approval. Propose fixes for approval — do not apply them and rescan
autonomously.
```

## For developers

```bash
pip install valvur          # or: uv tool install valvur
valvur update               # the image, the vulnerability database and the name index, once
valvur scan                 # offline by default; --profile full adds the networked checks
valvur doctor               # if anything above did not work: what this machine is missing, and the fix
```

The first `valvur update` pulls the image (about 240MB), the vulnerability database
(118MB) and the name index (34MB, one signed artifact, built daily) — a minute or
two. Later updates take seconds; run `valvur update --if-stale` from a hook or cron,
it costs one file read when current. It is optional before the first scan: a scan
that finds any of the three **absent** fetches it and says so — on the terminal, and
over MCP on `scan_status`, *"fetching the vulnerability database (119MB) — the first
run only"* — rather than sitting silent or failing. A **stale** one is never
refreshed by a scan; the warning stands and you decide. If the published index
cannot be reached, `valvur update` walks the five registries directly instead, which
takes about seven minutes once; a scan does not.

Results land in `.security-scan/`:

```
.security-scan/
├── SUMMARY.md          ← start here. Bounded, leads with anything that failed
├── REMEDIATION.md      ← ranked proposal, with dependency paths and upgrade targets
├── findings.json       ← complete, normalised, schema-versioned
├── results.sarif       ← SARIF 2.1.0 for your IDE
├── sbom.cdx.json       ← CycloneDX SBOM
├── run.json            ← what ran, which versions, how long each took, what was skipped and why
└── raw/                ← untouched per-tool output, so you can verify us
```

The folder ignores itself, so results are never committed. Secrets are redacted in
every artifact, `raw/` included. **You decide which fixes to apply and when to
rescan** — there is no autonomous loop. Suppressions (with mandatory expiry dates)
and `[scan] exclude` paths live in a committed `.security-scan.toml`; every Scanner
is told to skip an excluded path before it reads it — a data directory costs a
scan nothing — and every exclusion is reported. `honour_gitignore = true` (off
unless asked) also skips the directories `.gitignore` hides, except that `.env*`
files and agent instruction files are always read and a hidden directory holding
one is scanned whole; `include = [...]` keeps a hidden path.

In CI, `valvur scan` exits zero whenever the scan itself worked — findings are the
job, not a failure — and `valvur gate` turns the result into one exit code:

```bash
valvur scan . && valvur gate . --fail-on high --no-inconclusive
```

In GitHub Actions that is one line — [`MaverickHQ/valvur-action`](https://github.com/MaverickHQ/valvur-action)
installs the shim, fetches and caches what a scan needs, scans, uploads
`results.sarif` to code scanning and runs the gate; this repository's own release
gate uses it on every commit:

```yaml
- uses: MaverickHQ/valvur-action@16b19e275f843419887873ed536a71f872607e24 # v0.2
  with: { fail-on: high, no-inconclusive: "true" }
```

Pinned by commit, because a tag can move and a scan of your own tree would say
so: valvur's `mutable-action-ref` rule flags `@v0` as a finding, and this
repository's own gate runs on `any`. `@v0` works and follows the latest `v0.x`;
use it if you accept that, and expect the finding.

The gate fails on an incomplete run, on a lapsed suppression, on an active finding
at or above `--fail-on` (`any` is every one; it is what valvur's own release gate
uses), and with `--no-inconclusive` on a scan whose data was too old to be
evidence or that never inspected part of the tree. Under GitHub Actions each
reason is an annotation. `valvur cache` says what is on disk, how old and how
large; `valvur cache --clear` removes it; `valvur cache --prune` removes only what
is superseded — the image tags earlier shim versions pulled, and index files the
index no longer names — listing each first, and `valvur doctor` says when there
is something to prune.

## What actually does the scanning

valvur builds no detection engine. Six open source scanners do that and deserve the
credit; valvur adds orchestration, one findings model, exploit-aware ranking, and the
checks under claim 2.

| Tool | Licence | Does |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Dependency vulnerabilities |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets, including git history |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependencies against OSV.dev (`full` only: it sends lockfile names and versions out). Measured on twelve real repositories: **121 Go standard-library advisories on the one Go project**, keyed on `go.mod`'s `go` directive, which Trivy reports only from binaries; **1** disputed advisory on a Python project; **0** on the other ten; and on a thirteenth, **110 against the lower bounds of an unpinned `requirements.txt`** — versions nobody installs, dropped with the count since 25.3 (the file is a coverage note instead). About a second a scan. |
| [Opengrep](https://github.com/opengrep/opengrep) | LGPL-2.1 | Static analysis |
| [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Infrastructure misconfiguration |
| [Syft](https://github.com/anchore/syft) | Apache-2.0 | SBOM, and the dependency licences read from it |

Exploit intelligence comes from CISA KEV and FIRST EPSS — public primary sources,
auditable and mirrorable. No proprietary database; nothing to lock you in.

## What it deliberately does not do

- **No reachability analysis.** We do not prove a vulnerable function is called.
- **No autonomous fixing.** You choose the fixes.
- **No penetration testing.** No DAST, no exploitation, no scanning of deployed systems.
- **No code-quality analysis.** Security only.
- **We will not out-detect commercial SAST.** We win on trust, breadth in one
  artifact, and prioritisation — not on engine depth.

## Platforms

| | |
|---|---|
| Linux — Docker **and** Podman | **Supported**, and tested on every commit against both runtimes, on `amd64` and `arm64` |
| macOS — Docker Desktop or Podman | **Supported**, and tested by hand on an Apple-silicon Mac at each release — most recently `0.4.0`, 2026-09-26: the e2e suite against the image built from the release commit, and a first run over MCP with that image present measured 39s to `DONE` (`0.3.0`: 58s, of which a 13s pull). Not on every commit: a container runtime needs nested virtualisation, which GitHub's macOS runners do not offer |
| `linux/amd64` and `linux/arm64` | Both, **from 0.2.0**. `0.1.0rc1` was published `arm64` only — a defect, not a policy |
| Windows via **WSL2** | Supported — inside WSL valvur is running on Linux |
| Native Windows | **Not claimed.** Untested, and valvur says so at startup |
| SELinux-enforcing hosts (RHEL, Fedora) | Supported, with one deliberate friction: valvur will not relabel your source tree unless you set `VALVUR_SELINUX_RELABEL=1`. Details in [EVALUATING.md](docs/EVALUATING.md#5-what-it-does-not-claim) |

**Air-gapped?** The database, the name index and KEV all live outside the image and
each has a mirror setting, measured end to end. See [`docs/AIR-GAPPED.md`](docs/AIR-GAPPED.md).

A scan an agent no longer wants is stopped with the `scan_cancel` tool —
containers killed, nothing written — as Ctrl-C does on the command line.

## Contributing, and reporting problems

A finding you disagree with — especially one valvur *missed* — is a bug worth
reporting; `valvur doctor --bundle` writes the tarball to attach — this machine's
doctor report, the versions of everything involved and the last scan's
`run.json`, which since 28.3.6 records each Scanner's command line — and never
your source, raw output or findings. [CONTRIBUTING.md](CONTRIBUTING.md) has the setup and the short list of
things refused on principle; [SECURITY.md](SECURITY.md) is for suspected
vulnerabilities, which for a security tool include a false clean result;
[CHANGELOG.md](CHANGELOG.md) is what changed; [MAINTAINERS.md](MAINTAINERS.md) is
who can change what ships — one person today — and what you can rely on if they
cannot be reached.

## Licence

Apache-2.0 — see [LICENSE](LICENSE); chosen over MIT for the explicit patent grant.
Bundled scanners keep their own licences, listed above. valvur adds no GPL or AGPL
component; the Alpine base carries GPL userland as every Linux container does, and
the published SBOM discloses all of it ([ADR-0005](docs/adr/0005-no-gpl-tools-in-the-image.md)).
