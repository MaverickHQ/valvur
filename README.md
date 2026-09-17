# valvur

**A fully offline security scanner for AI-generated code. Your source never leaves your machine — and you can prove it.**

> **Status: `0.2.0`** — published and installable; `v1.0.0` follows the usability gate.
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
  each one is, and whether it is one edit from something popular.
- **Agent-config auditing.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`,
  skills and prompt files — scanned for injected directives, hidden Unicode
  (zero-width, bidi, tag characters), unpinned `@main` MCP refs, blanket
  `autoApprove` and permission-bypass flags.
- **A small set of Opengrep rules, which are not the claim.** Two pinning rules
  (tag-pinned actions, mutable git refs) that fire on most real repositories, and
  four for model output reaching `eval`, `exec`, a shell or `innerHTML` — taint rules
  whose sources are a completion call from the OpenAI, Anthropic or Gemini SDK, plus
  one for string-built SQL. Those four fire on our fixture and, measured on twelve
  real repositories including an LLM tool, **have never fired on real code**. They
  ship ranked `low`; the checks above carry this section.

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

Add valvur to your agent's MCP configuration:

```json
{ "mcpServers": { "valvur": { "command": "uvx", "args": ["--from", "valvur", "valvur-mcp"] } } }
```

Then ask it to scan. The server is **stdio only** — no listener, no port — and every
tool it exposes is read-only: valvur can never change your code. Nothing has to run
first: a first `scan` pulls the image, the vulnerability database and the name index
itself and says so on `scan_status` — measured 2026-09-13 from an empty machine,
**110 seconds** to a complete result, one tool call.

Add this to your project's `CLAUDE.md` or `AGENTS.md`, so the agent uses what it has:

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
and `[scan] exclude` paths live in a committed `.security-scan.toml`, and every
exclusion is reported with what it cost.

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
- uses: MaverickHQ/valvur-action@v0
  with: { fail-on: high, no-inconclusive: "true" }
```

The gate fails on an incomplete run, on a lapsed suppression, on an active finding
at or above `--fail-on` (`any` is every one; it is what valvur's own release gate
uses), and with `--no-inconclusive` on a scan whose data was too old to be
evidence or that never inspected part of the tree. Under GitHub Actions each
reason is an annotation. `valvur cache` says what is on disk, how old and how
large; `valvur cache --clear` removes it.

## What actually does the scanning

valvur builds no detection engine. Six open source scanners do that and deserve the
credit; valvur adds orchestration, one findings model, exploit-aware ranking, and the
checks under claim 2.

| Tool | Licence | Does |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Dependency vulnerabilities |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets, including git history |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependencies against OSV.dev (`full` only: it sends lockfile names and versions out). Measured on twelve real repositories: **121 Go standard-library advisories on the one Go project**, keyed on `go.mod`'s `go` directive, which Trivy reports only from binaries; **1** disputed advisory on a Python project; **0** on the other ten. About a second a scan. |
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
| macOS, Linux — Docker or Podman | **Supported**, tested on every commit against both runtimes |
| `linux/amd64` and `linux/arm64` | Both, **from 0.2.0**. `0.1.0rc1` was published `arm64` only — a defect, not a policy |
| Windows via **WSL2** | Supported — inside WSL valvur is running on Linux |
| Native Windows | **Not claimed.** Untested, and valvur says so at startup |
| SELinux-enforcing hosts (RHEL, Fedora) | Supported, with one deliberate friction: valvur will not relabel your source tree unless you set `VALVUR_SELINUX_RELABEL=1`. Details in [EVALUATING.md](docs/EVALUATING.md#5-what-it-does-not-claim) |

**Air-gapped?** The database, the name index and KEV all live outside the image and
each has a mirror setting, measured end to end. See [`docs/AIR-GAPPED.md`](docs/AIR-GAPPED.md).

**Docker Desktop's memory.** A scan starts eight Scanner containers at once; the
fleet peaks around 500 MB on Linux, but Docker Desktop's VM has its own limit, and
a container it cannot fit is killed with exit 137 and reported as a failed Scanner.
`valvur scan --jobs 2` runs two at a time; `VALVUR_JOBS=2` in the MCP server's
environment does the same for an agent. A scan an agent no longer wants is stopped
with the `scan_cancel` tool — containers killed, nothing written — as Ctrl-C does
on the command line.

## Contributing, and reporting problems

A finding you disagree with — especially one valvur *missed* — is a bug worth
reporting. [CONTRIBUTING.md](CONTRIBUTING.md) has the setup and the short list of
things refused on principle; [SECURITY.md](SECURITY.md) is for suspected
vulnerabilities, which for a security tool include a false clean result;
[CHANGELOG.md](CHANGELOG.md) is what changed.

## Licence

Apache-2.0 — see [LICENSE](LICENSE); chosen over MIT for the explicit patent grant.
Bundled scanners keep their own licences, listed above. valvur adds no GPL or AGPL
component; the Alpine base carries GPL userland as every Linux container does, and
the published SBOM discloses all of it ([ADR-0005](docs/adr/0005-no-gpl-tools-in-the-image.md)).
