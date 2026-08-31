# valvur

**A fully offline security scanner for AI-generated code. Your source never leaves your machine — and you can prove it.**

> **Status: `0.1.0rc1`** — a release candidate, published and installable.
> `pip install valvur` · `ghcr.io/maverickhq/valvur`

---

## Why this exists

Every serious code-security scanner sends your code — or metadata about it — to
someone else's servers. For a large and growing population of developers that is
not a preference to negotiate. It is a wall:

- **Regulated industries** — finance, defence, healthcare, government, critical
  infrastructure — where "your dependency manifest is analysed on our servers"
  ends the procurement conversation.
- **Data-residency jurisdictions**, where cloud code-analysis services simply
  are not offered in a region you are permitted to use.

This tool is on the other side of that wall. It runs entirely on your machine,
with networking switched off and your source mounted read-only.

At the same time, AI now writes a fast-growing share of production code, and it
fails in ways classic scanners were never built to catch — hallucinated
dependencies that attackers pre-register, poisoned agent instruction files,
hidden Unicode directives, model output flowing into shells and interpreters.

**Offline scanning, built for how AI-generated code actually breaks.**

## The three claims

### First run, measured

| | |
|---|---|
| Image download, once | **302MB compressed** — ~24s at 100 Mbit, ~48s at 50, ~97s at 25 |
| `offline` scan thereafter | **5.6s** |

So the first run lands inside a minute on a 50 Mbit connection or better, and takes
longer on a slower one. Every run after that is just the scan. We would rather give
you the figure than a promise.

### 1. It cannot exfiltrate your code — and you can verify it

Not a privacy policy. A property you can check yourself in one command:

```bash
docker run --rm --network=none -v "$PWD:/workspace:ro" valvur scan
```

`--network=none` means no network interface exists inside the container.
`:ro` means the scanner cannot write to your source tree even if it tried.
No account, no API key, no telemetry — there is nothing to opt out of.

### 2. Security checks built for AI-generated code

Checks no other scanner ships:

- **Dependency reality / slopsquat detection.** LLMs invent package names;
  attackers register them. Research across 16 models and 576,000 samples found
  hallucinated imports at scale, over half of them pure fabrications. No advisory
  database can catch this — the package is *new*, not known-bad. We check whether
  each dependency actually exists, how old it is, how adopted it is, and whether
  it is one character from something popular.
- **Agent-config auditing.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
  `.mcp.json`, skills and prompt files — scanned for injected directives, hidden
  Unicode (zero-width, bidi, tag characters), unpinned `@main` MCP refs, blanket
  `autoApprove`, and permission-bypass flags.
- **LLM-output-to-sink taint.** Model output reaching `eval`, `exec`,
  `subprocess`, SQL or `innerHTML`.
- **Pinning hygiene.** Unpinned ranges, missing lockfiles, git dependencies on
  mutable refs.

### What leaves your machine, stated plainly

**On `offline` (the default): nothing.** There is no network interface inside the container.

**On `full`**, two checks need the network: dependency reality sends
**package names** — never source code, never file contents — to public registries to
ask whether each dependency actually exists. That is how hallucinated packages are
caught at all; no advisory database can do it, because the package is new rather than
known-bad.

Every run records this in `run.json`, and `valvur scan --offline` disables it. We
criticise competitors for being vague about exactly this, so: package names, to PyPI,
on standard and deep, and nothing else, ever.

### 3. Ten things that matter, not four hundred findings

Findings are ranked by **whether attackers are actually exploiting them**, not
by CVSS theatre — using CISA KEV (including the ransomware-campaign flag) and
FIRST EPSS. Development-only dependencies are demoted. Transitive vulnerabilities
come with the dependency path and the direct package to bump.

| Finding | CVSS | EPSS | KEV | Severity-sorted | Ranked here |
|---|---|---|---|---|---|
| CVE in a dev-only test library | 9.8 CRITICAL | 0.04% | No | **#1** | #40 |
| CVE in your production web framework | 6.5 MEDIUM | 92% | **Yes** | #40 | **#1** |

## How it compares

| | Where code is processed | Account | Fully offline | Residency | AI-code checks |
|---|---|---|---|---|---|
| **valvur** | **Your machine** | **No** | **Yes** | **Never leaves** | **Yes** |
| Snyk CLI | Snyk servers | Required | No | Vendor-controlled | Partial, SaaS-coupled |
| AWS Transform custom | AWS Batch/Fargate | Required | No | us-east-1, eu-central-1 only | No |
| SonarQube (self-hosted CE) | Your infrastructure | No | Largely | Yours | No |
| GitHub Advanced Security | GitHub | Required | No | GitHub-controlled | No |

Stated fairly: **AWS Transform custom** performs static analysis and does not
modify your code; your repository is *ephemerally cloned into AWS*, processed,
and purged, with customer-managed KMS keys and PrivateLink available. PrivateLink
keeps your code off the public internet — it does not keep it on your hardware,
and it ships in two regions. **Self-hosted SonarQube CE** keeps code on your
infrastructure; our differences there are scope and prioritisation, not residency.

## For AI coding agents — the primary way in

Add valvur to your agent's MCP configuration:

```json
{ "mcpServers": { "valvur": { "command": "uvx", "args": ["--from", "valvur", "valvur-mcp"] } } }
```

Then ask it to scan. The server is **stdio only** — no listener, no port, no network
surface — and every tool it exposes is read-only: valvur can never change your code.

## For developers

```bash
pip install valvur          # or: uv tool install valvur

# Scan the current project (default profile)
valvur scan

# Fast, fully offline pre-commit check (~60s, no network interface at all)
valvur scan --profile offline

# Everything, including container images and deep licence analysis
valvur scan --profile deep
```

Results land in `.security-scan/`. Read `SUMMARY.md` — it renders in your IDE, on
GitHub, or in any Markdown viewer. Work through `REMEDIATION.md` in order — it is ranked so the top
of the list is genuinely the most urgent thing.

**You decide which fixes to apply, and when to rescan.** There is no autonomous
loop. Applying a fix is your call; `valvur scan` again reports what you fixed,
what you skipped, and what is new.

```
.security-scan/
├── SUMMARY.md          ← start here. Bounded, leads with anything that failed
├── REMEDIATION.md      ← ranked proposal, with dependency paths and upgrade targets
├── findings.json       ← complete, normalised, schema-versioned
├── results.sarif       ← SARIF 2.1.0 for your IDE
├── sbom.cdx.json       ← CycloneDX SBOM
├── run.json            ← what ran, which versions, what was skipped and why
└── raw/                ← untouched per-tool output, so you can verify us
```

**Results are never committed.** The folder ignores itself via its own
`.gitignore`, so the guarantee holds even if someone tidies your root
`.gitignore`. Secrets are redacted in every written artifact, including `raw/`.

Suppressions live in `.security-scan.toml` at your project root, which **is**
committed so your team shares them. Every suppression needs an expiry date.

The same file takes `[scan] exclude` — repo-relative paths you have decided not to
scan, for deliberately vulnerable test fixtures and the like:

```toml
[scan]
exclude = ["tests/fixtures"]
```

valvur never excludes anything by default, and it always tells you what an exclusion
cost: the number of findings dropped and the paths that dropped them appear in
`SUMMARY.md` and `run.json`.

## For AI coding agents

If you are an AI agent working in a repository that contains `.security-scan/`:

1. **Read `SUMMARY.md` first.** It is bounded and opens with a machine-facing
   block describing the folder. Never read `raw/` — it is large and unnecessary.
2. **Work from `REMEDIATION.md`.** Items are ordered by real exploitability and
   are independently applicable.
3. **Query `findings.json` for detail** on one finding at a time. Do not load it
   whole; on a large project it will not fit your context.
4. **Never commit anything in `.security-scan/`.**
5. **Never write suppressions without asking the human.** A suppression is a risk
   acceptance decision, not a fix.
6. **A finding disappearing is not proof it was fixed.** Deleting code and
   correctly fixing it look identical to a scanner. Say what you changed.

Add this to your project's `CLAUDE.md` or `AGENTS.md`:

```markdown
## Security scanning
This project uses valvur. Run `valvur scan` to scan; results appear in
`.security-scan/`. Read SUMMARY.md then REMEDIATION.md. Never commit
`.security-scan/`. Never add suppressions without explicit human approval.
Propose fixes for approval — do not apply them and rescan autonomously.
```

## What actually does the scanning

**We do not build a general-purpose detection engine** — six best-of-breed open
source scanners do that, and they deserve the credit. What valvur adds is
orchestration, a normalised findings model, exploit-aware ranking, and a small
number of **targeted checks for AI-specific risks nobody else covers** (listed
under claim 2 above). Full credit to:

| Tool | Licence | Does |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Dependencies, IaC, container images, SBOM, licences |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets, including git history |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependencies against OSV.dev |
| [Opengrep](https://github.com/opengrep/opengrep) | LGPL-2.1 | Static analysis, many languages |
| [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Deep IaC policy |
| [Syft](https://github.com/anchore/syft) | Apache-2.0 | SBOM generation |

Exploit intelligence comes from **CISA KEV** and **FIRST EPSS** — public primary
sources, auditable and mirrorable. No proprietary vulnerability database, so
there is nothing to lock you in.

## What it deliberately does not do

Stated plainly, because tools that overclaim get found out:

- **No reachability analysis.** We do not prove a vulnerable function is actually
  called. That is a multi-year, per-language effort and we do not attempt it.
- **No autonomous fixing.** You choose the fixes. See above for why.
- **No penetration testing.** No DAST, no exploitation, no scanning deployed
  systems. Different tool, different legal posture.
- **No code-quality analysis.** Security only.
- **We will not out-detect commercial SAST.** Snyk and SonarQube have deeper
  engines on mainstream languages. We win on trust, breadth in one artifact,
  and prioritisation — not on SAST depth.

## No lock-in

SARIF 2.1.0 and CycloneDX out. Public primary sources in. Every finding is
traceable to the tool and version that produced it via `raw/` and `run.json`.
Leave whenever you want and take everything with you.

## Air-gapped operation

No egress? Mirror the vulnerability database into your own OCI registry and point
valvur at it:

```bash
export VALVUR_DB_REPOSITORY=registry.internal/mirror/trivy-db
valvur update          # fetches from your mirror, not the internet
valvur scan            # scans offline against the cached copy
```

The database deliberately lives **outside** the image, so mirroring needs no special
build — and a six-month-old image never implies six-month-old vulnerability data.

## Running on AWS

The same image runs on ECS/Fargate via ECR — identical artifact, no
AWS-specific code paths, no behavioural difference. Local is the default and
always will be.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

Apache-2.0 rather than MIT for the explicit patent grant — this is a security
tool, and a contributor's patents should not become a downstream user's problem.

Bundled scanners retain their own licences, listed above. No GPL-licensed tools
are included in the distributed image.
