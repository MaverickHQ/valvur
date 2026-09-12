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
| `valvur update`, once | **~116MB** database, **~30MB** package-name index — and the index's first fetch walks the npm registry: **~5.5 minutes**, measured 2026-09-12 |
| `offline` scan, application code | **~7s** |
| `offline` scan, with infrastructure code | **~17s** |

So the image lands inside a minute on a 50 Mbit connection or better, and the first
`valvur update` is the slow part — once. Every run after that is just the scan, and
every later `update` is seconds. We would rather give you the figure than a promise.

The difference between those two rows is Checkov, which costs about ten seconds of
fixed startup whatever it finds. It runs only when there is infrastructure to
analyse — a Dockerfile, terraform, Kubernetes manifests, CI workflows, a
CloudFormation or Helm template. When it is skipped, `SUMMARY.md` and `run.json` both
say so and why, because a scanner that did not run must never look like one that ran
and found nothing.

Measured 2026-09-05 on a warm image and database: 7.1s on a 69-file Python project,
17.7s on a 109-file TypeScript project with GitHub Actions workflows, 23.4s on this
repository's own 38,697 lines.

### 1. It cannot exfiltrate your code — and you can verify it

Not a privacy policy. A property you can check yourself. No account, no API key, no
telemetry — there is nothing to opt out of.

The `offline` **Profile** is the default, and it has two parts to verify, because one
flag only covers one of them.

**The Scanners** run in containers launched with `--network=none`. There is no
network interface inside them, and the source is mounted `:ro` so they cannot write
to your tree either.

**The host process** that orchestrates them is not in a container, and could open a
socket. It has a reason to: exploit enrichment fetches EPSS scores from FIRST — on
`full` only, gated by one condition. So check both:

```bash
python3 scripts/verify-offline.py /path/to/your/repo
```

It asserts `--network=none` on every Scanner the Profile runs, then poisons every
connect path in the process and runs a real scan. It reports what it cannot prove as
well as what it can.

**Stronger, on Linux** — a proof the process cannot influence, because the OS denies
it the network outright:

```bash
unshare -rn valvur scan --profile offline
```

No privileges needed. It works because the container runtime is reached over a unix
socket rather than the network.

**On macOS** there is no `unshare` equivalent. The platform-independent version is to
disconnect the machine and run the scan: once the image and vulnerability database
are cached, `offline` needs nothing else. If it completes with the same findings,
nothing left.

### 2. Security checks built for AI-generated code

Checks no other scanner ships:

- **Dependency reality / slopsquat detection.** LLMs invent package names;
  attackers register them. Research across 16 models and 576,000 samples found
  hallucinated imports at scale, over half of them pure fabrications. No advisory
  database can catch this — the package is *new*, not known-bad. We check whether a
  dependency actually exists, how old it is, how adopted it is, and whether it is one
  character from something popular.

  > **Coverage today: Python and npm.** `requirements*.txt` and `pyproject.toml`
  > (PEP 621 and Poetry) against PyPI; `package.json` against the npm registry. Direct
  > manifests, never lockfiles — a lockfile is a resolved transitive tree, and the
  > invented name is in the file a human or an agent edited.
  >
  > **And it runs offline.** *Does this package exist?* is answered from a local index
  > of every name on PyPI and npm — 890,000 and 4.4 million of them, exact, no bloom
  > filter — fetched by `valvur update` into the same host cache as the vulnerability
  > database and mounted read-only into the container. No package name leaves the
  > machine on the default profile. Only *how old is it?* still needs a registry, and
  > that is what `full` adds.
  >
  > **JVM and Go are checked on `full` only.** `pom.xml`, Gradle build scripts and the
  > version catalog against Maven Central; `go.mod` against the Go module proxy. Neither
  > registry publishes a name list an offline index could be built from — Maven
  > Central's only one is 3.2GB, and Go's is a feed of versions, not a list of modules
  > — so on `offline` the run says these were not checked, rather than failing or
  > pretending.
  >
  > **Cargo, Ruby and PHP have no existence check.** A project using one gets a
  > finding saying so, on every profile, rather than a clean result it did not earn.
  > That reporting is the part we consider non-optional: a check that silently covers
  > nothing is worse than one that says it does not apply.
  >
  > **Known-vulnerability scanning needs a lockfile.** Trivy reads `package-lock.json`,
  > `yarn.lock` or `pnpm-lock.yaml` — never `package.json` alone — and likewise
  > `Gemfile.lock`, `Cargo.lock`, and a pinned `requirements.txt` or `uv.lock` rather
  > than `pyproject.toml`. A repository that commits none of them (Express, for one)
  > has its dependencies checked by nothing, and Trivy says so by saying nothing. So
  > valvur says it instead: a coverage note, and the run reads `inconclusive` rather
  > than `clean`. Found by the public corpus on its first run.
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

**On `full`**, two things reach the network. OSV-Scanner sends the names and versions
in your lockfiles to api.osv.dev for a second advisory source. The dependency-reality
check sends **package names** — never source code, never file contents: to PyPI and
the npm registry, only the names the local index has already confirmed exist, to ask
how old each one is, so a hallucinated Python or npm name is settled on your machine
and never sent anywhere; and to Maven Central and proxy.golang.org, every declared JVM
coordinate and Go module, to ask whether it exists, because no offline index can be
built for those. Enrichment sends the CVE identifiers it found to FIRST for EPSS scores.

Every run records this in `run.json`, and `valvur scan --offline` disables it. We
criticise competitors for being vague about exactly this, so: package names, to those
four registries, on `full`, and nothing else, ever.

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

# Scan the current project. The default profile is `offline`: no network
# interface inside any container, and nothing sent from the host either.
valvur scan

# Add the second advisory source, and the age check on dependencies. Both send
# dependency package NAMES — never source — to public registries.
valvur scan --profile full
```

Keep the vulnerability database and the package-name index current — the check
costs nothing when they are, so this is safe in a pre-commit hook, a cron entry or CI:

```bash
valvur update --if-stale    # ~116MB database + ~30MB index when out of date; one file read when not
```

The first `valvur update` walks the whole npm registry — about five minutes and
146MB, measured — because npm publishes no list of its package names. Every later
one applies the change feed instead: seconds, and a few hundred kilobytes.

A scan with a database older than a week reports **`inconclusive`** rather than
`clean` when it finds nothing. What was found is always real; only *absence* needs
current data to mean anything.

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

## For an agent reading the results

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
This project uses valvur. Scan with the `valvur` MCP tools if you have them:
call `scan`, then `scan_status` until it reports DONE. Otherwise run
`valvur scan`. Results appear in `.security-scan/`: read SUMMARY.md, then
REMEDIATION.md. Never commit `.security-scan/`. Never add suppressions without
explicit human approval. Propose fixes for approval — do not apply them and
rescan autonomously.
```

> **Tested against a real agent, not just written** (task 10.2.5). The first version
> said only *"Run `valvur scan`"*, and Claude Code did exactly that — two turns of
> `which valvur` and a not-found error before it looked for the MCP tool it already
> had. The snippet now names the tool first, because the agent will do what the text
> says, in the order it says it.

## What actually does the scanning

**We do not build a general-purpose detection engine** — six best-of-breed open
source scanners do that, and they deserve the credit. What valvur adds is
orchestration, a normalised findings model, exploit-aware ranking, and a small
number of **targeted checks for AI-specific risks nobody else covers** (listed
under claim 2 above). Full credit to:

| Tool | Licence | Does |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Dependency vulnerabilities |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets, including git history |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependencies against OSV.dev |
| [Opengrep](https://github.com/opengrep/opengrep) | LGPL-2.1 | Static analysis, many languages |
| [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Deep IaC policy |
| [Syft](https://github.com/anchore/syft) | Apache-2.0 | SBOM generation, and the dependency licences read from it |

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

No egress? `valvur update` fetches three things, and each has a mirror setting.
Measured end to end on 2026-09-12 — a registry on a Docker network with no route
out, a static file server, and every other connection refused — `valvur update`
and an `offline` scan both complete from the mirrors alone.

```bash
# 1. The vulnerability database: an OCI artifact, mirrored into any registry.
#    (once, from a connected machine — oras, crane and skopeo all work)
oras cp ghcr.io/aquasecurity/trivy-db:2 registry.internal/mirror/trivy-db:2

# 2. The package-name index and CISA KEV: plain files, served by any web server.
#    (from a machine that has run `valvur update`)
cp ~/.cache/valvur/names/{pypi.txt,npm.txt,metadata.json} /srv/valvur-mirror/
curl -o /srv/valvur-mirror/kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# 3. On the air-gapped machine:
export VALVUR_DB_REPOSITORY=registry.internal/mirror/trivy-db
export VALVUR_DB_INSECURE=1              # only if the registry is plain HTTP or self-signed
export VALVUR_NAME_INDEX_URL=http://mirror.internal/valvur-mirror
export VALVUR_KEV_URL=http://mirror.internal/valvur-mirror/kev.json
valvur update          # fetches from your mirrors, not the internet
valvur scan            # scans offline against the cached copies
```

`VALVUR_DB_INSECURE` exists because the first real test found it missing: Trivy
assumes TLS for any registry that is not `localhost` or a private-range IP literal,
so an internal mirror on plain HTTP fails with *"server gave HTTP response to HTTPS
client"* until it is set. If your mirror registry lives on a named container
network, `VALVUR_CONTAINER_NETWORK` joins the update container to it. And
`scripts/verify-mirror.py` runs the update and a scan with every connection outside
your mirrors refused, and tells you if anything tried.

The database, the index and KEV all deliberately live **outside** the image, so
mirroring needs no special build — and a six-month-old image never implies
six-month-old data. The age of each is reported in `run.json`, computed from when
the data was built, not when your mirror served it.

## Platforms

| | |
|---|---|
| macOS, Linux — Docker or Podman | **Supported**, tested on every commit against both runtimes |
| `linux/amd64` and `linux/arm64` | Both, **from 0.2.0**. `0.1.0rc1` was published `arm64` only — a defect, not a policy |
| Windows via **WSL2** | Supported — inside WSL valvur is running on Linux |
| Native Windows | **Not claimed.** It may work; nobody has tested it, so valvur says so at startup rather than pretending either way |

**SELinux-enforcing hosts (RHEL, Fedora, CentOS Stream).** Measured on Fedora CoreOS
44 with a workspace on native xfs under `$HOME`: a container may not read a directory
labelled `user_home_t` or `admin_home_t`, so valvur **refuses to scan** and tells you
why. It does not report a false clean.

valvur labels its own scratch and cache mounts automatically. It does **not** relabel
your source tree unless you ask, because `:z` rewrites the SELinux context of every
file in it and the change outlives the scan:

```bash
VALVUR_SELINUX_RELABEL=1 valvur scan .
```

Or do it yourself once — `chcon -R -t container_file_t .`, undone with
`restorecon -R -F .` (the `-F` is required; `container_file_t` is a customizable type
and restorecon skips those unless forced).

`:Z` is deliberately not offered: it stamps a private MCS category, and valvur runs its
scanners concurrently against one mount.

## Running elsewhere

The image is a plain OCI artifact with **no cloud-specific code paths**, so it pushes
to any registry — ECR included — and runs wherever a container runs.

Orchestration is the part to think about. valvur is a thin host shim that *launches*
scanner containers ([ADR-0001](docs/adr/0001-thin-host-shim-read-only-container.md)),
so wherever you run it needs to give the shim a container runtime to talk to. A build
agent, a VM or ECS on EC2 can do that. **Serverless container platforms generally
cannot** — AWS Fargate exposes no Docker socket and no privileged mode — and we have
not run valvur there, so we do not claim it works.

Local is the default and always will be.

## Contributing, and reporting problems

- **A finding you disagree with** — a false positive, or something valvur missed —
  is a bug worth reporting. The second kind especially: a missed finding is the worst
  failure this tool has, because it tells you your code is safe when it is not.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** covers the setup, the testing style, and the
  handful of things that will be refused on principle rather than on merit. Reading
  that list first is kinder than a rejected pull request.
- **[SECURITY.md](SECURITY.md)** — please do not open a public issue for a suspected
  vulnerability. It states what is in scope, which for a security tool includes a
  false clean result.
- **[CHANGELOG.md](CHANGELOG.md)** — what changed, including the profile rename and
  how the old names still resolve.
- **[docs/EVALUATING.md](docs/EVALUATING.md)** — for someone deciding whether this is
  worth their time: how to verify the signed image, how to prove it does not phone
  home, how to read the three statuses, and a plain list of what it does **not**
  claim. Written to be read sceptically.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — short, and only what will be enforced.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

Apache-2.0 rather than MIT for the explicit patent grant — this is a security
tool, and a contributor's patents should not become a downstream user's problem.

Bundled scanners retain their own licences, listed above.

**valvur adds no GPL- or AGPL-licensed component of its own.** The base image is
Alpine Linux, whose userland carries GPL components — busybox, apk-tools, musl-utils
and others — as every Linux container does; the published SBOM discloses all of them,
and CI fails the build if a GPL component appears in what *we* add
([ADR-0005](docs/adr/0005-no-gpl-tools-in-the-image.md), F10.4). Opengrep is LGPL-2.1
and ships as an unmodified binary invoked as a subprocess, which is aggregation
rather than a derivative work ([ADR-0004](docs/adr/0004-opengrep-not-semgrep.md)).
