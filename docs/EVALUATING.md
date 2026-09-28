# Evaluating valvur

For someone deciding whether this is worth their time. It answers the questions a
reviewer actually has, in the order they have them, and it is deliberately specific
about what valvur does **not** do — because a security tool that oversells is worse
than one that undersells.

The [README](../README.md) is the introduction. This is the audit.

---

## 1. Install it

```bash
pipx install valvur          # or: uv tool install valvur
valvur update                # the image, the vulnerability database and the name index — optional: a first scan fetches what is absent
valvur scan .
```

Needs Docker or Podman. The shim is Python, stdlib only, no runtime dependencies:
the Scanners live in one OCI image, so nothing is installed onto your machine beyond
the shim itself.

### The true first run, measured

The acceptance set judges every phase of the build on this Mac through Docker Desktop
and on GitHub's Linux runner; each run is in [`acceptance/`](acceptance/). The first
run, measured 2026-09-28 (`acceptance/r7.md`):

| | size | wall-clock | what you are looking at |
|---|---|---|---|
| `pip install valvur` | under 1 MB | 1.7 s with pip, 0.9 s with uv, measured 2026-09-20 | pip |
| the image, pulled by the first scan or `valvur update` | `0.5.0`: 256 MB on amd64, 246 MB on arm64, compressed | your connection's | the runtime's pull, said on the status line |
| a first `valvur scan` from an empty cache, image already local, acceptance repository 2 | 123 MB of vulnerability database, 36 MB of signed index, 35 and 217 MB of OSV's PyPI and npm databases | **59 s** in all: 21.5 s the database, 8.3 s the index, 2.5 and 6.0 s OSV's, the rest the Scanners | one line per fetch, *"— the first run only"*, then the result |
| a scan after that, the seven application repositories | nothing fetched | **5.6 to 16.4 s** on the Mac; **3.0 to 14.8 s** on Linux | the result |
| the Terraform module, where Checkov runs | nothing fetched | **60.0 s** on the Mac, **76.0 s** on Linux | the result |
| the gate's shape: a few hundred source files beside a gitignored archive of 100,000 | nothing fetched | **7.4 s** on the Mac, **8.3 s** on Linux, from 166 s and 105 s before R3 | the archive is never read: the File Set is the git view (ADR-0021) |
| `valvur update` **if the published index is unreachable**, measured 2026-09-20 | about 700 MB: the five registries walked directly, npm 146 MB in 439 requests, the crates.io dump 381 MB | **about seven minutes**, five and a half of them npm | `npm: 499,942 names so far` about every 40 s |

A scan fetches what is **absent** and refreshes what is **stale**, saying so as it
does and recording each fetch in `run.json` (ADR-0025); `fetch = "never"` in the
machine's settings turns both off, and a scan then says its data was not refreshed.
The index comes from a workflow in this repository that walks the registries once a
day and publishes the result as a signed OCI artifact
([ADR-0018](adr/0018-offline-package-name-index.md), amended). The walk remains
`valvur update --build-index`, the fallback, and the last row is what it costs; a
scan that cannot reach the published index says so and names `valvur update`, and
never starts a seven-minute walk on its own.

If you are evaluating on a laptop with a metered or slow connection, run
`valvur update` before the meeting.

One thing that measurement found: a Python **without a CA bundle** — python.org's
macOS installer until you run its *Install Certificates.command* — fails every
host-side fetch with `CERTIFICATE_VERIFY_FAILED`. `pip` works because it bundles its
own certificates; valvur has no dependencies and uses the interpreter's. The image
and the database still arrive (the runtime and Trivy fetch those), KEV and the index
do not, and the message names the cause. A Python from `uv`, Homebrew, pyenv or a
Linux distribution has certificates. `valvur doctor` checks — it counts the roots
the interpreter would verify against, and that number is 0 on python.org's build
and 128 on every interpreter that worked — and every other precondition a first run
has failed on for real: the runtime found and running, the image present,
compatible and able to start, the database and the index present and current, the
SELinux label on the tree, and which MCP client configuration names valvur. One
line each, the fix on any that would fail a scan, exit 1 if one would; `--network`
adds one bounded TCP connect per registry a first run and `full` need, and honours
every mirror setting in [AIR-GAPPED.md](AIR-GAPPED.md). It is also the `doctor`
MCP tool, so an agent whose scan failed has somewhere to go, and `scan_status`
tells it so. Measured 2026-09-13: 3.4s on the CLI, 1.7s over MCP, 8.8s with
`--network`; on this project's own machine it found Kiro's MCP switched off in the
user settings, which no scan would have said.

As an MCP tool, which is the primary path:

```json
{ "mcpServers": { "valvur": { "command": "valvur-mcp" } } }
```

`valvur-mcp --help` describes the six tools it exposes. None of them can change your
source: it is never mounted, only copied into the Scan Container, and no tool writes,
fixes or applies anything (ADR-0009). Three only read, `scan_status`, `findings` and
`doctor`, and declare `readOnlyHint: true`; `scan`, `scan_cancel` and `update` act on
your machine (a results folder, an image pull, the host cache, a container started
and stopped) and declare `false`, so a client may ask before running them. `scan`
returns the result itself, with progress on the way (ADR-0024): there is nothing to
poll.

**In Kiro**, the same block goes in `.kiro/settings/mcp.json` (workspace) or
`~/.kiro/settings/mcp.json` (user). Kiro starts the server the moment the file is
saved and logs it under *Kiro – MCP Logs*; each tool asks for consent on first use.
Two things that stop it silently: MCP has to be enabled (`kiroAgent.configureMCP`
— a workspace `.vscode/settings.json` can set it), and Kiro has to be signed in,
because the agent, and with it every MCP server, does not initialise until it is.
Verified 2026-09-12: server connected 1.6s after sign-in, and the agent ran `scan`,
polled `scan_status`, called `list_findings`, and reported the planted injection,
the hidden Unicode and the KEV-listed CVE, with the one failed Scanner named as
such rather than folded into a clean-looking summary. Since then `scan` returns the
result and `list_findings` is `findings` (R6); Kiro's calls, in the MCP SDK's
documented shape, are replayed against the server in CI, and a pass through Kiro's
own window is the owner's to record.

## 2. Verify the image before you trust it

The signature is keyless, so there is no key to trust — only a public transparency-log
entry naming the workflow that built it:

```bash
cosign verify ghcr.io/maverickhq/valvur@<digest> \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Build provenance, and the SBOM attached to every release:

```bash
gh attestation verify oci://ghcr.io/maverickhq/valvur:<version> --repo MaverickHQ/valvur
```

Signed **by digest, not by tag** — a tag can be moved, and signing one certifies
whatever it points at today.

The package-name index is published the same way, under the same identity, and
`valvur update` verifies it for you when `cosign` is on your PATH — the line
`signature: verified` (or `not verified: cosign is not installed`) is printed and
recorded in the index's metadata. **Install cosign later and the next `valvur
update` checks the index you already have** (27.1.3): it verifies the digest it
recorded, prints the new verdict and keeps it, without fetching a byte. A cosign
that refuses stops the update. To check by hand:

```bash
cosign verify ghcr.io/maverickhq/valvur-index:latest \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/.github/workflows/index.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For comparison, the vulnerability database beside it is pulled by Trivy with no
signature at all — `ghcr.io/aquasecurity/trivy-db:2` publishes none.

## 3. Prove it does not phone home

The claim is that source never leaves your machine, and it has two halves.

**The containers** run with `--network=none` on the default profile. No interface, not
a policy.

**The host shim** is the half a `--network=none` flag cannot cover. Before the Scan
Container starts, it fetches public data a scan lacks or holds stale, and says so
(23.2.4, 24.1, ADR-0025): the image, the vulnerability database, the name index, and
OSV's offline database for each ecosystem the lockfiles use (R4.6). Each is a pull of
a fixed public name and carries nothing from the workspace, though which OSV
databases it asks for says which ecosystems are present. `valvur update` does the
same ahead of time, and `fetch = "never"` turns it off. During a scan it has one
reason to reach out, fetching EPSS exploitation scores, and only on `full`. Under
`unshare -rn` on a fresh machine those fetches fail, loudly, naming each, so run
`valvur update` first if you want that proof on a first run.

```bash
scripts/verify-offline.py          # checks both halves
```

On Linux you can prove it at the OS level, without privileges, because the container
runtime is reached over a unix socket:

```bash
unshare -rn valvur scan --profile offline .
```

macOS has no equivalent. Saying otherwise would be exactly the overclaim this
document exists to avoid.

Every run records what left the machine, in `run.json`:

```json
"network": { "used": false, "what_left_the_machine": "nothing" }
```

On `full` that field enumerates each destination by name. **That sentence is the
claim**, not a description of it, so a registry added without amending it makes the
claim false — there is a test asserting every destination reached appears there.

## 4. Read the verdict correctly

Three statuses. The distinction between the last two is the point of the product.

| Status | What it licenses you to say |
|---|---|
| `findings` | Live problems were found in this repository. |
| `clean` | Nothing live was found, **by a scan that could support the claim**. |
| `inconclusive` | Nothing was found **and that is not evidence**. Either the vulnerability database was too old, or an ecosystem present in your repository was never inspected. |

Only **active** findings make a status `findings`. Two things deliberately do not:

- **Suppressed findings** are risks your project already recorded a decision about, in
  a committed `.security-scan.toml` with a mandatory expiry date. They are always
  listed, never hidden, and always counted separately.
- **Coverage notes** are valvur's own missing features, not defects in your code.
  Counting them would fail your CI for something you cannot fix. Two kinds: a
  *gap* — an ecosystem nothing here reads, a manifest with no lockfile — makes a
  nil result `inconclusive`, because "clean" is not ours to claim over something we
  did not look at; a *licence statement* — "licences could not be determined for
  600 of 618 dependencies", a `LICENSE` no signature matches — is listed under
  *What valvur could not read* and casts no doubt, because a licence we could not
  read is not a vulnerability we did not look for.

```
clean: 0 active, 4 suppressed
findings: 70 active, 1 not covered
```

## 5. What it does not claim

Read this before the feature list, not after.

- **It is not a scanning engine.** Detection is Trivy, Gitleaks, Opengrep, zizmor,
  Checkov, OSV-Scanner and Syft. valvur orchestrates, normalises, enriches and presents. Every
  finding names its source.
- **It is not a reachability analyser.** It does not prove a vulnerable function is
  ever called. That is a multi-year per-language effort and claiming it would be a lie.
- **It does not fix anything.** `REMEDIATION.md` is a proposal. There is no
  `scan_and_fix` tool and a test asserts none exists in the registry, so adding one
  fails the build rather than merely failing review. An agent told to drive findings
  to zero has a cheaper path via deleting code than via correct fixes.
- **The existence check is offline for Python, npm, Ruby, PHP and Rust, and
  `full`-only for JVM and Go.** `requirements*.txt` and `pyproject.toml` (PEP 621
  and Poetry), `package.json`, `Gemfile` and `*.gemspec`, `composer.json` and
  `Cargo.toml` are checked against a local index of every name on PyPI, npm,
  RubyGems, Packagist and crates.io, 900,170, 4,432,959, 196,977, 463,413 and 340,644
  on 2026-09-28, exact, fetched by `valvur update` or the first scan
  ([ADR-0018](adr/0018-offline-package-name-index.md)). `pom.xml`, Gradle scripts
  and `go.mod` are checked against Maven Central and the Go module proxy on `full`,
  because neither registry publishes a name list an offline index could be built
  from (Maven Central's only one is 3.2GB; Go's is a feed of versions). A manifest
  valvur recognises but does not read — a lone `Pipfile`, a lockfile with no
  manifest beside it — produces a coverage note rather than a clean result. Every
  case is stated in the run's coverage contract.
- **Known-vulnerability scanning needs a lockfile.** Measured 2026-09-12: Trivy
  produces no result — not zero findings, no scan — for `package.json`,
  `pyproject.toml`, `Gemfile` or `Cargo.toml` without a lockfile (or a pinned
  `requirements.txt`) beside it. Express commits no lockfile and read `clean` with
  thirty dependencies unchecked, until the public corpus found it. Now it is a
  coverage note and the run is `inconclusive`. Direct manifests are read for
  *existence* precisely because that is where a hallucinated name is written;
  lockfiles are read for *vulnerabilities* because that is where the versions are.
  **A `requirements.txt` counts only for its pinned lines** (task 25.3, found by
  the corpus on 2026-09-18): Trivy reads `==` and nothing else, so a file of
  ranges — `transformers>=4.46.0` — is present and checks nothing, and read as
  *checked* until the note learned to count pins. It now names the file and how
  many of its lines are ranges, and the run is `inconclusive`; a mixed file is
  *partly* checked and says so. OSV-Scanner evaluates every range at its
  lower bound and reports each advisory since — 97 raw on that one file with
  OSV-Scanner 2.6.0 (193 with 2.2.4, which read the file twice), against
  versions nothing installs — and those are dropped with the count in `run.json`
  and `SUMMARY.md`, never shown as the project's.
- **OSV-Scanner earns its place on `offline` with one kind of finding.** Its data
  carries the known-malicious `MAL-` packages from ossf/malicious-packages, which no
  other source here reports: with its offline database, measured on acceptance
  repository 8's planted `MAL-2023-1` with no network (R4.6, ADR-0023), it runs on
  `offline` from a database per ecosystem in the host cache. On `full` it asks
  api.osv.dev instead, which receives your lockfile's names and versions. Its other
  advisories mostly repeat Trivy's: on the twelve-repository corpus (task 23.4.5, run
  34764187516) it added **121** findings on cobra, every one a Go standard-library
  advisory keyed on `go 1.15` in `go.mod`, which Trivy reports only from compiled
  binaries; **1** on flask; and **0** on the other ten. Reading npm's database costs
  it about ten seconds on every npm project, on both lanes (`acceptance/r4.md`).
- **The Opengrep rules are a supplement, not the product, and the LLM-output rules
  are not a coverage claim.** Measured on eleven real repositories (task 22.E.2):
  75 findings, 64 of them tag-pinned GitHub Actions and the other 11 rejected by a
  reviewer to the last one. The taint rules from a model call to `eval`/`exec`, a
  shell or `innerHTML`, with sources for the OpenAI, Anthropic, Gemini, LangChain,
  litellm and ollama SDKs, fire on all fifteen planted flows in the fixture and have
  never fired on real code (23.5.3): on the two corpus projects that execute model
  output, smolagents and pandas-ai, the flow crosses a class boundary, Opengrep's
  taint tracking is intra-procedural and does not see it, and the INFO sink
  inventory names both `exec` sites. They are ranked `low`; the AI-specific claim
  rests on the Checks above.
- **On SELinux-enforcing hosts the source's label no longer matters** (since `0.7.0`,
  ADR-0022). Measured on Fedora CoreOS 44, native xfs under `$HOME`, before it: a
  container may not read a `user_home_t` directory, so a first run on RHEL failed until
  the tree was relabelled, a trade ADR-0017 accepted rather than rewrite the labels of
  the code you asked us not to touch. The source is now copied into the Scan Container
  on its standard input and never mounted, so there is nothing to relabel, and
  `VALVUR_SELINUX_RELABEL` does nothing. valvur still labels its own cache mounts.
- **It has not been run on a serverless container platform, and does not claim to.**
  The image is a plain OCI artifact with no cloud-specific code paths, so it pushes
  to any registry and runs wherever a container runs. But valvur is a thin host shim
  that *launches* scanner containers
  ([ADR-0001](adr/0001-thin-host-shim-read-only-container.md)), so wherever it runs
  must give it a container runtime to talk to. A build agent, a VM or ECS on EC2 can;
  AWS Fargate exposes no Docker socket and no privileged mode, and we have not run it
  there. Local is the default and always will be.
- **It is not a pen-test tool.** No DAST, no exploitation, no scanning of deployed
  systems.

## 6. Judge it by how it handles being wrong

The interesting question about a security tool is not what it finds — it is what it
does when it cannot find anything.

- A Scanner that crashed appears **at the top** of `SUMMARY.md`, and the run is marked
  incomplete. A silent failure manufactures false confidence and is worse than no scan.
- A Scanner that was **skipped** (Checkov, where there is no infrastructure to
  analyse) says so with its reason, in `run.json` and `SUMMARY.md`. A conditional
  Scanner is one that can silently stop running.
- A Scanner the **profile did not run** is named on every scan, whether or not
  anything was found.
- **How long each Scanner took** is in `run.json` (`duration_s`), on the `scan`
  reply's `slowest`, and as one line in `SUMMARY.md`. Every Scanner runs at once in
  the one Scan Container, so the slowest is about what the scan cost. On the
  acceptance set it is OSV-Scanner reading npm's database on an npm project, and
  Checkov on the Terraform module, the one repository where Checkov runs at all: a
  repository with no infrastructure but its workflows no longer starts it (R4.3).
  The number is on every run so you can see yours rather than trust ours.
- An **ecosystem nothing inspects** produces a finding saying so.
- **Excluded paths** are reported with the count they cost. An exclusion you cannot
  see is indistinguishable from a scan that found nothing.
- A **fingerprint algorithm change** is announced, because otherwise every finding
  silently reappears as new and every committed suppression stops matching.
- The **agent snippet was tested against an agent**, not just written. The first
  version said only *"Run `valvur scan`"*, and Claude Code did exactly that — two
  turns of `which valvur` and a not-found error before it looked for the MCP tool it
  already had. The snippet in the README names the tool first, because the agent
  will do what the text says, in the order it says it.

## 7. How it compares

| | Where code is processed | Account | Fully offline | Residency | AI-code checks |
|---|---|---|---|---|---|
| **valvur** | **Your machine** | **No** | **Yes** | **Never leaves** | **Yes** |
| Snyk CLI | Snyk servers | Required | No | Vendor-controlled | Partial, SaaS-coupled |
| AWS Transform custom | AWS Batch/Fargate | Required | No | us-east-1, eu-central-1 only | No |
| SonarQube (self-hosted CE) | Your infrastructure | No | Largely | Yours | No |
| GitHub Advanced Security | GitHub | Required | No | GitHub-controlled | No |

Stated fairly: **AWS Transform custom** performs static analysis and does not modify
your code; your repository is *ephemerally cloned into AWS*, processed, and purged,
with customer-managed KMS keys and PrivateLink available. PrivateLink keeps your code
off the public internet — it does not keep it on your hardware, and it ships in two
regions. **Self-hosted SonarQube CE** keeps code on your infrastructure; our
differences there are scope and prioritisation, not residency. On SAST depth alone,
Snyk and SonarQube have deeper engines on mainstream languages and we do not claim
otherwise.

## 8. Read the record

The repository keeps its own audit trail, and it is not flattering by design.

- [`.kiro/specs/valvur/requirements.md`](../.kiro/specs/valvur/requirements.md) — 136
  numbered requirements. Unmet ones are annotated as unmet, with the measurement.
- [`.kiro/specs/valvur/tasks.md`](../.kiro/specs/valvur/tasks.md) — the current build,
  each task closed with its measurement, and the owner's queue; the earlier phases,
  with what went wrong while doing them, are in [`history/`](history/). Several
  entries record a premise asserted and then measured to be false.
- [`docs/acceptance/`](acceptance/) — the eight repositories and four probes every
  phase is judged on, run on a Mac and on Linux, and the agent's score, misses
  included.
- [`docs/adr/`](adr/) — 25 decisions with their rejected alternatives.
- CI runs a **traceability ratchet** that fails when a requirement loses its last
  citation, and a **self-scan gate** that fails on any unsuppressed finding in
  valvur's own repository.

The clearest single illustration: a Check was added to report ecosystems valvur cannot
inspect, its tests passed, and it shipped. A scan of six real local projects then
showed it never ran on the default profile at all, because it had been placed inside a
network-gated Check. Unit tests could not have caught that, and no amount of reasoning
did. Running it against real repositories did.
