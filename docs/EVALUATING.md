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

Needs Docker or Podman. The shim is Python, stdlib only, no runtime dependencies —
the scanners live in one OCI image, so nothing is installed onto your machine beyond
a ~200-line launcher.

### The true first run, measured

The number a competitor would quote, measured on **2026-09-13 against the published
`0.2.0`** — a clean venv, an empty cache, the image removed, on an Apple-silicon Mac
with Docker Desktop — so it is here before they do (22.B.4, re-measured for 23.1.1):

| | bytes | wall-clock | what you are looking at |
|---|---|---|---|
| `pip install valvur` | <1MB | **1.7s** | pip |
| `valvur update`, first time | **~475MB**: the image 320MB compressed (pulled here since 23.2.4, and said on the status line if a scan has to do it), vulnerability database 118MB, the published name index 34MB (one signed OCI artifact: PyPI, npm, RubyGems, Packagist and crates.io), KEV 2MB | **53s** | docker's layer bars, Trivy's progress bar, then one line per ecosystem with its build time and `signature: verified` |
| `valvur update`, first time, **if the published index is unreachable** | **~700MB**: as above, but the five registries walked directly — npm 146MB in 439 requests, the crates.io dump streamed until its crate list ends (381MB), PyPI 10MB, RubyGems 3MB, Packagist 4MB | **~7 minutes**, five and a half of them npm | `npm: 499,942 names so far` about every 40s |
| `valvur update`, every later time | two small requests when the published index has not moved; a few hundred KB when it has | seconds | one line per source |
| first `valvur scan` | — | **33s** on the ten-file `tests/fixtures/broken-repo` (Terraform present, so Checkov runs); 7–24s on the real projects in the README. On GitHub's `ubuntu-latest` runner, the twelve-repository corpus: **14–18s** on every application repository from 22k to 100k lines, 88s on a Terraform module (Checkov analysing it) — run 34764187516, 2026-09-13 | eight scanner names, each turning `ok` |
| **first `scan` over MCP, nothing run first** — no image, empty cache, one tool call (24.1) | the same ~475MB | **110s** to `complete: True`: image pulled 22s, database fetched 30s, index fetched 7s, then the Scanners | `scan_status` reads *"Now: pulling ghcr.io/… (223MB) — the first run only"*, then *"fetching the vulnerability database (119MB)"*, then *"fetching the package-name index (35MB)"*, each gone once it is over |

**A minute and a half from nothing to a first result, measured — two minutes over
MCP with nothing run first — or about eight minutes on the day the published index
cannot be reached.** The README once promised sixty seconds; then this table said
eight minutes, because npm publishes no list of its package names and every machine
walked the registry's replication feed itself. Since 23.2.1 a workflow in this
repository does that walk once a day and publishes the result as a signed OCI
artifact ([ADR-0018](adr/0018-offline-package-name-index.md), amended). The walk
remains the fallback for `valvur update`, and the second row is what it costs; a
scan that finds the index absent pulls the published one and, if it cannot, says
so and names `valvur update` — it never starts a seven-minute walk on its own.
`valvur update` is therefore optional before the first scan and remains the way to
**refresh**: a scan fetches what is *absent*, and never touches what is *stale*
(task 14.2) — the warning stands, and you decide.

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

`valvur-mcp --help` describes the four tools it exposes. All four are read-only with
respect to your source.

**In Kiro**, the same block goes in `.kiro/settings/mcp.json` (workspace) or
`~/.kiro/settings/mcp.json` (user). Kiro starts the server the moment the file is
saved and logs it under *Kiro – MCP Logs*; each tool asks for consent on first use.
Two things that stop it silently: MCP has to be enabled (`kiroAgent.configureMCP`
— a workspace `.vscode/settings.json` can set it), and Kiro has to be signed in,
because the agent, and with it every MCP server, does not initialise until it is.
Verified 2026-09-12: server connected 1.6s after sign-in, and the agent ran `scan`,
polled `scan_status`, called `list_findings`, and reported the planted injection,
the hidden Unicode and the KEV-listed CVE — with the one failed Scanner named as
such rather than folded into a clean-looking summary.

## 2. Verify the image before you trust it

The signature is keyless, so there is no key to trust — only a public transparency-log
entry naming the workflow that built it:

```bash
cosign verify ghcr.io/maverickhq/valvur@<digest> \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/' \
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
recorded in the index's metadata. A cosign that refuses stops the update. To check
by hand:

```bash
cosign verify ghcr.io/maverickhq/valvur-index:latest \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For comparison, the vulnerability database beside it is pulled by Trivy with no
signature at all — `ghcr.io/aquasecurity/trivy-db:2` publishes none.

## 3. Prove it does not phone home

The claim is that source never leaves your machine, and it has two halves.

**The containers** run with `--network=none` on the default profile. No interface, not
a policy.

**The host shim** is the half a `--network=none` flag cannot cover. It has one reason
to reach out during a scan — fetching EPSS exploitation scores — and it is gated on
the `full` profile only. Before a scan, on a machine that has none of them, it
fetches the image, the vulnerability database and the name index and says so
(23.2.4, 24.1): three pulls of three fixed names, nothing from the workspace, and
`valvur update` does the same ahead of time. Under `unshare -rn` on a fresh
machine those fetches fail — loudly, naming each — so run `valvur update` first if
you want that proof on a first run.

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

- **It is not a scanning engine.** Detection is Trivy, Gitleaks, Opengrep, Checkov,
  OSV-Scanner and Syft. valvur orchestrates, normalises, enriches and presents. Every
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
  RubyGems, Packagist and crates.io — 890,000, 4.4 million, 197,000, 462,000 and
  332,000, exact, fetched by `valvur update`
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
  *partly* checked and says so. On `full`, OSV-Scanner evaluates every range at its
  lower bound and reports each advisory since — 193 raw on that one file, against
  versions nothing installs — and those are dropped with the count in `run.json`
  and `SUMMARY.md`, never shown as the project's.
- **OSV-Scanner's marginal value is measured, and small outside Go.** On the
  twelve-repository corpus (task 23.4.5, run 34764187516): `full` added **121**
  findings to `offline` on cobra — every one a Go standard-library advisory keyed on
  `go 1.15` in `go.mod`, which Trivy reports only from compiled binaries, and which
  describe the toolchain rather than the repository's code; **1** on flask (a
  disputed Click advisory Trivy's database does not carry); and **0** on the other
  ten, across npm, Ruby, PHP, Rust, Java, Python and Terraform. It stays on `full`
  because the Go toolchain gap is real for a Go application, it costs about a second,
  and it is the second primary source (§3 of CLAUDE.md) — but if you scan no Go, it
  will find you nothing Trivy did not, and it sends your lockfile's names and
  versions to api.osv.dev, which `offline` never does.
- **The Opengrep rules are a supplement, not the product — and the LLM-output
  rules are not a coverage claim.** Measured on eleven real repositories (task
  22.E.2; twelve on the run of 2026-09-13, same result): 75 findings, 64 of them tag-pinned GitHub Actions and the other 11
  rejected by a reviewer to the last one; the four LLM-output-to-sink rules fired
  zero times, including on `simonw/llm`. Those four are what they are: taint rules
  whose only sources are a completion call from the OpenAI, Anthropic or Gemini SDK
  (`messages.create`, `chat.completions.create`, `generate_content`) flowing into
  `eval`/`exec`, a shell or `innerHTML`, plus one plain rule for string-built SQL
  with no model source at all. They fire on our fixture; whether they catch
  anything in the wild is **unmeasured, not proven** — no repository in the corpus
  executes model output, so a zero there is not a miss and not a hit. Until that is
  measured (task 23.5.3), the README says so and the AI-specific claim rests on the
  Checks above. They are all ranked `low` now, bar the ones that have never fired
  on real code.
- **On SELinux-enforcing hosts valvur refuses to scan until you act.** Measured on
  Fedora CoreOS 44, native xfs under `$HOME`: the container may not read a
  `user_home_t` directory. valvur fails loudly rather than reporting a false clean,
  and will not relabel your source tree unless you set `VALVUR_SELINUX_RELABEL=1` —
  `:z` persists after the scan, and rewriting the labels of the code you asked us not
  to touch is not a thing to do quietly. That means a first run on RHEL fails, and
  that is a deliberate trade rather than an oversight. To do it yourself, once:
  `chcon -R -t container_file_t .`, undone with `restorecon -R -F .` (the `-F` is
  required; `container_file_t` is a customizable type and restorecon skips those
  unless forced). `:Z` is deliberately not offered: it stamps a private MCS category,
  and valvur runs its scanners concurrently against one mount.
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
- **How long each Scanner took** is in `run.json` (`duration_s`), on `scan_status`,
  and as one line in `SUMMARY.md`: *"slowest: checkov 40.9s"*. The fleet runs
  concurrently, so the slowest Scanner is about what the scan cost, and it is
  usually Checkov — measured 2026-09-13 on the ten-file fixture, published image,
  a loaded laptop: checkov 40.9s, opengrep 26.0s, syft 20.9s, the rest 8–16s, the
  scan 44s. Ten minutes earlier the same scan on a quiet machine took 33s. On
  GitHub's Linux runner the same day, across twelve real repositories: Checkov
  14–17s on every one that has a workflow file to analyse (they all do), every
  other Scanner 1–4s, and Checkov 88s on the one Terraform module — a container
  start costs 2–3s there against 10–16s through Docker Desktop. The number is on
  every run so you can see yours rather than trust ours.
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
- [`.kiro/specs/valvur/tasks.md`](../.kiro/specs/valvur/tasks.md) — every task, with
  what went wrong while doing it. Several entries record a premise I asserted and then
  measured to be false.
- [`docs/adr/`](adr/) — 16 decisions with their rejected alternatives.
- CI runs a **traceability ratchet** that fails when a requirement loses its last
  citation, and a **self-scan gate** that fails on any unsuppressed finding in
  valvur's own repository.

The clearest single illustration: a Check was added to report ecosystems valvur cannot
inspect, its tests passed, and it shipped. A scan of six real local projects then
showed it never ran on the default profile at all, because it had been placed inside a
network-gated Check. Unit tests could not have caught that, and no amount of reasoning
did. Running it against real repositories did.
