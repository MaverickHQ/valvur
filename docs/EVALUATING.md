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
valvur update                # fetches the vulnerability database, once
valvur scan .
```

Needs Docker or Podman. The shim is Python, stdlib only, no runtime dependencies —
the scanners live in one OCI image, so nothing is installed onto your machine beyond
a ~200-line launcher.

### The true first run, measured

The number a competitor would quote, measured on 2026-09-12 from an empty cache on an
Apple-silicon Mac with Docker Desktop, so it is here before they do (22.B.4):

| | bytes | wall-clock | what you are looking at |
|---|---|---|---|
| `pipx install valvur` | <1MB | seconds | pip |
| image pull, once | **321MB** compressed as published (`0.1.0rc1`); ~240MB from the current tree | ~26s at 100 Mbit, ~52s at 50, ~105s at 25 | docker's layer bars |
| `valvur update`, first time | **276MB**: vulnerability database 118MB, npm names 146MB in 439 requests, PyPI names 10MB, KEV 2MB | **6m27s** | Trivy's progress bar for ~20s, then `npm: 499,942 names so far` about every 40s for five and a half minutes |
| `valvur update`, every later time | a few hundred KB | seconds | one line per source |
| first `valvur scan` | — | **45s** on the ten-file `tests/fixtures/broken-repo` (Terraform present, so Checkov runs); 7–24s on the real projects in the README | eight scanner names, each turning `ok` |

**About eight minutes from nothing to a first result on a 100 Mbit connection, and
most of it is npm.** The README once promised sixty seconds. It does not any more,
and this table is why: npm publishes no list of its package names, so the first
index build walks the registry's replication feed (ADR-0018). Every update after
the first applies the change feed instead. A valvur-published index would cut the
first run to a single download; it waits on the release pipeline having run at
least once (Phase 22, Block B), and is the next thing that moves this number.

If you are evaluating on a laptop with a metered or slow connection, run
`valvur update` before the meeting.

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

## 3. Prove it does not phone home

The claim is that source never leaves your machine, and it has two halves.

**The containers** run with `--network=none` on the default profile. No interface, not
a policy.

**The host shim** is the half a `--network=none` flag cannot cover. It has one reason
to reach out — fetching EPSS exploitation scores — and it is gated on the `full`
profile only.

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
  Counting them would fail your CI for something you cannot fix.

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
- **The existence check is offline for Python and npm, `full`-only for JVM and
  Go, and absent for Rust, Ruby and PHP.** `requirements*.txt` and `pyproject.toml`
  (PEP 621 and Poetry) and `package.json` are checked against a local index of every
  name on PyPI and npm — 890,000 and 4.4 million, exact, fetched by `valvur update`
  ([ADR-0018](adr/0018-offline-package-name-index.md)). `pom.xml`, Gradle scripts
  and `go.mod` are checked against Maven Central and the Go module proxy on `full`,
  because neither registry publishes a name list an offline index could be built
  from (Maven Central's only one is 3.2GB; Go's is a feed of versions). Cargo, Ruby
  and PHP have no check at all. Every case is stated in the run's coverage contract,
  and the last two produce a coverage note rather than a clean result.
- **Known-vulnerability scanning needs a lockfile.** Measured 2026-09-12: Trivy
  produces no result — not zero findings, no scan — for `package.json`,
  `pyproject.toml`, `Gemfile` or `Cargo.toml` without a lockfile (or a pinned
  `requirements.txt`) beside it. Express commits no lockfile and read `clean` with
  thirty dependencies unchecked, until the public corpus found it. Now it is a
  coverage note and the run is `inconclusive`. Direct manifests are read for
  *existence* precisely because that is where a hallucinated name is written;
  lockfiles are read for *vulnerabilities* because that is where the versions are.
- **The Opengrep rules are a supplement, not the product.** Measured on eleven real
  repositories (task 22.E.2): 75 findings, 64 of them tag-pinned GitHub Actions and
  the other 11 rejected by a reviewer to the last one; the four LLM-output-to-sink
  rules fired zero times, including on an LLM tool. They are all ranked `low` now,
  bar the ones that have never fired on real code. The AI-specific claim is carried
  by the Checks above.
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
