# CLAUDE.md — long-term context for this repository

> **Audience:** any AI agent or human joining this project with no prior context.
> Read this before proposing changes. Written 2026-08-29.
> **Working name:** `valvur` (Estonian: *guard, watchman*). Provisional until first
> publish — renaming is one `sed` away and stays cheap until a GitHub repo, PyPI
> release or Docker push exists.

---

## 1. What this is

A lean, **local-first, fully offline** security scanner for codebases, with a
first-class focus on **AI-generated code**. It orchestrates best-of-breed open
source scanners, normalises their findings, ranks them by real-world
exploitability, and writes an **agent-consumable** results folder into the
project being scanned.

Delivered primarily as an **MCP tool** the developer adds to their agent (Kiro,
Claude Code) and invokes deliberately; the CLI is the second way in. The MCP server
is hand-rolled over stdio with **zero dependencies** (ADR-0015).
Packaged as one OCI container. Runs on Docker or Podman, locally by default.

> **Corrected 2026-09-05 (task 12a.4).** This previously read "optionally on AWS
> (ECR/Fargate) using the identical image". The image pushes to any registry, ECR
> included, and has no cloud-specific code paths — but ADR-0001's shim *launches*
> containers, and Fargate exposes no Docker socket and no privileged mode. It has
> never been run there. The intent is recorded, the claim is not.

**Status:** spec phase. No application code yet.

## 2. What it is NOT

Be ruthless about this — scope creep here destroys the product:

- **Not a new scanning engine.** Detection is done by Trivy, Gitleaks, Opengrep,
  Checkov, OSV-Scanner and Syft. We orchestrate, normalise, enrich and present.
  Never imply proprietary detection. Always credit the scanners.
- **Not a reachability analyser.** We do not prove a vulnerable function is
  called. That is a multi-year, per-language effort (Endor Labs / Semgrep Pro
  territory). Never claim or imply it.
- **Not an autonomous fixer.** No scan→fix→rescan loop. See §4.
- **Not a pen-test tool.** No DAST, no exploitation, no network scanning of
  deployed systems. That is a separate product with a different legal posture
  (authorisation required) and a blast radius this tool must never have.
- **Not a code-quality platform.** SonarQube's territory. We do security only.

## 3. The moat — non-negotiable

**The product is defined by what it refuses to do.** Competitors cannot copy
this without breaking their own business model. Every one of these is a hard
constraint, not an aspiration. Any feature that trades one away must be
rejected, however useful it seems.

1. **It never phones home, and that is provable.** `--network=none` on the
   default (`offline`) profile. Source is mounted read-only. No account, no API key, no
   telemetry, ever. A reviewer must be able to *verify* this themselves, not
   take our word for it.

   The claim has **two halves**, and the flag only covers one. The Scanners run in
   containers with no network interface; the **host shim does not**, and it has a
   reason to reach out — enrichment fetches EPSS from FIRST on `full`, gated by a
   single condition. `scripts/verify-offline.py` checks both. On Linux
   `unshare -rn valvur scan --profile offline` proves both at the OS level, without
   privileges, because the container runtime is reached over a unix socket. macOS has
   no equivalent; say so rather than implying one.
2. **The source tree is mounted read-only.** The scanner cannot modify the code
   it scans — structurally, not by policy.
3. **Vulnerability data comes from auditable primary sources** (CISA KEV, FIRST
   EPSS, OSV). No proprietary database, no lock-in, mirrorable for air-gapped
   use.
4. **Results never leave the machine and are never committed.**

> If a future proposal improves results by sending data somewhere, that is the
> moat being traded away. Refuse it, or escalate to the owner explicitly.

## 4. Human-in-the-loop is a safety property, not a UX choice

The developer chooses **which** fixes to apply and **when** to rescan. There is
no autonomous remediation loop.

Why this is non-negotiable: an agent told to drive findings to zero has a
cheaper path via deleting code or writing suppressions than via correct fixes.
"The finding disappeared" is not the same claim as "the vulnerability is fixed"
— swapping a hash function satisfies the scanner and breaks every stored
credential. Only a human can distinguish those.

Consequences, already reflected in the architecture:
- No `scan_and_fix` MCP tool exists. The MCP surface is read-only w.r.t. source.
- `REMEDIATION.md` is a **proposal**, never an execution script. Each item is
  independently applicable, because the developer will cherry-pick.
- Rescan is always an explicit call. No file watchers, no on-save hooks.

## 5. Target market

Primary, in priority order:

1. **Regulated industries that cannot send code to a vendor** — finance,
   defence, healthcare, government, critical infrastructure. For them, "your
   dependency manifest is analysed on our servers" ends the procurement
   conversation.
2. **Jurisdictions with data-residency requirements** for AI and code-generation
   tooling. Cloud code-analysis services are typically offered in a handful of
   regions; anything outside them is non-compliant by construction. A fully
   offline tool has no residency question to answer.
3. **Teams shipping AI-generated code** who need checks nobody else runs —
   slopsquatting, agent-config auditing, hidden Unicode, LLM-output-to-sink
   taint.
4. **Individual developers and OSS maintainers** who want one command, no
   account, useful output in under 60 seconds.

## 6. Locked decisions

Full rationale lives in `docs/adr/`. Do not re-litigate these without a strong
new argument.

| # | Decision |
|---|---|
| [001](docs/adr/0001-thin-host-shim-read-only-container.md) | **Thin host shim + read-only container engine.** MCP server is a small host-side shim; all scanners live in the image; source mounted `:ro`; scratch dir mounted `:rw`; the shim writes results as the developer's own user. Chosen over a fat container (file-ownership chaos across Docker/Podman/rootless/SELinux) and host install (dependency hell). The mount **is** the workspace jail — structural, not validation code. |
| [002](docs/adr/0002-layered-results-contract.md) | **Layered results contract.** One in-memory findings model projected to several artifacts, each with exactly one consumer. Self-ignoring results folder. See §7. |
| [003](docs/adr/0003-per-class-finding-identity.md) | **Per-class finding identity.** Fingerprints keyed by each finding class's natural identity, not line numbers. Versioned (`fp_version`). See §8. |
| [004](docs/adr/0004-opengrep-not-semgrep.md) | **Opengrep, not Semgrep.** Semgrep moved its maintained rules to a licence permitting only internal, non-competing, non-SaaS use (Dec 2024). We publish a scanning tool — that is plausibly a competing use, and redistributing those rules in an image is legally murky. Opengrep is the LGPL-2.1 consortium fork with the same rule syntax. |
| [005](docs/adr/0005-no-gpl-tools-in-the-image.md) | **No GPL tools deliberately added.** hadolint is GPL-3.0; Checkov and Trivy cover Dockerfiles adequately. *Corrected 2026-08-30:* the original claim was "no GPL component in the image", which no Linux container can satisfy — ours has 12, all base-OS. F10.4 now constrains what we **add**, and requires an SBOM disclosing the rest. |
| [006](docs/adr/0006-no-graph-database.md) | **No graph database.** Findings are a flat table with predictable queries. The one graph-shaped thing (the dependency tree) arrives free in the SBOM. Visual comprehension is served by `SUMMARY.md` and `REMEDIATION.md`, which render natively everywhere (see ADR-0014). |
| [007](docs/adr/0007-internal-enrichment-no-external-platform.md) | **Enrichment is internal and has zero external prerequisites.** ~200 lines behind an `EnrichmentProvider` interface: KEV snapshot bundled in the image, EPSS fetched on demand for found CVEs only, degrading to KEV-only when offline. The sibling VulnGraph project is **parked** and must never become a dependency. |
| [008](docs/adr/0008-no-saas-coupled-dependencies.md) | **No SaaS-coupled dependencies.** `snyk/agent-scan` was rejected despite being credible (Apache-2.0, well-adopted) because it requires `SNYK_TOKEN` and transmits component data to Snyk. Applying this rule to Snyk and waiving it elsewhere would make the principle meaningless. |
| [009](docs/adr/0009-human-in-the-loop-remediation.md) | **Human-in-the-loop remediation.** valvur proposes, never remediates. No `scan_and_fix` tool, no watchers, no on-save hooks — and a test asserts no such tool *exists in the registry*, so adding one fails the build rather than merely failing review. An agent told to drive findings to zero has a cheaper path via deletion and suppression than via correct fixes. See §4. |
| [015](docs/adr/0015-hand-rolled-mcp-stdio-transport.md) | **MCP stdio is hand-rolled, zero dependencies.** The official SDK pulls 22 packages — an HTTP server, an OAuth stack and a crypto library — to support transports Kiro and Claude Code do not use. stdio has no listener: the process boundary is the trust boundary. MCP is on the **primary** install path; the CLI is second. |
| [014](docs/adr/0014-no-html-report.md) | **No `report.html`.** Cut before implementation. The Results Folder is deliberately unshareable (ADR-0011), which removes an HTML report's main advantage over Markdown; rendering untrusted content in a browser was the largest security surface in the contract; and it was the only artifact with no single identified consumer, which is ADR-0002's own rule. F7.8 deferred, F7.15 stays dormant. |
| [013](docs/adr/0013-checks-run-inside-the-container.md) | **valvur's own Checks run inside the container**, like Scanners. Host-side would put the Dependency Reality Check's registry calls outside `--network=none`, turning ADR-0010's guarantee back into a policy. No new orchestrator protocol was needed: Checks emit JSON and fit the existing adapter contract. |
| [011](docs/adr/0011-scan-output-never-enters-git.md) | **Scan output never enters git history, on any branch.** Self-ignoring folder + root `.gitignore` + a tracked `pre-commit` hook that refuses staged `.security-scan/` paths (`.gitignore` does not stop `git add -f`). A separate "clean publish branch" was rejected: git objects are repo-wide, so committing on any branch puts results on the remote. |
| [012](docs/adr/0012-vulnerability-db-lives-outside-the-image.md) | **The vulnerability DB lives outside the image.** Baking Trivy's DB in took the image from 187MB to 1.52GB *and* tied advisory freshness to image release cadence. It now lives in a host cache, mounted at scan time; scans run `--skip-db-update` so `offline` stays offline. |
| [016](docs/adr/0016-two-profiles-split-on-the-network-boundary.md) | **Two Profiles, split on the network boundary.** `offline` (the default) runs every Scanner that completes under `--network=none` — which is all of them bar two. `full` adds `osv-scanner` and the dependency-reality Check, the only two needing a socket. The old set was drawn along *speed* while being described as a network boundary, and `deep` was byte-identical to `standard` — it promised more and delivered exactly `standard`. Retired names still resolve. |
| [010](docs/adr/0010-provable-non-exfiltration.md) | **Provable non-exfiltration is a hard constraint.** Not a policy — a testable property, with a regression test that fails if the `offline` profile touches a socket. This is the product; see §3. |

## 7. Results contract

Written into the scanned project:

```
.security-scan/
  .gitignore          # contains "*" — the folder ignores itself
  SUMMARY.md          # entry point, capped ~200 lines, leads with failures
  REMEDIATION.md      # ranked proposal: KEV/EPSS order, dependency paths
  findings.json       # normalised, schema-versioned, secrets redacted
  results.sarif       # SARIF 2.1.0 for IDEs and tooling
  sbom.cdx.json       # CycloneDX
  run.json            # provenance: tool + DB versions, skips, failures
  state.json          # previous run's fingerprints (local only)
  raw/                # per-tool output, secrets redacted
```

Plus `.security-scan.toml` at project root — **committed**, holding two things:
suppressions with **mandatory expiry dates**, and `[scan] exclude`, repo-relative
path prefixes the project has chosen not to scan. Exclusion is never a built-in
default: a project of deliberately vulnerable test data needs it, and every other
project would be harmed by having its tests silently skipped. Both the count of
excluded findings and the paths responsible appear in `SUMMARY.md` and `run.json`,
because an exclusion the reader cannot see is indistinguishable from a scan that
found nothing.

Rules that must hold:
- **Self-ignoring folder** is the guarantee results are never committed; a root
  `.gitignore` entry is added too, as a visible signal to humans.
- **Secrets are redacted** in every written artifact including `raw/`. Gitleaks
  emits live credential values; writing those verbatim would have our security
  tool copy your secrets to a second cleartext location on disk.
- **Progressive disclosure.** The agent always reads `SUMMARY.md` (bounded),
  works from `REMEDIATION.md`, queries `findings.json` per finding, and never
  reads `raw/`. A 40MB scan stays usable because the read path is bounded.
- **`SUMMARY.md` opens with a machine-facing block** explaining the folder. An
  agent in someone else's repo meets the output before it ever sees our README.
- **Fail loudly.** If a scanner crashed, that appears at the top of
  `SUMMARY.md`. A silent failure manufactures false confidence and is worse
  than no scan.
- **Evidence is neutralised, never reproduced raw** (F3.13). An agent reads
  `SUMMARY.md` first and by instruction. If we quote an injection payload
  verbatim, we launder an attack out of a file the agent might never have
  opened into one we tell it to read. Hidden Unicode is escaped; directive
  text is fenced and labelled untrusted. **valvur must never become the
  delivery mechanism.**
- **The same applies to MCP responses** (F9.9). A response reaches an agent's
  context with no file in between — the most direct injection path valvur has,
  and the only one the agent cannot decline to read.
- **In markup, escaping replaces fencing** (F7.15). The `[UNTRUSTED CONTENT]`
  fence is a textual convention with no effect in HTML, where a payload can
  execute or hide itself with styling while remaining in the file. Any
  artifact that renders escapes workspace content so it cannot act as markup,
  style or script. Dormant since ADR-0014 cut `report.html`; the guard stays in
  force for whatever renders next.
- **Clean is explicit.** No findings still writes the folder, with
  `"status": "clean"`, so an agent can tell "clean" from "never ran".
- **A Scanner that did not run says so.** Checkov is skipped where there is no
  infrastructure to analyse — it costs ~10s of fixed startup whatever it finds — and
  the skip with its reason appears in `run.json` (`scanners_skipped`) and in
  `SUMMARY.md`. It is not a failure and the run stays `complete`. A conditional
  Scanner is one that can silently stop running, so the skip is reported, detection
  is biased towards scanning when unsure, and both branches are tested.

## 8. Finding identity

Identity is per finding class, keyed on what is naturally stable — never on
line numbers, which shift on every edit and would make the rescan diff useless.

| Class | Identity |
|---|---|
| Dependency CVE | `(ecosystem, package, version, vuln_id)` |
| Secret | `(rule, path, sha256(secret)[:16])` |
| IaC misconfig | `(rule, path, resource_address)` |
| Licence | `(package, license_id)` |
| Slopsquat / dep-reality | `(ecosystem, package_name)` |
| SAST / AI-artifact | `(rule, path, sha256(normalised_match), occurrence)` |

Only the last row needs a content hash. Paths are repo-relative so fingerprints
are byte-identical across machines — suppressions are shared in a committed
file and must match everywhere.

`fp_version` is a compatibility surface from the first commit: changing the
algorithm invalidates every suppression in every repo using the tool.

Status diff: `new` / `persisting` / `fixed` / `regressed`, computed against
`state.json`. A fresh clone has no history and reports everything as `new` —
correct and honest.

## 9. Working conventions

- **Spec-driven.** [`.kiro/specs/valvur/`](.kiro/specs/valvur/) holds
  [requirements](.kiro/specs/valvur/requirements.md) →
  [design](.kiro/specs/valvur/design.md) →
  [tasks](.kiro/specs/valvur/tasks.md). Requirement IDs (F1.1, N2.1, P5 …) are
  load-bearing — cited by the design, the tasks and the verification suite.
  **Never renumber them.**
- **Vocabulary.** [CONTEXT.md](CONTEXT.md) is the glossary. Use its terms
  exactly; the `_Avoid_` lists exist because the wrong word erodes a constraint.
- **Test-driven.** Tests before implementation. Fingerprinting, normalisation
  and redaction are the highest-value units — write those first.
- **ADRs** in `docs/adr/`, numbered, with rejected alternatives recorded.
- **Dogfooding is a release gate.** The tool scans itself; a clean self-scan,
  signed image, published SBOM and pinned dependencies gate every release.
  For a security tool the repo is its own best test case, and anything we
  preach but do not practise is the first thing a reviewer will notice.

## 10. Prohibited without explicit owner approval

- Any network call in the `offline` profile.
- Any dependency requiring an account, API key or token to function.
- Any feature that writes to the scanned source tree.
- Any autonomous remediation.
- Any claim of reachability analysis, proprietary detection, or coverage we do
  not have.
- Bundling GPL-licensed tools into the distributed image.
