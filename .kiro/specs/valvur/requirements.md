# valvur — Requirements

**Status:** approved for design · **Version:** 1.0 · **Date:** 2026-08-30

Requirement IDs are load-bearing. `design.md` and `tasks.md` cite them and the
verification suite traces to them. **Never renumber.** Add new IDs at the end of a
section; mark withdrawn ones `WITHDRAWN` in place.

Terms in **bold** are defined in [CONTEXT.md](../../../CONTEXT.md) and used
precisely. Decisions referenced as ADR-NNNN are in [docs/adr/](../../../docs/adr/).

---

## Introduction

valvur is a fully offline security scanner for codebases, focused on how
AI-generated code fails. A developer invokes it deliberately via MCP or CLI; it
orchestrates six third-party **Scanners** and four in-house **Checks**, normalises
the output, ranks it by real-world exploitability, and writes a **Results Folder**
into the **Workspace** for the developer or their coding agent to act on.

**Out of scope for v1:** reachability analysis, autonomous remediation, DAST or
penetration testing, code-quality analysis, a hosted service, and any UI at all —
including an HTML report ([ADR-0014](../../../docs/adr/0014-no-html-report.md)).

---

## F1 — Scan execution and isolation

**User Story:** As a developer in a regulated industry, I want scanning to happen
entirely on my machine, so that my source code never reaches a third party.

### Acceptance Criteria

1. F1.1 — WHEN a **Scan Run** starts, valvur SHALL mount the **Workspace** into the
   container read-only.
2. F1.2 — WHEN the `offline` **Profile** is selected, valvur SHALL run the container
   with no network interface.
3. F1.3 — valvur SHALL write no file inside the **Workspace** from within the
   container; the host shim SHALL write every **Results Folder** artifact.
4. F1.4 — WHEN the host shim writes the **Results Folder**, the files SHALL be owned
   by the invoking user on Docker rootful, Docker Desktop, and rootless Podman.
5. F1.5 — valvur SHALL detect the available container runtime in the order `docker`,
   `podman`, `nerdctl`, and SHALL allow override by environment variable.
6. F1.6 — WHERE SELinux labelling is required by the host, valvur SHALL apply the
   appropriate mount label.
7. F1.7 — valvur SHALL require no account, API key, token or credential to perform
   any **Scan Run**.
8. F1.8 — valvur SHALL emit no telemetry under any **Profile**.
9. F1.9 — IF the host shim's major version is incompatible with the image's, THEN
   valvur SHALL refuse to run and SHALL state both versions.
10. F1.10 — WHEN a **Scan Run** targets AWS, valvur SHALL use the identical image
    with no AWS-specific code path.

## F2 — Scanner orchestration

**User Story:** As a developer, I want one command to run every relevant scanner, so
that I do not maintain six toolchains myself.

1. F2.1 — valvur SHALL orchestrate Trivy, Gitleaks, OSV-Scanner, Opengrep, Checkov
   and Syft as **Scanners**.
2. F2.2 — valvur SHALL pin every **Scanner** to an exact version in the image.
3. F2.3 — valvur SHALL select **Scanners** by **Profile** per the table in
   `design.md`.
4. F2.4 — WHEN a **Scanner** exits non-zero because it found issues, valvur SHALL
   treat the **Scan Run** as successful.
5. F2.5 — IF a **Scanner** crashes, times out, or emits unparseable output, THEN
   valvur SHALL record the failure in **Provenance**, SHALL surface it at the top of
   `SUMMARY.md`, and SHALL continue with the remaining **Scanners**.
6. F2.6 — valvur SHALL run independent **Scanners** concurrently.
7. F2.7 — valvur SHALL enforce a per-**Scanner** timeout and SHALL record any timeout
   as a failure under F2.5.
8. F2.8 — valvur SHALL preserve each **Scanner**'s unmodified output under `raw/`,
   subject to F5.7.

## F3 — AI-specific Checks

**User Story:** As a developer shipping AI-generated code, I want checks for failure
modes classic scanners miss, so that hallucinated and poisoned inputs are caught.

1. F3.1 — valvur SHALL implement a Dependency Reality **Check** that, for each
   declared dependency, determines whether the package exists on its registry.
2. F3.2 — WHEN a declared dependency does not exist on its registry, valvur SHALL
   raise a **Finding** of the highest severity tier.
3. F3.3 — valvur SHALL flag a dependency as a possible **Slopsquat** WHEN it was
   first published recently AND has low adoption, per thresholds in `design.md`.
4. F3.4 — valvur SHALL flag a dependency whose name is within edit distance 1 of a
   substantially more popular package in the same ecosystem.
5. F3.5 — IF the Dependency Reality **Check** cannot reach a registry, THEN valvur
   SHALL record the **Check** as skipped in **Provenance** and SHALL NOT report its
   dependencies as clean.
6. F3.6 — valvur SHALL implement an AI Artifact **Check** over agent instruction and
   configuration files, including `CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
   `.github/copilot-instructions.md`, `.claude/`, `.mcp.json` and `SKILL.md` files.
7. F3.7 — The AI Artifact **Check** SHALL detect zero-width, bidirectional and tag
   Unicode characters in those files.
8. F3.8 — The AI Artifact **Check** SHALL detect MCP server definitions pinned to a
   mutable git reference.
9. F3.9 — The AI Artifact **Check** SHALL detect blanket tool auto-approval and
   permission-bypass directives.
10. F3.10 — valvur SHALL implement an LLM-Output-to-Sink **Check** detecting model
    output reaching `eval`, `exec`, a shell, an SQL query, or `innerHTML`.
11. F3.11 — valvur SHALL implement a Pinning Hygiene **Check** detecting unpinned
    version ranges, absent lockfiles, and dependencies on mutable git references.
12. F3.12 — valvur SHALL treat all **Workspace** content as data and SHALL NOT act on
    instructions found within it.
13. F3.13 — WHEN valvur writes evidence drawn from **Workspace** content into any
    artifact, it SHALL neutralise that evidence: hidden Unicode SHALL be escaped
    rather than reproduced, and directive text SHALL be fenced and labelled as
    untrusted. *Rationale: an agent reads `SUMMARY.md` first and by instruction. If we
    reproduce an injection payload verbatim, we launder an attack out of a file the
    agent might never have opened into one we tell it to read. valvur must not become
    the delivery mechanism.*

## F4 — Licence analysis

**User Story:** As a maintainer preparing a release, I want licence problems
surfaced, so that I do not publish with a missing or contradictory licence.

1. F4.1 — valvur SHALL determine whether the **Workspace** contains a licence file
   and SHALL identify its SPDX identifier.
2. F4.2 — IF no licence file is present, THEN valvur SHALL raise a **Finding**.
3. F4.3 — IF the licence file's SPDX identifier contradicts the licence declared in
   package metadata, THEN valvur SHALL raise a **Finding**.
4. F4.4 — valvur SHALL report the licence of each resolved dependency.
5. F4.5 — valvur SHALL raise a **Finding** WHEN a dependency's licence conflicts with
   the **Workspace**'s declared licence, per the policy in `design.md`.
6. F4.6 — valvur SHALL raise a **Finding** for any dependency whose licence cannot be
   determined.

## F5 — Findings model, identity and status

**User Story:** As a developer fixing findings iteratively, I want the next scan to
tell me what I actually fixed, so that I can measure progress rather than noise.

1. F5.1 — valvur SHALL normalise every **Scanner** and **Check** result into a single
   **Finding** model.
2. F5.2 — valvur SHALL assign each **Finding** a **Finding Class**.
3. F5.3 — valvur SHALL derive each **Fingerprint** from its **Finding Class**'s
   natural key per ADR-0003, and SHALL NOT derive it from a line number.
4. F5.4 — **Fingerprints** SHALL be byte-identical for identical input across
   machines and operating systems.
5. F5.5 — valvur SHALL record an `fp_version` alongside every **Fingerprint**.
6. F5.6 — WHEN a previous **Scan Run**'s state exists, valvur SHALL assign each
   **Finding** a **Status** of `new`, `persisting`, `fixed` or `regressed`.
7. F5.7 — valvur SHALL apply **Redaction** to secret values in every written
   artifact, including `raw/`, before that artifact reaches disk.
8. F5.8 — valvur SHALL deduplicate **Findings** reported by more than one **Scanner**
   into a single **Finding** listing every reporting **Scanner**.
9. F5.9 — WHEN no previous state exists, valvur SHALL assign every **Finding** a
   **Status** of `new`.

## F6 — Enrichment and prioritisation

**User Story:** As a developer with limited time, I want the top of the list to be
genuinely the most urgent thing, so that I fix what attackers actually exploit.

1. F6.1 — valvur SHALL attach **Exploit Signals** to every **Finding** carrying a CVE
   identifier.
2. F6.2 — valvur SHALL ship a CISA KEV snapshot inside the image, including the
   ransomware-campaign flag.
3. F6.3 — WHERE network access is permitted, valvur SHALL retrieve EPSS scores for
   only the CVEs present in the **Scan Run**.
4. F6.4 — IF EPSS is unavailable, THEN valvur SHALL rank using KEV alone and SHALL
   record the degradation in **Provenance**.
5. F6.5 — valvur SHALL rank **Findings** by **Exploit Signal** ahead of
   **Scanner**-assigned severity.
6. F6.6 — valvur SHALL demote **Findings** affecting development-only dependencies.
7. F6.7 — valvur SHALL record **Enrichment** age in **Provenance** and SHALL warn in
   `SUMMARY.md` WHEN it exceeds the staleness threshold in `design.md`.
8. F6.8 — valvur SHALL resolve **Enrichment** through an `EnrichmentProvider`
   interface, and SHALL have no external platform prerequisite (ADR-0007).
9. F6.9 — valvur SHALL report the **Dependency Path** and the direct dependency to
   change for every transitive vulnerability.
10. F6.10 — WHERE **Enrichment** requires a network lookup, valvur SHALL record in
    **Provenance** exactly what was transmitted, and SHALL provide an opt-out.
    *Rationale: EPSS lookups transmit the CVE identifiers found in the **Workspace** —
    a map of the project's unpatched vulnerabilities, which is a more sensitive
    disclosure than the dependency names of F3.1. Having made a point of being
    explicit about the lesser leak, silence about the greater one would be worse than
    never having claimed it.*

## F7 — Results contract

**User Story:** As an AI coding agent, I want results in a bounded, self-describing
form, so that I can act on them without exhausting my context window.

1. F7.1 — valvur SHALL write the **Results Folder** to `.security-scan/` in the
   **Workspace**.
2. F7.2 — valvur SHALL write `.security-scan/.gitignore` containing `*`.
3. F7.3 — valvur SHALL add `.security-scan/` to the **Workspace**'s root `.gitignore`
   if absent, and SHALL NOT otherwise modify that file.
4. F7.4 — valvur SHALL write `SUMMARY.md`, `REMEDIATION.md`, `findings.json`,
   `results.sarif`, `sbom.cdx.json`, `run.json` and `raw/`.
5. F7.5 — `SUMMARY.md` SHALL NOT exceed 200 lines regardless of **Finding** count.
6. F7.6 — `SUMMARY.md` SHALL open with a machine-facing block describing the folder,
   the **Status** values, the ranking basis, and the constraints in F9.5–F9.7.
7. F7.7 — WHEN any **Scanner** or **Check** failed or was skipped, `SUMMARY.md` SHALL
   state so before reporting any **Finding**.
8. F7.8 — **DEFERRED 2026-08-30, see [ADR-0014](../../../docs/adr/0014-no-html-report.md).**
   ~~`report.html` SHALL be self-contained, referencing no external asset, and SHALL
   render offline.~~ Cut before implementation: the **Results Folder** is
   deliberately unshareable, which removes an HTML report's main advantage over
   Markdown, while rendering untrusted content in a browser was the largest security
   surface in the contract. Returns only with an identified consumer.
9. F7.9 — `results.sarif` SHALL conform to SARIF 2.1.0 and SHALL carry **Fingerprints**
   in `partialFingerprints`.
10. F7.10 — `findings.json` SHALL carry a schema version.
11. F7.11 — WHEN a **Scan Run** produces no **Findings**, valvur SHALL still write the
    full **Results Folder** with an explicit clean status.
12. F7.12 — `run.json` SHALL record **Scanner** versions, **Enrichment** source dates,
    the **Profile**, duration, and every skip and failure with its reason.
13. F7.13 — Every **Finding** in `findings.json` SHALL appear in `results.sarif` and
    SHALL be counted in `SUMMARY.md`.
14. F7.14 — `REMEDIATION.md` SHALL present **Remediation Items** in ranked order, each
    independently applicable. A **Remediation Item** SHALL correspond to one *action*,
    not one **Finding**: several **Findings** resolved by a single change SHALL appear
    as one item.
15. F7.15 — WHEN valvur renders **Workspace**-derived content into a markup or markup-
    adjacent artifact, it SHALL escape that content so it cannot be interpreted as
    markup, styling or script. *Rationale: F3.13's fencing is a textual convention
    and has no effect in HTML, where a payload can execute, or hide itself from the
    reader with styling while remaining present in the file.*

## F8 — Suppressions

**User Story:** As a team lead, I want accepted risks recorded and shared, so that
they are reviewed rather than forgotten.

1. F8.1 — valvur SHALL read **Suppressions** from `.security-scan.toml` at the
   **Workspace** root.
2. F8.2 — Each **Suppression** SHALL reference a **Fingerprint** and SHALL carry an
   expiry date, a reason, and **human-readable context** naming at minimum the rule
   and path it applies to. *Rationale: a 32-character hash is unreviewable. A pull
   request adding a suppression must let a reviewer see what is being accepted, which
   is the entire argument for per-class identity — suppressing
   `aws_s3_bucket.logs / CKV_AWS_18` is a decision a human can read, and suppressing
   `4e4dff39…` is not. The hash is the key; it is never the whole entry.*
3. F8.3 — IF a **Suppression** lacks an expiry date, THEN valvur SHALL reject it and
   SHALL raise a **Finding**.
4. F8.4 — WHEN a **Suppression** has expired, valvur SHALL report the **Finding**
   normally and SHALL note the expiry.
5. F8.5 — WHEN a **Suppression** matches no **Finding**, valvur SHALL report it as
   stale.
6. F8.6 — valvur SHALL report suppressed **Findings** in a distinct section rather
   than omitting them.
7. F8.7 — valvur SHALL NOT create or modify **Suppressions**.
8. F8.8 — valvur SHALL be able to **print** a ready-to-paste **Suppression** block for
   a given **Fingerprint**, with its context filled in. *Rationale: F8.7 correctly
   forbids writing the file, but nobody will hand-copy a 32-character hash out of
   `findings.json`. Printing is not writing, and without it F8.7 makes the feature
   theoretical rather than deliberate.*
9. F8.9 — Suppressed **Findings** SHALL be excluded from ranking positions and counted
   separately from active ones. *Rationale: a suppressed Finding occupying a top slot
   crowds out a live one, which is the noise problem F6.5 exists to solve; and
   `Findings: 84` when 30 are suppressed misstates the result.*

## F9 — MCP and CLI surface

**User Story:** As a developer, I want to trigger scans deliberately and keep control
of fixes, so that nothing changes my code without my decision.

1. F9.1 — valvur SHALL expose MCP tools to run a **Scan Run**, list **Findings**,
   explain one **Finding**, and report **Scan Run** status.
2. F9.2 — valvur SHALL NOT expose any tool that modifies the **Workspace**'s source.
3. F9.3 — valvur SHALL provide equivalent CLI commands for every MCP tool.
4. F9.4 — valvur SHALL NOT watch files, hook editor save events, or start a **Scan
   Run** other than by explicit invocation.
5. F9.5 — valvur SHALL document that a disappeared **Finding** is not evidence of a
   correct fix.
6. F9.6 — valvur SHALL document that **Suppressions** require human approval.
7. F9.7 — valvur SHALL document that the **Results Folder** must never be committed.
8. F9.8 — WHEN a **Finding** is explained, valvur SHALL return its evidence, its
   **Exploit Signals**, its **Dependency Path** where applicable, and its originating
   **Scanner** or **Check**.
9. F9.9 — MCP responses SHALL carry neutralised evidence, per F3.13. *Rationale: an
   MCP response goes straight into an agent's context with no file in between. It is
   the most direct injection path valvur has, and the only one where the agent cannot
   choose not to read it.*
10. F9.10 — MCP responses SHALL be bounded by default and SHALL state what was
    omitted. *Rationale: returning several thousand **Findings** into an agent's
    context is the problem F7.5 solved for `SUMMARY.md`, arriving by another door.*

## F10 — Distribution

1. F10.1 — valvur SHALL publish one OCI image running unchanged on Docker and Podman.
2. F10.2 — The image SHALL run as a non-root user with a read-only root filesystem and
   all capabilities dropped.
3. F10.3 — valvur SHALL publish a signed image, an SBOM, and build provenance per
   release.
4. F10.4 — **CORRECTED 2026-08-30.** ~~The image SHALL contain no GPL- or
   AGPL-licensed component.~~ valvur SHALL add no GPL- or AGPL-licensed component
   **as a Scanner, Check or library it deliberately installs** (ADR-0005), and SHALL
   publish an SBOM disclosing every component's licence, including the base image's.
   *Rationale: as originally written this was unsatisfiable by any Linux container.
   Measured on our own image: 12 GPL components — busybox, apk-tools,
   alpine-baselayout, musl-utils, xz-libs, gdbm, readline and others — all from the
   base OS, all mere aggregation with no linking. A requirement that can never pass
   either blocks every release or gets quietly ignored, and the second is worse
   because it trains people to skip the check. ADR-0005's real concern was
   deliberately adding a GPL tool (hadolint) to a product that ships licence
   analysis. Disclosure is a better answer than an impossible claim.*
5. F10.5 — valvur SHALL support retrieving vulnerability databases from a
   user-specified OCI registry for air-gapped operation.
6. F10.6 — The host shim SHALL install without a compiler, without the **Scanners**
   present on the host, and with **no runtime dependencies at all** — including the
   MCP server, which is on the primary install path.
   *(See [ADR-0015](../../../docs/adr/0015-hand-rolled-mcp-stdio-transport.md): the
   official SDK pulls 22 packages including an HTTP server, an OAuth stack and a
   crypto library to support transports we do not use. stdio is implemented directly.)*

---

## Non-functional requirements

### P — Positioning commitments
Traceable to [docs/POSITIONING.md](../../../docs/POSITIONING.md) §6.

1. P1 — A first **Scan Run** SHALL require one command, no account, and SHALL complete
   the `offline` **Profile** in under 60 seconds on a mid-sized repository.
2. P2 — Every **Finding** SHALL be traceable to the **Scanner** or **Check** and
   version that produced it.
3. P3 — valvur SHALL emit SARIF and CycloneDX, and SHALL depend on no proprietary
   vulnerability database.
4. P4 — valvur SHALL credit every bundled **Scanner** with its licence in user-facing
   documentation.
5. P5 — valvur SHALL provide a documented command by which a reviewer can verify
   non-exfiltration unaided.
6. P6 — Documentation SHALL address developers and AI coding agents separately, and
   the **Results Folder** SHALL be self-describing.

### N1 — Performance
1. N1.1 — `offline` **Profile** SHALL complete in under 60 seconds on a repository of
   ≤50k lines.
2. N1.2 — `full` **Profile** SHALL complete in under 5 minutes on the same.
3. N1.3 — `SUMMARY.md` SHALL be readable within a 200k-token context alongside
   `REMEDIATION.md`.
4. N1.4 — Memory use SHALL remain under 2 GB for the `full` **Profile**.

### N2 — Security
1. N2.1 — The `offline` **Profile** SHALL make no network connection, verified by an
   automated test that fails on any socket attempt (ADR-0010).
2. N2.2 — valvur SHALL never write outside the **Results Folder** and the host
   scratch directory.
3. N2.3 — No **Workspace**-derived value SHALL reach a shell interpreter.
4. N2.4 — Secret values SHALL NOT be written to disk unredacted, nor to logs.
5. N2.5 — valvur SHALL pass its own `full` **Profile** with no unsuppressed
   **Findings** as a release gate.

### N3 — Operability
1. N3.1 — Every **Scan Run** SHALL produce **Provenance** sufficient to distinguish a
   **Clean Scan** from a failed one.
2. N3.2 — valvur SHALL exit non-zero only on **Scan Run** failure, never on the
   presence of **Findings**.
3. N3.3 — valvur SHALL prune `raw/` to the most recent N **Scan Runs**.

---

## Ordered cut list

If v1 must be reduced, cut in this order. Below the line is an abort threshold, not a
scope decision.

1. Syft SBOM (F2.1 partial) — Trivy emits an adequate SBOM
2. LLM-Output-to-Sink **Check** (F3.10) — the narrowest of the four **Checks**
3. Dependency licence policy (F4.4–F4.6) — keep project licence hygiene F4.1–F4.3
4. `regressed` **Status** (F5.6 partial) — three states remain useful
5. Air-gapped DB mirroring (F10.5) — defer to v1.1

**Not cuttable:** F1 entirely, N2.1, F5.3, F7.2, F9.2, F9.4. These are the moat.
