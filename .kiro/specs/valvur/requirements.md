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

   > ✅ **MET 2026-09-10 (Phase 20), and measured on a real enforcing host.**
   > Fedora CoreOS 44, SELinux `targeted` policy enforcing, `container-selinux`
   > installed, workspace on native **xfs on a block device — not virtiofs** — under
   > `$HOME`. Both rootful and rootless Podman.
   >
   > **It was a real defect, not a theoretical one.** All three of valvur's mounts were
   > denied: the source unreadable (`user_home_t` / `admin_home_t`), the scratch
   > directory unwritable, the database cache unwritable. valvur was unusable on its
   > **primary target platform** (§5: regulated industries, where Podman on RHEL is the
   > default).
   >
   > **The 2026-09-05 note was wrong in its conclusion and right to be suspicious.**
   > It recorded that the defect could not be reproduced through Podman's VM and
   > guessed virtiofs was why. It reproduces immediately on a native filesystem inside
   > that same VM. *Could not reproduce* was indeed not the same as *does not happen*.
   >
   > **`:Z` is ruled out by valvur's own architecture.** It stamps a private MCS
   > category; measured, a second container is then denied. Scanners run concurrently
   > against one mount, so `:Z` would break the fleet from the second Scanner onward.
   >
   > **What is applied, and what is not.** valvur's own directories — the scratch mount
   > and the Trivy cache — are labelled `:z` unconditionally on an enforcing host:
   > they are a temporary directory we created and a cache we own. **The Workspace is
   > not**, unless `VALVUR_SELINUX_RELABEL=1` is set. `:z` rewrites the SELinux context
   > of every file in the scanned tree and the change persists after the scan, which
   > §10 prohibits without explicit owner approval. Approval was sought and the opt-in
   > shape was chosen deliberately, accepting that valvur fails on first run on RHEL.
   >
   > **The failure is loud, which is what makes the opt-in defensible.** The readability
   > probe returns 0 entries where the host has entries, so `WorkspaceUnreadable` is
   > raised and the message names SELinux, the environment variable, the manual `chcon`
   > and the undo. Verified verbatim on the enforcing host: valvur never reports a
   > false clean there.
   >
   > **F1.1 survives the relabel** — measured: a `,z` mount is still read-only, and a
   > write to `/workspace` is refused.

7. F1.7 — valvur SHALL require no account, API key, token or credential to perform
   any **Scan Run**.
8. F1.8 — valvur SHALL emit no telemetry under any **Profile**.
9. F1.9 — IF the host shim's major version is incompatible with the image's, THEN
   valvur SHALL refuse to run and SHALL state both versions. *Extended 2026-09-14
   (task 23.4.4): and IF the shim and the image record different build trees, THEN
   valvur SHALL say so in `run.json`, `SUMMARY.md` and `scan_status` — a warning,
   never a refusal. The version label answers "which release?"; `0.1.0rc1` showed
   two equal labels on different code. The wheel now carries the digest of the tree
   it was built beside (`valvur/_build.py`, generated by the build hook and never
   committed) and the image records the same digest over the same inputs
   (`/etc/valvur/inputs.sha256`, 22.C.1); a scan compares them, reading the
   image's once per image id. A mismatch is a diagnosis: the results are real, and
   what they mean is what this shim expects of that image.*
10. F1.10 — valvur SHALL have no cloud-specific code path: one image and one shim,
    behaving identically wherever a container runtime exists. **The AWS half is
    DEFERRED 2026-09-13 (task 24.3), never exercised.** ~~WHEN a **Scan Run**
    targets AWS, valvur SHALL use the identical image with no AWS-specific code
    path.~~ The requirement had two halves and evidence for one. *No cloud-specific
    code path* is asserted on every commit (`test_there_is_no_cloud_specific_code_path`
    greps the source for cloud SDKs and platform branches) and is the property the
    original was reaching for. *Targets AWS* has never been run there: ADR-0001's
    shim launches containers, Fargate exposes no Docker socket (12a.4 corrected
    CLAUDE.md's claim to that effect), and nobody has run it on ECS-on-EC2 or a plain
    EC2 host, which is where it would work. The condition that revives the deferred
    half is a measured run on such a host, recorded here with the date and the
    numbers; until then the traceability ratchet counts the ID as cited by the
    test of the half that holds, and no document may say valvur runs on AWS. The
    ID stays; nothing else may reuse it.

11. F1.11 — WHEN a **Scan Run** is interrupted, valvur SHALL stop the **Scanner**
    containers it started, SHALL write no **Results Folder**, and SHALL NOT report the
    run as failed. *Added 2026-09-05 (task 16.2). Interruption is a third outcome:
    "a Scanner produced no report" is a failure path, and a cancelled scan must not
    be mistaken for one. Measured: `docker run` propagates no useful signal, so
    containers must be named and killed explicitly.* *Note 2026-09-13 (task 23.3.3):
    held over MCP as well as on the CLI — `scan_cancel` kills that job's own
    containers in one call, the scan checks the cancellation before the fleet, after
    it and before it writes, and `scan_status` reads CANCELLED, never FAILED.
    Measured over stdio: seven containers running, none two seconds after the call,
    and a Results Folder holding only its `.gitignore` and `.lock`.* *Note 2026-09-20 (task 26.0.2): over MCP the property had two holes, both measured — a cancel that landed before the job's runner was attached was confirmed and dropped (the scan ran to completion), and a second `scan` during `cancelling` replaced the job in the registry. Attach and cancel now share one lock, `start` refuses a job still stopping, and the flag is checked before and between a first run's fetches, not only at the fleet.*
12. F1.12 — valvur SHALL permit only one **Scan Run** per **Workspace** at a time, and
    SHALL refuse a second with a message naming the cause. *Added 2026-09-05 (task
    16.3). Concurrent scans do not corrupt the artifacts — measured — but both read
    the same `state.json` and the last to finish wins, so the next run's **Status**
    diff is computed against a view that never happened.*
## F2 — Scanner orchestration

**User Story:** As a developer, I want one command to run every relevant scanner, so
that I do not maintain six toolchains myself.

1. F2.1 — valvur SHALL orchestrate Trivy, Gitleaks, OSV-Scanner, Opengrep, Checkov
   and Syft as **Scanners**.
2. F2.2 — valvur SHALL pin every **Scanner** to an exact version in the image.
   *Extended 2026-09-13 (task 23.4.1): and every package a **Scanner** pulls in.
   Checkov, the one Python Scanner, was pinned by version while its ~95 transitive
   packages were resolved afresh on every build — the one input of the image we
   sign with our identity that was not pinned by hash. Now `requirements-checkov.txt`
   pins each by version and sha256, the image installs from it with
   `--require-hashes` into its own virtual environment, the lock is part of the
   image's build digest (22.C.1) and watched by Dependabot, and a test refuses a
   Dockerfile that installs Checkov by name again.*
3. F2.3 — valvur SHALL select **Scanners** by **Profile** per the table in
   `design.md`.
4. F2.4 — WHEN a **Scanner** exits non-zero because it found issues, valvur SHALL
   treat the **Scan Run** as successful.
5. F2.5 — IF a **Scanner** crashes, times out, or emits unparseable output, THEN
   valvur SHALL record the failure in **Provenance**, SHALL surface it at the top of
   `SUMMARY.md`, and SHALL continue with the remaining **Scanners**. *Note
   2026-09-20 (task 26.0.1): the third clause was unmet for as long as it existed —
   `adapter.parse` was never wrapped, so a Scanner exiting 0 with a report the
   adapter could not read raised out of the whole run, and every test citing this
   requirement exercised a crash or a refusal. Measured with Trivy's JSON cut at
   character 50, found by the second external review. Now one failed Scanner,
   `report unreadable: <exception>: <message>`, its raw text kept under `raw/`;
   four tests in `test_failures.py` cover a decode error, a shape change, the
   summary and `raw/`, and one bad report inside the Checks' batch.* *Note 2026-09-21 (task 26.2.1): a second unmet case, latent since 23.4.2 — a Check that raised inside the Checks' batch was recorded ok with zero findings and its error dropped, because the batch gave it an empty report with a non-zero exit and that is what a Scanner that found nothing looks like. Found by the refactor's fakes reproducing the real report shape; fixed in `check.split_batch`, a fleet-level test pins it.*
6. F2.6 — valvur SHALL run independent **Scanners** concurrently.
7. F2.7 — valvur SHALL enforce a per-**Scanner** timeout and SHALL record any timeout
   as a failure under F2.5. *Extended 2026-09-13 (task 23.3.7): and a budget for the
   fleet as a whole — none on the CLI unless `--budget` is given, 300 seconds over
   MCP unless the client names another (N1.2's figure) — past which no new
   **Scanner** starts, the running ones are stopped, and each one cut is recorded
   as a failure under F2.5 naming the budget, so the run reads incomplete on every
   surface. A cut is not an interruption (F1.11): the **Scanners** that finished
   are a result. Measured against the real image with a 20s budget: six Scanners
   ok, Opengrep and Checkov cut at 20s, `complete: False`, no container left.*
8. F2.8 — valvur SHALL preserve each **Scanner**'s unmodified output under `raw/`,
   subject to F5.7.

## F3 — AI-specific Checks

**User Story:** As a developer shipping AI-generated code, I want checks for failure
modes classic scanners miss, so that hallucinated and poisoned inputs are caught.

1. F3.1 — valvur SHALL implement a Dependency Reality **Check** that, for each
   declared dependency, determines whether the package exists on its registry.

   > ✅ **MET 2026-09-10 (task 19.D.1), for the ecosystems named — and the residue is
   > now reported rather than silent.** Reads `requirements*.txt` and `pyproject.toml`
   > (PEP 621 *and* Poetry shapes) against PyPI, and `package.json` against the npm
   > registry. Direct manifests only, never lockfiles: a lockfile is a resolved
   > transitive tree, and the invented name is written into the file a human or an
   > agent edited.
   >
   > **What it was.** The **Check** read one manifest format and queried one registry.
   > Measured: an npm project with a deliberately non-existent package returned
   > **0 findings**, silently. F3.5 did not cover that — its skip condition is *"cannot
   > reach a registry"*, and an unsupported ecosystem is a different thing entirely.
   > The most distinctive **Check** in the product (§5.3) reported nothing, and said
   > nothing about why, for the majority of repositories.
   >
   > **Cargo, Go, Ruby, PHP and JVM still have no existence check**, and that is the
   > half this requirement now depends on staying honest: each is declared in
   > `ecosystems.py` and reported as a **Finding** by `coverage.py` when present, on
   > every **Profile**. *"Each declared dependency"* is satisfied where we say it is,
   > and where it is not, the reader is told rather than left to infer coverage from
   > silence.
   >
   > **Extended 2026-09-12.** JVM and Go are read on `full` (22.A.4); Ruby
   > (`Gemfile`, `*.gemspec`), PHP (`composer.json`) and Rust (`Cargo.toml`) are read
   > offline from the **Name Index** (23.2.2, 23.2.3). What remains unread — a
   > `Pipfile` or `setup.py` with nothing readable beside it, a lockfile alone — is
   > still reported by `coverage.py` as before, and the mechanism is pinned against a
   > hypothetical ecosystem with no parser so it cannot rot for want of a live case.

2. F3.2 — WHEN a declared dependency does not exist on its registry, valvur SHALL
   raise a **Finding** of the highest severity tier.
3. F3.3 — valvur SHALL flag a dependency as a possible **Slopsquat** WHEN it was
   first published recently AND has low adoption, per thresholds in `design.md`.

   > **Partially met, stated 2026-09-12 (task 22.C.2).** The age half is implemented
   > (`valvur.dependency.newly-registered`, 90 days, on `full`). The adoption half is
   > **not**: PyPI publishes no download counts — they come from a third-party
   > service, which F1.7 and ADR-0008 rule out — and npm's counts would give one
   > ecosystem a signal the other cannot have. A package under 90 days old is
   > reported without the adoption qualifier, which over-reports rather than
   > under-reports. Cited by the code that implements the half it implements; the
   > ratchet cannot tell the difference, and this note is what can.
   >
   > **Met for npm, 2026-09-18 (task 23.5.4).** `api.npmjs.org/downloads/point/last-month/`
   > is public and unauthenticated, so on `full` an npm name the registry has dated
   > under 90 days is asked for its last-month downloads — only those names, so
   > nothing leaves the machine that had not already — and *new AND under 1,000
   > downloads* (design.md's threshold) is reported at **high**; new but adopted at
   > low, with the count; the API unreachable falls back to the age-only finding at
   > medium. Measured through the real container: a 7-day-old scoped package with
   > 89 downloads, high; a 6-day-old one with 1,940, low. PyPI, RubyGems, Packagist
   > and crates.io stay age only, and the finding's evidence says so.
4. F3.4 — valvur SHALL flag a dependency whose name is within edit distance 1 of a
   substantially more popular package in the same ecosystem.

   > **Met for PyPI, by proxy (task 22.C.2).** "Substantially more popular" is
   > membership of the top-3,000 list shipped in the image, not the 100× download
   > ratio `design.md` names, for the same reason as F3.3. No other registry has such
   > a list in the image, so npm, RubyGems, Packagist and crates.io names are checked
   > for existence and not for similarity — the Coverage contract says so on every
   > run (19.E.1).
5. F3.5 — IF the Dependency Reality **Check** cannot reach a registry, THEN valvur
   SHALL record the **Check** as skipped in **Provenance** and SHALL NOT report its
   dependencies as clean.

   > **Amended 2026-09-12 (ADR-0018).** "Cannot reach a registry" now covers two
   > sources. Existence is answered from the **Name Index** on every Profile, so the
   > registry is needed only for first-publish age on `full`. The rule extends
   > unchanged to the index: **no index on `offline` is a recorded failure with the
   > fix named, never clean**, and a stale index makes a nil result `inconclusive`
   > (F7.16) with its age in **Provenance** — the same treatment as the vulnerability
   > database (F6.11).
6. F3.6 — valvur SHALL implement an AI Artifact **Check** over agent instruction and
   configuration files, including `CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
   `.github/copilot-instructions.md`, `.claude/`, `.mcp.json` and `SKILL.md` files.

   > **Amended 2026-09-18 (task 23.5.1).** The list now includes the primary
   > client's own folder — `.kiro/steering/`, `.kiro/settings/mcp.json`,
   > `.kiro/hooks/` (and not `.kiro/specs/`, the project's own documents) — and the
   > clients the Check did not read: `.clinerules` (file or directory), `.roo/`,
   > `.continue/`, `.windsurf/`, `.roomodes`, `.aider.conf.yml`. And a second kind
   > of surface: a **hook that runs a shell command on an event** — a Kiro hook of
   > action type `command`, a Claude Code `type: command` handler in
   > `.claude/settings.json`, aider's `lint-cmd`/`test-cmd` — is a Finding
   > (`valvur.ai-artifact.hook-runs-command`, high) with the command as fenced
   > evidence, because a committed hook makes every agent that opens the repository
   > execute it unprompted (§4). A Kiro workspace was scanned on 2026-09-12 by the
   > Check that exists for it and could not have seen a poisoned steering file.
7. F3.7 — The AI Artifact **Check** SHALL detect zero-width, bidirectional and tag
   Unicode characters in those files.
8. F3.8 — The AI Artifact **Check** SHALL detect MCP server definitions pinned to a
   mutable git reference.
9. F3.9 — The AI Artifact **Check** SHALL detect blanket tool auto-approval and
   permission-bypass directives.
10. F3.10 — valvur SHALL implement an LLM-Output-to-Sink **Check** detecting model
    output reaching `eval`, `exec`, a shell, an SQL query, or `innerHTML`. *Note
    2026-09-13 (task 24.2): implemented as four Opengrep rules in
    `rules/llm-output-sinks.yaml`, three in taint mode with the OpenAI, Anthropic
    and Gemini SDK calls as sources, one a plain string-built-SQL pattern. They fire
    on the fixture
    and have fired zero times on twelve real repositories including an LLM tool
    (22.E.2) — no repository there executes model output, so the requirement is
    cited and exercised, and whether it is* met *on real code is unmeasured. The
    README and POSITIONING.md no longer present it as a held capability; 23.5.3
    measures it with real sources or retires the word.* *Measured 2026-09-18
    (23.5.3): sources widened to six SDK families and fifteen planted flows fire,
    `innerHTML` included; on two real projects that execute model output
    (smolagents, now in the corpus; pandas-ai) the flow crosses a class boundary,
    intra-procedural taint does not see it, and the INFO sink inventory names both
    `exec` sites. The word stands as a description of the rules; the README says
    the inventory is what fires on real code.*
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

   > **Amended 2026-09-17 (task 23.5.5).** Raised, and since 23.5.5 a **coverage
   > note** — never active, never a gate failure, counted as `not covered` — because
   > "cannot be determined" is a statement about what valvur could read, not a
   > defect in the code (§7's rule that the verdict is about the code). Unlike the
   > other notes it casts no doubt on the security verdict: `clean` stays `clean`.
   > The same class holds F4.1's "could not be identified" and the collapsed
   > "N dependencies have no licence recorded". A *missing* licence file (F4.2), a
   > *contradiction* (F4.3) and a *copyleft conflict* (F4.5) are facts about the
   > project and stay Findings in the ordinary sense. Measured on the public corpus
   > before the change: a licence statement active on eight of twelve real
   > repositories, one reading `findings` on nothing else.

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

11. F6.11 — valvur SHALL determine the age of the vulnerability database from the data
    it contains, not from the file's modification time, and SHALL report that age in
    the **Results Folder**. *Added 2026-09-05 (task 14.1). An air-gapped mirror (F10.5)
    can serve a six-month-old database today; mtime would read as fresh, so the users
    who most need the warning were guaranteed not to get it.*
## F7 — Results contract

**User Story:** As an AI coding agent, I want results in a bounded, self-describing
form, so that I can act on them without exhausting my context window.

1. F7.1 — valvur SHALL write the **Results Folder** to `.security-scan/` in the
   **Workspace**.
2. F7.2 — valvur SHALL write `.security-scan/.gitignore` containing `*`.
3. F7.3 — **RETIRED 2026-09-12 (task 22.C.2), never implemented.** ~~valvur SHALL add
   `.security-scan/` to the **Workspace**'s root `.gitignore` if absent, and SHALL
   NOT otherwise modify that file.~~ Found by taking the traceability ratchet to
   zero: this was the one requirement no code cited, and the reason was that no code
   does it. Nor should any — editing a tracked file in the scanned tree is a write to
   the **Workspace**'s source, which CLAUDE.md section 10 prohibits and moat item 2
   makes structural (the container cannot; the host shim must not). The guarantee
   this was reaching for is already F7.2's: the **Results Folder** ignores itself
   from the moment it is created, and travels with that ignore file wherever it is
   copied. CLAUDE.md section 7 claimed the root entry was added; it was corrected in
   the same task. The ID stays; nothing else may reuse it.
4. F7.4 — valvur SHALL write `SUMMARY.md`, `REMEDIATION.md`, `findings.json`,
   `results.sarif`, `sbom.cdx.json`, `run.json` and `raw/`. *Note 2026-09-20 (task 26.0.3): every document is written whole beside its name and renamed into place in one loop, `run.json` last, and `findings.json`, `run.json`, `state.json` and `results.sarif` (as `automationDetails.guid`) carry one `generation` per Scan Run — so a folder holding two runs' files is detectable, where before the seven sequential writes could leave it silently mixed. An optional artifact this run did not produce is removed.*
5. F7.5 — `SUMMARY.md` SHALL NOT exceed 200 lines regardless of **Finding** count.
6. F7.6 — `SUMMARY.md` SHALL open with a machine-facing block describing the folder,
   the **Status** values, the ranking basis, and the constraints in F9.5–F9.7.

   > ⚠️ **PARTIALLY UNMET until 2026-09-10 (task 10.4.12).** The block described the
   > folder and the F9.5–F9.7 constraints, and said nothing about **the Status values
   > or the ranking basis** — two of the four things this requirement names. An agent
   > reading `inconclusive` had nothing telling it not to report that as clean, which
   > is the entire reason F7.16 put the claim in the verdict rather than in prose. Both
   > clauses are now present, and a test asserts each **Status** value appears by name.
   >
   > **A one-sentence human verdict now precedes the block**, after the title. F7.6's
   > protection is that an agent meets the constraints before any **Finding**, which
   > F7.7 states at the content level and which still holds. What a human met first was
   > twelve lines of instructions addressed to somebody else.
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

16. F7.16 — valvur SHALL report a **Status** of `findings`, `clean` or `inconclusive`,
    and SHALL NOT report `clean` when no **Finding** was made against a vulnerability
    database older than the threshold in `design.md`, **or when an ecosystem present in
    the Workspace was not inspected at all**. *Added 2026-09-05 (tasks 14.1, 14.2).
    Presence of **Findings** needs no fresh data to mean something; absence does. Prose
    alone was insufficient: agents are instructed to read `SUMMARY.md` bounded and query
    `findings.json`, so the verdict itself must carry the claim.*

    > **Amended 2026-09-10 (tasks 19.C.2, 19.E.2).** Three **Status** values, still —
    > `clean-with-suppressions` was rejected, because every consumer switches on these
    > three and a fourth is a breaking change buying a count now printed beside the
    > verdict on every surface.
    >
    > What changed is what feeds the verdict. It was every **Finding**, so a scan whose
    > only **Findings** were accepted risks read `findings`, and after 19.D.1 any
    > repository containing a `Cargo.toml` could never read `clean`. Neither is a
    > statement about the user's code. **Suppressed Findings and coverage notes no
    > longer make the verdict negative**, and both are counted explicitly instead.
    >
    > The uninspected-ecosystem clause is the same claim the stale-database clause
    > already made: *we did not look, so `clean` is not ours to claim*. It deliberately
    > does **not** cover a **Profile** omission — the user chose `offline` and valvur
    > did that job completely, which is different from valvur silently being unable to
    > do a job nobody declined. That gap is named in `SUMMARY.md` and `run.json` on
    > every run instead.
17. F7.17 — `run.json` SHALL record the vulnerability database's age, whether it is
    stale, and the threshold applied. *Added 2026-09-05. N3.1 requires a **Clean
    Scan** to be distinguishable from a failed one; it must also be distinguishable
    from one whose data was too old to know.*
18. F7.18 — The **Results Folder** SHALL be self-ignoring from the moment it is
    created, not from the completion of a **Scan Run**. *Added 2026-09-05 (task 16.3).
    F7.2 was satisfied only at the end of a run; interruption (F1.11) is routine, and
    would otherwise leave a folder git can see.*
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
   release. *Note 2026-09-21 (task 26.1.3): and the pipeline SHALL verify what it
   publishes — the image's signature and its SLSA provenance in `artifact`, on
   both architectures, and each distribution's attestation read back from the
   index in `promote`. Until then the attestation was made and never checked by
   the pipeline; the second external review found it.*
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
   *Extended 2026-09-12 (task 23.2.1): the **Name Index** is an OCI artifact too,
   published daily and signed, and `VALVUR_INDEX_REPOSITORY` mirrors it the way
   `VALVUR_DB_REPOSITORY` mirrors the database; the static-file mirror of 22.B.3
   remains. `docs/AIR-GAPPED.md` is the measured recipe.*
6. F10.6 — The host shim SHALL install without a compiler, without the **Scanners**
   present on the host, and with **no runtime dependencies at all** — including the
   MCP server, which is on the primary install path.
   *(See [ADR-0015](../../../docs/adr/0015-hand-rolled-mcp-stdio-transport.md): the
   official SDK pulls 22 packages including an HTTP server, an OAuth stack and a
   crypto library to support transports we do not use. stdio is implemented directly.)*

---

7. F10.7 — valvur SHALL publish the image for `linux/amd64` and `linux/arm64`, and
   SHALL verify the published artifact rather than a locally built one. *Added
   2026-09-05 (task 13.1). `0.1.0rc1` was published `arm64` only, unusable for most
   CI, most Linux desktops and every Intel Mac. Both workflows built locally and
   neither pulled what was published, so no test could see it.* *Note 2026-09-21
   (task 26.1.2): "verify" had meant amd64 — the arm64 image was built, listed
   and never run by the pipeline. Now `artifact` and `published` each run on both
   architectures natively; measured, the arm64 leg is the faster and leaner.*
8. F10.8 — valvur SHALL provide a means of refreshing the vulnerability database that
   is a no-op when it is current, and SHALL NOT refresh a database it has as a side
   effect of a **Scan Run**, however stale. A database or **Name Index** that is
   *absent* SHALL be fetched by the first **Scan Run** that needs it, and the fetch
   reported on every progress surface. *Added 2026-09-05 (task 14.2). The check costs
   one file read, so it is safe in a hook or a cron entry. Refreshing during a scan
   would start a 116MB download the developer did not ask for, and would make the
   `offline` and `full` **Profiles** scan different data.* *Amended 2026-09-13 (task
   24.1): absence is not staleness. Measured against the published `0.2.0`, the
   primary path's first `scan` finished incomplete naming a CLI command the agent
   could not run; without the data there is no scan at all, and 23.2.4 had already
   fetched the absent image from inside one. The stale case is unchanged.*
## Non-functional requirements

### P — Positioning commitments
Traceable to [docs/POSITIONING.md](../../../docs/POSITIONING.md) §6.

1. P1 — A first **Scan Run** SHALL require one command, no account, and SHALL complete
   the `offline` **Profile** in under 60 seconds on a mid-sized repository. *Note
   2026-09-13 (task 24.1): "one command" is now true on the primary path — a first
   `scan` over MCP with nothing run first fetches the image, the database and the
   index itself, measured at 110s to a complete result from an empty machine. The
   60s is the scan proper (33s on the fixture, 7–24s on small real projects); the
   first run's fetches are stated separately in `docs/EVALUATING.md`.*
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
   ≤50k lines of application code, on a 2-vCPU Linux host with a native container
   runtime, with the image and the data already present. *Amended 2026-09-13 (task
   24.3), with the evidence the original lacked.* The requirement was cited by an
   e2e test that scans this repository (38,697 lines on 2026-09-01: 23.4s) and by
   nothing at the size it names. **Measured on the public corpus with 23.3.2's
   per-Scanner timing, on GitHub's `ubuntu-latest` runner (Ubuntu 24.04; the
   workflows name that image since 2026-09-20), 2026-09-13 (run
   34764187516):** every application repository — cobra 44k lines 14.4s, flask
   47.5k 16.1s, llm 53k 15.2s, gson 64k 16.7s, ripgrep 80k 17.6s, fastify 100k
   16.1s, and the six smaller ones 14–17s — completes in **14–18 seconds, flat with
   size**, because the scan is Checkov's ~15s fixed start-up and every other
   Scanner takes 1–4s. Three amendments follow. **(a)** *Application code*: the one
   corpus repository that is infrastructure, `terraform-aws-vpc` (22k lines), took
   **88.2s — Checkov analysing it for 87.8s** — so the 60s claim is not held for
   IaC-heavy repositories and this text says so; every run names its slowest
   Scanner (23.3.2), and 23.4.6 decides Checkov's place. **(b)** *The host*: the
   same 3,404-file workspace that meets 60s on the runner read 60.6s, 75s and 94s
   on an Apple-silicon laptop through Docker Desktop at load 8–13, where a container
   start costs 10–16s against 2–3s on Linux; the requirement names the machine
   class it is met on rather than implying every laptop. **(c)** *Data present*: a
   first run's fetches are stated separately (24.1, `docs/EVALUATING.md`).
2. N1.2 — `full` **Profile** SHALL complete in under 5 minutes on the same. *Note
   2026-09-13 (task 24.3): measured beside N1.1 on the same run — `full` is `offline`
   plus 0–1s on every corpus repository (osv-scanner 0.9–1.9s), 15–17s on
   application code and 88.2s on the Terraform module. Met with an order of
   magnitude to spare.*
3. N1.3 — `SUMMARY.md` SHALL be readable within a 200k-token context alongside
   `REMEDIATION.md`.
4. N1.4 — Memory use SHALL remain under 2 GB for the `full` **Profile** — the whole
   fleet of Scanner containers at once, plus the shim. *Amended 2026-09-13 (task
   24.3): measured by hand at 344 MiB peak container usage on 2026-09-01 and never
   asserted — the test that cited this ID skipped itself. Now asserted in the e2e
   suite on Linux (`test_a_full_scan_stays_within_its_memory_budget`): a sampler
   reads `<runtime> stats` throughout a `full` scan of this repository, keeps the
   highest sum over every `valvur-*` container, adds the shim's own peak RSS, and
   fails the build above 2 GiB; the number it measured is printed on every CI run.
   Its first: **505 MiB** on `ubuntu-latest` (Ubuntu 24.04), 2026-09-13 — a 451 MiB fleet at the
   peak (seven containers alive, the largest 253 MiB) and a 54 MiB shim.
   On macOS the same sampler read a 493 MiB fleet peak and a 38 MiB shim on the
   ten-file fixture (2026-09-13), but through Docker Desktop's VM that is the VM's
   view, so the assertion is Linux-only and macOS keeps the hand measurement.*

### N2 — Security
1. N2.1 — The `offline` **Profile** SHALL make no network connection, verified by an
   automated test that fails on any socket attempt (ADR-0010). *Note 2026-09-21 (task 26.2.2): the decision is written once, in `egress.py` — the flag, the hosts and the disclosure sentence derive from it, and a test refuses the flag literal anywhere else under `src/valvur`; `scripts/verify-offline.py` keeps its own literal as the independent check.*
2. N2.2 — valvur SHALL never write outside the **Results Folder** and the host
   scratch directory.
3. N2.3 — No **Workspace**-derived value SHALL reach a shell interpreter.
4. N2.4 — Secret values SHALL NOT be written to disk unredacted, nor to logs.
5. N2.5 — valvur SHALL pass its own `full` **Profile** with no unsuppressed
   **Findings** as a release gate.

   > **Amended 2026-09-18 (task 12b.2).** The gate runs twice in `release.yml`:
   > in `verify`, against the tree (`valvur:dev`, `uv run`), before anything is
   > pushed; and in `artifact`, after `release`, against the *release artifact* —
   > the wheel from `dist/` installed into a clean environment with the tree off
   > the path, driving the image by the digest the release job signed — together
   > with the Phase 11 constraint suite and the whole e2e suite. The second run
   > cannot stop a release that has left; it turns the run red and names why, which
   > is the honest shape of a post-publication check. Proven by rehearsal first.

6. N2.6 — valvur SHALL serialise writes to the vulnerability database cache against
   readers of it. *Added 2026-09-05 (task 16.3). Trivy takes no lock of its own —
   measured — and `trivy.db` is a 1.35GB file rewritten under live readers. Task 14.2
   put `--if-stale` into pre-commit hooks, which made the overlap likely rather than
   theoretical.*
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
