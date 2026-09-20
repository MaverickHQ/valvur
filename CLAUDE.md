# CLAUDE.md — long-term context for this repository

> **Audience:** any AI agent or human joining this project with no prior context.
> Read this before proposing changes. Written 2026-08-29, last reviewed 2026-09-20.
> **Name:** `valvur` (Estonian: *guard, watchman*) — settled, not provisional. It was
> provisional only until first publish, and `0.1.0rc1` went to PyPI on 2026-08-31,
> which claimed it (task 10.0.1).

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

**Status (2026-09-20):** **`0.3.0` is published** (`v0.3.0`, 2026-09-20; `0.2.0` on
2026-09-13) — `pip install valvur` works for anyone, the image is on GHCR for both
architectures, signed and attested, the release pipeline's last job tested the
published wheel and the signed image rather than the tree, and a stranger's first
run measures **about a minute** from nothing to a first result on either path (CLI:
45s of fetches then a 19s scan; one `scan` call over MCP with nothing run first: 58s
to `DONE`). The `0.2.0` story, which this release closes: an audit of the requirements
against `0.2.0` the morning it shipped became **Phase 24**, whose head holds **the one ordered list of every open
task** — 4 of them now, the release cut and the action's tag given IDs on
2026-09-18 and both closed with the yank on 2026-09-20 — and whose first engineering item was the audit's worst
finding: over MCP, the primary path, a stranger's first `scan` finished *incomplete*
because the database and index were absent and the only fix named was a CLI command
the agent cannot run. **24.1 closed that the same afternoon**: a scan fetches what is
*absent* — image, database, index, in that order, each announced on `scan_status` —
and never touches what is *stale*; measured from an empty machine over stdio, one
tool call, **110s to `complete: True`**. **24.2 followed**: the README no longer
sells the LLM-output-to-sink rules as a capability. **Then `valvur doctor`
(23.3.1)**: nine checks in the order a scan meets them — TLS trust counted rather
than requested, the runtime found *and running*, the image present, compatible and
started once, database and index present and current, the SELinux label, the MCP
client configuration — one line each with the fix, exit 1 if a scan would fail, the
same report as a `doctor` MCP tool that a FAILED `scan_status` now names. **Then
23.3.2**: `duration_s` on every Scanner, on every surface — which measured Checkov
at 41–59s and the three Checks at 10–16s *each* for millisecond work, the numbers
23.4.6 and 23.4.2 were waiting for. **Then 24.3**: the three requirements the ratchet could not see through, given
evidence — N1.1 measured on the corpus on Linux at 14–18s for every application
repository and 88s for a Terraform module, and amended to say both. **Then 23.3.4**: `scan_status` never cuts a failure reason mid-sentence (lines
are bounded, sentences are not) and names the next two moves — `explain_finding`
for the top active Finding and `REMEDIATION.md`'s first action. **Then 23.3.5**: `valvur gate` — the release-gate heredoc `ci.yml` and
`release.yml` each carried, once, with a threshold, and the same command a user's CI
runs — and `valvur cache`. **Then 23.3.3**: `scan_cancel` — a per-runner kill, one call for the whole fleet,
and F1.11's three properties over MCP: containers stopped, nothing written, not a
failure — and `--jobs`/`VALVUR_JOBS`. **Then 23.3.7**: a scan budget — 300s over MCP, none on the CLI unless asked —
past which nothing new starts, the running Scanners are stopped, and the run is
written incomplete with each cut named. **Then 23.3.6**: `MaverickHQ/valvur-action`, public, self-tested, and the
self-scan job here uses it with the tree's own shim. **Then 23.4.1**: Checkov hash-locked — 96 packages, 1,866 hashes — into its own
venv, and on the way the Dockerfile's `… || true` that had let a failed install
report success. **Then 23.4.2** (2026-09-14): the three Checks in one container — nine starts a
scan became seven, ~4s off every scan measured, three ScannerRuns kept. **Then 23.4.3**: one bake file, and the release builds each architecture on its
own native runner — 1m14s against 4m50s under QEMU, proven by rehearsal. **Then 23.4.4**: the wheel carries the tree hash it was built beside, and a scan
says — never refuses — when the image's differs: rc1's hole, closed as a diagnosis.
**Then 23.4.5**: OSV-Scanner's marginal value measured on the corpus — 121 Go
standard-library advisories on the one Go project, one disputed advisory on flask,
nothing on the other ten — kept on `full` with the number in the README. **Then
23.5.5** (2026-09-17, the first of Batch 1): a licence valvur could not read is a
coverage note that casts no doubt — awesome-cursorrules went from `findings` to
`clean: 0 active, 1 not covered` — and on the way, two older defects: every
coverage note had been a `REMEDIATION.md` action (the lockfile gap read *"Remove
the hallucinated dependencies"*), and Trivy's comma-joined fix list reached the
proposal verbatim. **Then 23.5.1** (2026-09-18, Block A's first): the AI Artifact
Check reads `.kiro/` — steering, MCP settings, hooks, and deliberately not `specs/`,
where this repository's own task text would have failed its own gate — plus Cline,
Roo, Continue, Windsurf and aider's files, and a new high rule for **a committed hook
that runs a shell command on an event** (Kiro, Claude Code, aider), the command as
fenced evidence. **Then 23.5.2**: the MCP `tools/list` reply is a committed
snapshot, taken through the real server, so a schema change is a diff in review —
the rc's `standard` Profile could not happen again. **Then 23.5.3**: the LLM
taint rules know six SDK families and fifteen planted flows fire — the `innerHTML`
rule had never had a fixture — and, measured on two real projects that execute
model output, neither flow is seen: the model call and the `exec` sit in different
classes, Opengrep's taint is intra-procedural, and the INFO sink inventory names
both. The word stays, the README says the inventory is what fires on real code,
and smolagents is the corpus's thirteenth repository so the limit is measured
weekly. **Then 23.5.4**: npm adoption on `full` — a name the registry has dated
under 90 days is asked api.npmjs.org for its last-month downloads, and *new and
under 1,000* is the slopsquat signal at high, measured live on a 7-day-old package
with 89 downloads; and `run.json`'s non-exfiltration sentence, found to have
missed three registries since 23.2.2, now names every destination. **Then 23.4.6**,
decided by measurement and declined (ADR-0019): Checkov is 53MB of a 223MB pull, a
slim image saves about 5s of a 110s first run and reaches a repository the corpus
cannot find — 13 of 13 carry a workflow file — while the cost users pay, Checkov's
runtime at 97–100% of every scan, is unchanged by either shape. **Then 12b.2**: the
release pipeline's last job tests the artifact, not the tree — the wheel from
`dist/` in a clean environment with `src/` off the path (proven: `valvur._build`
exists only in a wheel), the image by the digest just signed, the constraint suite,
the e2e suite and the gate through both. Three rehearsals to green, each finding
something: the F10.4 licence test had only ever checked a literal `valvur:dev`, and
a 2026-09-01 suppression matched only because the verify job's checkout carries a
`.venv`. **Block A is complete**, and its corpus dispatch read as planned — zero AI
Artifact findings on real instruction files, the taint rules zero with the inventory
naming smolagents' `exec` — **and found one more thing**: on smolagents, `full`
added 110 advisories that are OSV-Scanner evaluating a wholly unpinned
`requirements.txt` at its lower bounds, while on `offline` the same file read as
*checked* with Trivy correctly finding nothing for a range — a silent clean on the
commonest Python manifest shape. **25.3 closed it the next morning** (2026-09-19): a
requirements file counts only for its pinned lines — a file of ranges is the
lockfile coverage note, naming the file and how many lines are ranges — and
OSV-Scanner's lower-bound advisories are dropped before merging with the count on
every surface; 193 on smolagents. **Twenty-three tasks closed after `0.2.0`
shipped — and released together as `0.3.0` on 2026-09-20 (25.1)**: a rehearsal on
the exact tree, the tag, fifteen minutes to a green run whose last job tested the
artifact; re-measured from a stranger's state, 58s over MCP against 110s. **Then
25.2**, the same day: `valvur-action` tagged `v0.1` and `v0` — on a commit whose
own self-test had just installed `0.3.0` from PyPI, the README example's path,
green in 50s — so `uses: MaverickHQ/valvur-action@v0` works for anyone; `ci.yml`
keeps the tree's shim and a SHA pin, now the tag's commit. **Then 24.4**: `0.1.0rc1`
yanked, twenty days after it went up as a release nobody could run — Checkpoint B
is complete. **Next: the usability gate on `0.3.0` (10.1.1–10.1.2, then 12b.1),
then `v1.0.0` (12b.3).** When "what is next" is asked, Phase 25 is the answer; Phase
24's list keeps the rows and the numbers, and the sequencing diagrams in Phases
21, 23 and 24 are history.

The repository and both GHCR packages — `valvur`, the image, and `valvur-index`,
the daily name index — went public on 2026-09-13, after a pre-public sweep that
rewrote history to scrub two AWS identifiers (12a.1). `main` is protected: five
required checks, signed commits, linear history, enforced for administrators — so
**every change lands by pull request**, fast-forwarded onto `main` once the checks
pass. Phases 19 and 20 are complete. A critical review on 2026-09-12 became
**Phase 22**, and its first two blocks ran *before* `0.2.0` published:

- **Block A — the offline existence check. Done, 22.A.1–2 (2026-09-12).** Slopsquat
  detection ran only on `full` because it needed a registry — and `full` sends
  package names out, which target market #1 cannot do. "Fully offline" and
  "hallucinated-package detection" were both true and never at the same time. Now
  *existence* is answered from a **Name Index** — every name on PyPI and npm (and,
  since 23.2.2–3, RubyGems, Packagist and crates.io), exact, in the host cache
  beside the vulnerability database, mounted read-only —
  on the default Profile with no socket; only first-publish age — and, for npm since
  23.5.4, last-month adoption — still needs `full`.
  ADR-0018, amending ADR-0016. Proven on the broken fixture in a real container:
  `reqeusts` and `aws-helper-sdk` reported offline, `what_left_the_machine: nothing`.
  **Block A is complete** (22.A.3 bounded concurrent lookups; 22.A.4 JVM and Go,
  `full`-only because neither registry has a name list — measured, 3.2GB for Maven).
- **Block B — prove the release pipeline. Done (2026-09-12).** The push that
  started it found CI had not run for twelve days and 68 commits. Three rehearsals of
  `release.yml` (its new `workflow_dispatch` mode: same steps, throwaway targets)
  broke four things, all fixed; everything is proven except SLSA attestation, which
  GitHub refuses on a private repository, and the TestPyPI upload, which needs the
  owner's trusted publisher. The keyless signature on the rehearsal image verifies
  with the README's own command. A real air-gapped run — mirror registry on an
  `--internal` network, host poisoned to loopback — found the documented
  `VALVUR_DB_REPOSITORY` insufficient on its own: three settings that did not exist
  that morning (`VALVUR_DB_INSECURE`, `VALVUR_CONTAINER_NETWORK`, `VALVUR_KEV_URL`),
  plus `VALVUR_NAME_INDEX_URL`. The true first run was **about eight minutes**, most
  of it npm, and `EVALUATING.md` said so — until 23.2.1 published the index (below).

**Phase 22 is complete (2026-09-12)**: the offline existence check, four release
rehearsals, the image-staleness guard, the traceability ratchet at zero, the named
pipeline, the public corpus (which found the Express lockfile gap on its first run),
the halved README, and Kiro verified — which found that the published `0.1.0rc1`
shim looks for a local `valvur:dev` image and can never have worked for anyone.

A second review, grounded in that Kiro run, became **Phase 23**: `0.2.0` first
(Block 1, owner actions); then the **published name index** and **`valvur doctor`**
(every first-run failure this project has met was a precondition it would have
named; both done 2026-09-13) — both *before* the usability gate measures a
stranger's first ten minutes;
then Checkov isolated and hash-locked, the Checks in one container, per-scanner
timing, the shim carrying its build hash, and `.kiro/` — the primary client's own
files — into the AI Artifact Check. Then the gate and `v1.0.0`. *(Block 4 ran
ahead of the gate, on 2026-09-14 — it needed nothing from a stranger — and closed
with its Checkov-on-demand decision on 2026-09-18, declined by measurement; Block 5
closed the same day.)*

**Phase 24 was written the same morning `0.2.0` shipped**, from an audit of the
requirements against the published release — three measurements taken against the
PyPI wheel and the GHCR image rather than the tree, and a pass over all 136
requirement IDs asking *met?* rather than *cited?*. Its head is the single ordered
list of everything open; its four tasks are the audit's findings, and three of
them — 24.1, 24.2 and 24.3 — closed the same day (below); the fourth, the owner's
yank, on 2026-09-20. It also moved Checkov's hash-locking
(23.4.1) ahead of the usability gate: it is the one input we sign with our identity
that is not pinned by hash.

**Block 1 closed on 2026-09-13 with `v0.2.0`** — three rehearsals on the public
repository first. The sixth found that `uv build` writes core metadata 2.5 and the
pinned publish action's twine refused it: the real release would have failed at its
last step, after the image was pushed and signed. The TestPyPI upload is the only
step that runs that check, which is the argument for rehearsing the step that
"was not really required". The measured first run, and the one defect it found
(a Python without a CA bundle fails every host-side fetch — a `doctor` check), are
under 23.1.1.

**Block 2 landed the evening before (23.2.1–23.2.4).** `index.yml` walks PyPI, npm,
RubyGems, Packagist and crates.io daily and publishes the result to
`ghcr.io/maverickhq/valvur-index` as a cosign-signed OCI artifact; `valvur update`
pulls it through the shim's own zero-dependency registry client (`oci.py`) — 34MB,
seconds — verifies the signature with cosign when installed, and falls back to
walking the registries when the package cannot be reached. Ruby (`Gemfile`,
`*.gemspec`), PHP (`composer.json`) and Rust (`Cargo.toml`) join Python and npm
offline. `valvur update` pulls the image, and a scan that has to says so on
`scan_status`. It held the pattern: the first real pull found a chunk-boundary
defect the unit fixtures could not; the Rust task's "impossible per user" premise
was wrong by a factor of five once measured; and the first workflow run showed the
private package refusing every anonymous pull, which is now on Block 1's list. Both
diagrams and the notes are at the head of Phase 23 in
[`tasks.md`](.kiro/specs/valvur/tasks.md).

Roughly: 57 modules under `src/valvur`, 973 tests in 52 files, 19 ADRs, 136
requirement IDs, **172 done and 4 open** across 25 phases — the usability gate and
the `v1.0.0` tail; Phases 23 and 24, Block A and Checkpoint B are complete, `0.3.0` is out, the action is tagged and the rc is yanked. Two of the 4
are the owner's (the gate, the `v1.0.0` tag). A public corpus of thirteen real repositories runs
weekly (`corpus.yml`); it found a defect on its first run. Traceability debt: zero, and a hard check since 22.C.2.

The work that closed Phases 19 and 20 was run as **six blocks** rather than task by
task; the grouping and what each block found sits at the head of Phase 19 in
[`tasks.md`](.kiro/specs/valvur/tasks.md). The pattern that held across all six: every
block found defects that unit tests could not — through a corpus of real repositories,
a real enforcing SELinux host, and a real agent driving the MCP surface — and most
were introduced by the block before, with tests passing.

**Known gaps, and one deliberate friction, worth knowing before proposing anything:**

- **A scan fetches what is absent and never what is stale (24.1, closed
  2026-09-13).** Measured against the published release that morning, the primary
  path's first run finished `complete: False`: Trivy and the dependency-reality
  Check both failed, each saying *"Fetch it once with: `valvur update`"* — a command
  the agent has no tool for. 14.2's rule that valvur never updates by itself was
  about *staleness*; absence is a different case, and 23.2.4 had already fetched
  the absent image from inside `scan`. Now `api._ensure_data` does the same for the
  database and the index, before the shared cache lock (both fetches take it
  exclusively), announced on `scan_status` and the terminal; the index fetch never
  falls back to the seven-minute registry walk; a failed fetch costs only the
  Scanner that needed it, and that Scanner's failure says why. The stale rule is
  unchanged and now pinned by behaviour rather than by a word in `scan`'s source.
  F10.8 amended. **The friction worth knowing:** a first run on a host with no
  route to GHCR is *incomplete* with the cause named, not a hang and not a silent
  clean.
- **The LLM-output-to-sink taint rules detect the single-function shape, and real
  code does not take it (24.2, 2026-09-13; 23.5.3, 2026-09-18; F3.10 annotated).**
  Four Opengrep taint rules with sources for six SDK families — Anthropic, OpenAI
  (three call shapes), Gemini, LangChain, litellm, ollama — into the sinks the INFO
  inventory names. Fifteen planted flows fire. On **thirteen** real repositories,
  zero — and since 23.5.3 the zero is *measured*, not unmeasured: smolagents and
  pandas-ai both execute model output, both route it across a class boundary, and
  Opengrep's taint tracking is intra-procedural, so the flow is invisible to the
  taint rules while the inventory names both `exec` sites. The README says the
  inventory is what fires on real code and lists the taint rules as what they are;
  the section is carried by the Checks; `POSITIONING.md` records the measurement.
  smolagents is in the corpus so the limit is re-measured weekly.
- **Three requirements the ratchet could not see through now have evidence (24.3,
  closed 2026-09-13).** F1.10's AWS half is deferred with the condition that
  revives it (a measured run on a host with a Docker socket); the no-cloud-branch
  half is asserted. N1.1 is measured on the corpus on GitHub's Linux runner —
  **14–18s on every application repository from 22k to 100k lines, flat with
  size**, and **88s on a Terraform module** (Checkov analysing it), which the
  requirement now states as an exception rather than hides; it also names the
  machine class, because the same workspace read 60–94s on a loaded laptop through
  Docker Desktop, where a container start costs 10–16s against 2–3s on Linux. N1.4
  is asserted on Linux CI by sampling `docker stats` through a `full` scan (344 MiB
  by hand; the CI number is printed on every run). What the numbers also say:
  Checkov runs on every real repository (they all carry a workflow file) and is
  85–95% of every scan — which decided 23.4.6 (ADR-0019, 2026-09-18): one image,
  Checkov in it, because the cost is time and no image shape changes it.

- **Slopsquat detection covers Python, npm, Ruby, PHP and Rust offline, JVM and Go
  on `full`, and nothing else.** `requirements*.txt` and `pyproject.toml` (PEP 621
  and Poetry), `package.json`, `Gemfile` and `*.gemspec`, `composer.json` and
  `Cargo.toml` against the Name Index — every name on the five registries, 6.3
  million, exact (23.2.2, 23.2.3); `pom.xml`, Gradle scripts and `libs.versions.toml`
  against Maven Central and `go.mod` against the Go proxy, per name, `full` only —
  neither registry publishes a list an offline index could be built from (22.A.4,
  ADR-0018), so on `offline` those two are a stated Profile omission, not a gap. A
  manifest valvur recognises but does not read — a lone `Pipfile`, a lockfile with
  nothing beside it — gets a **Finding** saying so, on every Profile, so the gap is
  stated rather than inferred from silence. Closed 19.D.1; the reporting half is
  permanent, and pinned against a hypothetical ecosystem now that no real one is
  unread.
- **The eleven Opengrep rules are not the product.** Measured on the public corpus
  (22.E.2): 75 findings on eleven real repositories, 64 of them tag-pinned GitHub
  Actions and the other 11 rejected by a reviewer to the last one; the four
  LLM-output-to-sink rules fired zero times, including on an LLM tool. They are now
  all `low` bar the ones that never fire on real code. What carries the AI-specific
  positioning is the **Checks** — dependency-reality, the AI Artifact Check, the
  coverage contract — and that is what the README leads with (Block F; the rules
  are listed as what they are since 24.2).
- **Known-vulnerability scanning needs a lockfile, and says so.** Measured
  2026-09-12: Trivy produces no result at all — not zero findings, no scan — for
  `package.json`, `pyproject.toml`, `Gemfile` or `Cargo.toml` without a lockfile
  beside them. Express read `clean` with thirty dependencies never checked; the public
  corpus (22.E.1) found it on its first run. Now a coverage note
  (`valvur.dependency.vulnerabilities-unchecked`) and `inconclusive`, the same
  treatment as the existence gap. `ecosystems.VULNERABILITY_MANIFESTS` records what
  was measured.
- **The Name Index is published daily and pulled in seconds.** `index.yml` walks
  the five registries every morning and pushes the result to
  `ghcr.io/maverickhq/valvur-index` as a cosign-signed OCI artifact; the shim's own
  registry client (`oci.py`, zero dependencies, anonymous only) pulls it — 34MB,
  **7.8s from GHCR measured, `signature: verified`** — and verifies the signature
  with `cosign` when installed (23.2.1, ADR-0018 amended). If the registry cannot
  be reached, `valvur update` says so and walks the registries itself — about seven
  minutes, 700MB, five and a half of the minutes npm — which is also
  `--build-index` and what the workflow runs.
- **On SELinux-enforcing hosts, valvur refuses to scan until the developer acts.**
  Measured 2026-09-10 on Fedora CoreOS 44, native xfs under `$HOME`: a container may
  not read a `user_home_t` directory, so all three mounts were denied. valvur labels
  its **own** scratch and cache mounts automatically; it does **not** relabel the
  scanned tree unless `VALVUR_SELINUX_RELABEL=1` is set, because `:z` rewrites the
  SELinux context of every file in it and that outlives the scan (§10). The cost is a
  failed first run on RHEL, accepted deliberately. F1.6 met; Phase 20 closed.

> **This line was wrong for six weeks**, saying "spec phase, no application code yet"
> while the tool scanned its own repository on every commit. It is the first thing a
> joining agent reads, so it is the first thing worth keeping true — the same drift
> Phase 17 exists to catch, in the document describing the project. If it disagrees
> with [`tasks.md`](.kiro/specs/valvur/tasks.md), the task list is authoritative and
> this line is stale again.

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
   single condition. And since ADR-0018 one Check with a reason to reach a registry
   runs on `offline` too, told by the runner whether it has a network and never
   guessing. `scripts/verify-offline.py` checks all three. On Linux
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
| [016](docs/adr/0016-two-profiles-split-on-the-network-boundary.md) | **Two Profiles, split on the network boundary.** `offline` (the default) runs every Scanner that completes under `--network=none`. `full` adds `osv-scanner` — and, since ADR-0018 amended this, lets the dependency-reality Check ask a registry for the one thing its local index cannot answer. The old set was drawn along *speed* while being described as a network boundary, and `deep` was byte-identical to `standard` — it promised more and delivered exactly `standard`. Retired names still resolve. |
| [019](docs/adr/0019-one-image-checkov-included.md) | **One image, Checkov in it.** Decided by measurement (23.4.6): Checkov is 164MB uncompressed but **53MB of a 223–233MB pull**, a slim image saves about 5s of a 110s first run, and it would reach a repository the corpus cannot find — 13 of 13 carry a workflow file, so `applies_to` runs Checkov everywhere and an on-demand second image would be pulled by everyone. The cost users pay is Checkov's runtime, 97–100% of every scan on Linux CI, which no image shape changes. Reopened by a measured user for whom 53MB matters, `applies_to` skipping on a real share of repositories, or a faster IaC scanner under an acceptable licence. |
| [018](docs/adr/0018-offline-package-name-index.md) | **An exact index of package names, from primary sources, in the host cache.** Existence — the hallucination check — is answered offline from every name on PyPI (890k), npm (4.4M) and, since 23.2.2–3, RubyGems (197k), Packagist (462k) and crates.io (332k): exact rather than a bloom filter because a false positive there is a *missed hallucination*, and a binary search over the memory-mapped file costs 8µs a name. **Published daily as a signed OCI artifact** (`valvur-index`, the `trivy-db` pattern; amendment of 2026-09-12) and pulled by a zero-dependency client in the shim — 34MB, seconds — with the registries walked directly only as the fallback. Signature verified by cosign when installed, never by a hand-rolled verifier; the alternatives are in the amendment. `all-the-package-names` was rejected on measurement, not only principle: 140,823 names it lists do not exist. Stale past 30 days → `inconclusive`. Amends ADR-0016. |
| [017](docs/adr/0017-selinux-relabelling-is-opt-in.md) | **SELinux relabelling of the source tree is opt-in.** Measured on a native enforcing host: all three mounts are denied, so valvur was unusable on RHEL — the primary target market. Its **own** scratch and cache mounts are labelled `:z` unconditionally; the **Workspace is not**, unless `VALVUR_SELINUX_RELABEL=1`, because `:z` rewrites the SELinux context of every file in the scanned tree and that outlives the scan (§10, moat item 2). `:Z` is impossible rather than merely undesirable — it stamps a private MCS category and valvur runs its Scanners concurrently against one mount, so the second is denied. The accepted cost is a failed first run on RHEL. |
| [010](docs/adr/0010-provable-non-exfiltration.md) | **Provable non-exfiltration is a hard constraint.** Not a policy — a testable property, with a regression test that fails if the `offline` profile touches a socket. This is the product; see §3. |

## 7. Results contract

Written into the scanned project:

```
.security-scan/
  .gitignore          # contains "*" — the folder ignores itself, from creation
  .lock               # flock target: one scan per workspace at a time
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
- **Self-ignoring folder** is the guarantee results are never committed, and the
  only one valvur writes: it does **not** touch the scanned project's root
  `.gitignore`, because that is a tracked file in the source tree (§10, moat item 2).
  This line claimed otherwise for two weeks; F7.3 was retired on 2026-09-12 when the
  traceability ratchet found no code behind it. The folder's `.gitignore` is written
  when the folder is *created*, not when a scan succeeds — an interrupted run
  (routine since task 16.2) would otherwise leave a folder git can see.
- **One scan per Workspace at a time**, enforced by `flock` on `.security-scan/.lock`.
  Concurrent scans do not corrupt anything, but both read the same `state.json` and
  the last to finish wins — so the next run's new/fixed/regressed diff is computed
  against a view that never happened. The database cache is locked too: readers
  share, `valvur update` excludes.
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
- **Clean is explicit, and never claimed when it cannot be supported.** Three
  statuses, not two: `findings`, `clean`, and **`inconclusive`** — nothing live was
  found, and either the vulnerability database was too old for that to be evidence or
  an ecosystem present in the workspace was never inspected. An agent can tell all
  three from "never ran". Warning in `SUMMARY.md` alone is not enough: the contract
  tells agents to read it *bounded* and query `findings.json` for detail, so the
  consumer most likely to act on the verdict is the one least likely to see a caveat
  explaining it means nothing. The verdict itself has to carry the claim — and since
  22.D.4 so does **`status_reason`**: one line in `run.json` and `findings.json`,
  the same words in `SUMMARY.md` and the MCP `scan_status` reply, naming every cause
  (three exist: database age, index age, an ecosystem never inspected). No consumer
  reconstructs it from `database.stale` and `findings.not_covered` any more.
- **The verdict is about the code, not about valvur.** Only **active** findings —
  unsuppressed, and excluding valvur's own coverage notes — make a status `findings`.
  A suppressed finding is a decision this project already recorded; a coverage note is
  our missing feature. Counting either as a problem in the user's code makes a release
  gate go red for something they did not do and cannot fix, and a gate nobody can turn
  green is a gate that gets deleted. All three counts appear on every surface: the
  terminal, `run.json`, `SUMMARY.md` and the MCP `scan_status` response. **Coverage
  notes are two kinds since 23.5.5**: a *gap* (`coverage.DOUBT_RULES` — nothing reads
  the ecosystem, no lockfile) makes a nil result `inconclusive`; a *licence statement*
  (`coverage.LICENCE_STATEMENT_RULES` — dependency licences absent from a lockfile,
  a `LICENSE` no signature matches) is listed, counted as `not covered`, and casts
  no doubt, because a licence we could not read is not a vulnerability we did not
  look for. Neither kind is ever a `REMEDIATION.md` action — nothing in the user's
  code resolves a statement about valvur.
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
