# Changelog

All notable changes to valvur are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the 0.x caveat that
a minor bump may break things until 1.0.

## [Unreleased]

- **A budget cut is its own message, and a failure says its cause.** At the
  first usability gate the 300 s default budget cut every Scanner and the
  reply read *every scanner failed — run doctor*, and `doctor` said *ready*.
  Now that refusal says what ran and for how long, what never started, and the
  three levers — `[scan] exclude`, `budget_s` (`--budget`), `VALVUR_JOBS`
  (`--jobs`) — and `scan_status` names `doctor` only when a precondition could
  be the cause; `SUMMARY.md` puts the same levers beside a partial cut. Each
  failed Scanner's record now says the cause valvur knows: cut by the budget,
  timed out and stopped, or *killed by the runtime — the container's memory
  ceiling (2g) or the VM's* for an exit 137 valvur did not send — with the
  command line in `run.json` and out of the sentence. The README's first-run
  section names the levers (29.0.3).
- **A Scanner past its timeout is stopped, not abandoned.** The per-Scanner
  timeout killed the `docker run` client and left the container to the daemon:
  at the first usability gate a Gitleaks container ran 401 s past its 300 s
  timeout and a Checkov one was still at 92 % CPU 90 s after the server had
  exited. Now the container is stopped by name and waited for, and the record
  says *timed out after Ns and was stopped* with the last of its stderr — not
  the 1,500-character command line `str(TimeoutExpired)` used to leave there.
  `valvur scan` stops its fleet on SIGTERM as well as Ctrl-C, so a cancelled CI
  job leaves nothing running (29.0.2).
- **Excludes are skipped, not filtered.** The built-in list of vendored and
  generated directories and a project's `[scan] exclude` used to be applied to
  findings after every Scanner had walked the whole tree: at the first
  usability gate, on a 107,544-file working tree, Gitleaks spent 212 s
  producing 3,892 hits inside an excluded archive that were then dropped, and
  Checkov never finished. Now every Scanner is told what to skip before it
  reads — Trivy, Checkov, Syft, Opengrep and OSV-Scanner by their own flags,
  Gitleaks by a generated config beside its report, valvur's Checks by a
  pruned walk — each form measured inside the image. The finding filters stay,
  so a Scanner that ignored its flag could not leak an excluded path, and
  `SUMMARY.md` says the paths were excluded before the scan. Measured on the
  gate's tree with its two-line exclude: **complete in 88 s** on the same
  Mac, nothing dropped, Gitleaks 6 s against 212 s and the three Checks 8 s
  against 403 s. And an opt-in: `[scan] honour_gitignore = true` skips the
  directories `.gitignore` hides as well — except that `.env*` files and agent
  instruction files are always read, and a hidden directory holding one is
  scanned whole; `[scan] include` keeps a hidden path. Off unless asked, because
  a gitignored `.env` holds exactly what a scan is for; `run.json` and
  `SUMMARY.md` say what it hid (29.0.1).

## [0.4.0] — 2026-09-26

Three reviews of the `0.3.0` tree, six days, and every finding measured against
the tree before it became a task. The second review found what a release could
do wrong — a Scanner's unreadable report took the whole run down, a cancel could
be confirmed and dropped, the Results Folder could hold a mixed generation, and
PyPI was published before the artifact was validated — and all four are closed:
the release is now stage → validate → promote, and this tag is the first to take
that path for real. The third found the edges of the record: the daily index
tagged before it was verified, the release SBOM by a floating syft, an MCP server
that left its scans running, `readOnlyHint` on `scan`. The fourth found that
write access was release authority and that Checkov was the wall clock: the
signing identity is now one workflow and one ref, a `v*` tag needs a key in
`allowed_signers`, every container has a memory and PID ceiling, and Checkov
starts in a third of the time — **6–9 s against 16–19 s** for a scan of every
application repository in the corpus. Also here: the MCP handshake carries the
rules and the readers answer structured content, the image is reproducible,
Python 3.11 and 3.13 are tested, `NOTICE`, `valvur cache --prune`, `valvur
doctor --bundle`, `argv` in `run.json`. Fifty-one tasks between `v0.3.0` and
this tag; the entries below are the thirty-three a user can see.

- **An unknown profile is refused at the door.** `--profile bogus`, or a `scan`
  call naming one, was passed along as a string and failed three calls later
  with a `KeyError`; it is refused where it arrives, naming the two that exist.
  The retired names still resolve. Underneath, Profile, severity and finding
  status are typed (28.4.1); every artifact is byte-identical.
- **The image is reproducible.** Two builds of one commit are one image: the
  commit's timestamp on every file in every layer (`SOURCE_DATE_EPOCH`,
  `rewrite-timestamp`), and bytecode compiled in hash mode with a fixed seed.
  Anyone can rebuild the tree a release names and compare digests, rather than
  trust the signing identity alone; CI builds twice without cache on every
  change and fails unless the two are one (28.4.5).
- **Supportable.** `run.json` records each Scanner's command line (`argv`)
  beside its version and duration, so the raw output has its provenance;
  `VALVUR_DEBUG=1` echoes every container command to stderr as it runs; and
  `valvur doctor --bundle` writes the tarball to attach to an issue — the doctor
  report, the versions of everything involved, the last scan's `run.json` — and
  never source, raw output or findings, which a test holds it to (28.3.6).
- **`valvur cache --prune`.** Each shim version pulls its own image tag and
  nothing removed the one before; `valvur cache` could inventory and not clean.
  `--prune` removes the published image's local tags that are not this shim's
  version and index files the index's metadata no longer names, listing each
  first — never the database, never this shim's image, never any other
  repository's images — and `valvur doctor` names what is superseded (28.3.7).
- **The code-scanning upload leaves accepted risks out** (`valvur-action`
  v0.2). GitHub does not read SARIF `suppressions` — measured: five suppressed
  results uploaded on every push for thirteen days, five open alerts, none ever
  dismissed — so a risk `.security-scan.toml` had recorded a decision about sat
  in the Security tab as an open alert for as long as the decision stood. The
  action now uploads `results.sarif` without its suppressed results; the file on
  disk keeps every one of them (28.3.3).
- **`NOTICE`.** The attribution the redistributed tools' licences ask for, at the
  root and at `/usr/share/doc/valvur/NOTICE` in the image: each Scanner with its
  licence and upstream, the base, the bundled data (28.3.5).
- **Tested on Python 3.11 and 3.13** as well as 3.12, which is what
  `requires-python = ">=3.11"` had claimed without evidence (28.3.4).
- **The MCP handshake carries the rules, and the two readers answer structured
  content.** `initialize` now returns `instructions` — the five rules `SUMMARY.md`
  opens with, from the same constant — so an agent has them before its first call
  rather than only if a human pasted the README's snippet into `CLAUDE.md`.
  `scan_status` and `list_findings` declare an `outputSchema` and answer
  `structuredContent` beside their text: the verdict, the counts, the Scanners
  and the next moves as fields, each shown Finding as an object, neutralised like
  the text. The text is unchanged; both snapshots are committed (28.2.2).
- **Checkov starts in a third of the time.** Most of its fixed startup — the
  scan's wall clock on every repository with a workflow file, which is all of
  them — was the image's doing, not Checkov's: its update checker asked PyPI at
  every start, because the variable set to stop it was one Checkov never reads,
  and waited five seconds for DNS to fail with no network; and every start
  compiled its 3,900 modules from source, because the image deleted the bytecode.
  The check is off by the variable Checkov reads and the bytecode is in the image
  (22 MB more to pull, once): 10.2–10.7 s → 3.0–3.3 s on a workflow-only tree,
  measured as the runner runs it (28.2.1).
- **The three refactors, reviewed.** An adversarial pass over the moves that
  produced `summary.py`, the typed pipeline result and the ecosystem registry —
  twenty-one findings, each measured — and what the goldens could not see, fixed:
  the verdict's staleness doubts now use the same two predicates `run.json`'s
  `stale` flags use rather than a copy; `run.json` is rendered by `provenance`,
  not by the writer; the KEV / ransomware / EPSS badge is one decision for
  `SUMMARY.md` and the CLI/MCP reply, which had drifted; the pipeline's result is
  its own copy rather than a view of the mutable bag the stages write to; a
  Workspace's own packages are named by the ecosystem entry (`defines`) rather
  than by a second table an added ecosystem would have missed — and been reported
  as hallucinating its own code for. The summary goldens are now rendered at real
  ranks. No document a user reads changed (28.1.1).
- **A first run's fetches are in the record.** A first scan pulls the image, the
  vulnerability database and the name index before any Scanner runs; that was
  announced live and absent from `run.json`, which said `network.used: false` and
  `what_left_the_machine: nothing` — true of the workspace, silent about the
  three hosts reached. `run.json` (`network.fetched`), `findings.json` and
  `SUMMARY.md` now list each fetch: what, from where, how large, how long, and
  whether the index's signature verified. Empty, not absent, when nothing was
  fetched (28.0.4).
- **The signature you are told to verify names one workflow and one ref.** The
  identity in every verify command was the repository alone, which a signature
  from any workflow on any branch satisfies. The image's is now the release
  workflow on a version tag and the index's the index workflow on `main`; the
  pipeline verifies its own image against its exact identity. A release tag must
  now be signed by a known key and sit on `main`, and only the repository's
  admins can create one (28.0.2).
- **Every Scanner's container has a ceiling.** Until now a container ran with a
  read-only root, no capabilities and no network — and could still take every
  byte of memory the host had: a pathological pattern for Opengrep, a
  multi-gigabyte lockfile for Trivy. Each is now launched under `--memory=2g`
  with no swap, a 512-PID limit and `no-new-privileges`; a container past the
  ceiling is killed and reported as a failed Scanner rather than the host
  swapping while the budget counts down. Rootless Podman on a cgroup v1 host
  cannot take a memory limit and keeps the other two; `doctor` says so
  (28.0.3, F3).
- **One place to add an ecosystem.** What valvur knows about Python, npm, Ruby,
  PHP, Rust, the JVM and Go was spread over three modules that had to be edited
  together — which files to read, which index answers existence, and a chain of
  per-ecosystem branches for the registry's name and the name form. It is one
  registry entry each now, with the parsers beside it (the URL each registry
  answers at, and how it dates a first publication, stay in the Check as the
  transport they are); the dependency-reality
  Check is 1,206 lines lighter by half and no longer imports the index module
  that imported it back. No behaviour changed, and five goldens taken before the
  move say so (27.3.2).
- **A scheduled workflow's failure is a tracked thing.** The daily name-index
  build and the weekly corpus run are the work nobody is watching, and GitHub
  mails their failures to one person and does nothing else. Each now opens an
  issue — reusing the open one, so a week of failures is one problem — with the
  run link, what the failure costs a user, and the recovery (27.2.7).
- **The source distribution ships an allowlist.** `0.3.0`'s sdist carried six
  files of an external review's output, and a one-file `valvur/` directory holding
  the wheel's generated build hash — both because the packaging config named what
  to *exclude* and nothing named what the archive should contain. The review's
  artefacts moved under `docs/`, the build hook runs for the wheel only, and a
  test now holds the sdist's top level to a list in both directions: something new
  at the root fails, and so does something missing (27.2.3).
- **The MCP tool annotations say what each tool does.** All six declared
  `readOnlyHint: true`, `scan` included — which writes the Results Folder, pulls an
  image and starts containers, while `scan_cancel` kills them. MCP's hint means
  "does not modify its environment", which is a narrower claim than valvur's: your
  *source* is untouched either way. The four readers still declare `true`; `scan`
  and `scan_cancel` declare `false`, so a client that asks before running them is
  right to. Nothing valvur exposes is destructive, and a test over the registry
  says so (27.1.2, F9.2).
- **An index pulled without cosign is verified once cosign is installed.**
  `valvur update` skips everything when the index on disk is already the published
  build — and that skip happened before the signature was looked at, so an index
  first pulled on a machine without cosign kept *"not verified: cosign is not
  installed"* until a newer index was published: a trust state the user could not
  improve by installing the tool the message named. The next `update` now verifies
  the recorded digest and keeps the new verdict, fetching nothing (27.1.3).
- **The MCP server stops the scans it started.** When the client went away —
  stdin closed, Ctrl-C, a broken pipe, or a SIGTERM — the server returned and its
  scan jobs died with it, but the containers those jobs had launched belong to the
  container runtime and kept running with nobody to read their result. Now every
  way out cancels each active scan the way `scan_cancel` does, waits briefly for it
  to settle and sweeps up anything left; measured over stdio against a real image,
  the containers are gone 0.3s after the client disconnects, where before they ran
  to completion (27.1.1, F1.11).
- **The daily name index is tagged only after it is verified.** `index.yml` used
  to write the day's tag and `latest` first and verify afterwards, so a build
  that failed its own round trip had already moved `latest`. Now the index is
  pushed under a `candidate` tag, signed, pulled back through the shim's own
  client — which must resolve the very digest that was pushed — and only then
  tagged with the date and `latest`; a red run leaves `latest` where it was.
  Nothing is pushed, signed or tagged from a branch. The order the release
  pipeline adopted in 26.1.1 (ADR-0020), applied to the index (27.0.1).
- **The release SBOM is one per architecture, made by the pinned syft.** The
  image ships for amd64 and arm64 and its published SBOM described amd64 only,
  generated by a syft named by tag — the one floating pointer in a pipeline
  where every action is a SHA and every base image a digest. Now the release
  attaches four files (CycloneDX and SPDX for each architecture), each checked
  to describe the child it names, generated by the syft the Dockerfile pins by
  digest, read from the Dockerfile so there is one pin (27.0.2, F10.4).
- **The generation id is on every surface.** `SUMMARY.md`'s machine block,
  `scan_status`'s DONE line and `valvur gate`'s count line name the run's
  `generation`, so an agent that reads the summary and then `findings.json` can
  tell they are the same run (26.4.2). Over MCP a job's state is an enum with a
  fixed transition table; the words it prints are unchanged (26.4.1).
- **The shim/image protocol is written down and versioned (F1.9).**
  `docs/PROTOCOL.md` is the contract — paths, binaries, the Checks' entry point,
  labels, the process — and the image carries it as one label,
  `org.valvur.protocol`. Compatibility is now decided by that label: a shim and
  an image that speak the same protocol run together whatever their versions
  say (a different tree is still reported, never refused), and a different
  protocol is the one thing refused, with both sides named. Images from `0.3.0`
  and earlier carry no label and are judged by the version rule as before
  (26.3.1).
- **A Check that fails inside the Checks' batch is a failed Check (F2.5).** Since
  the three Checks began sharing one container (0.3.0), a Check that raised
  inside it was recorded ok with zero findings and its error dropped — the batch
  handed the fleet an empty report with a non-zero exit, which is what a Scanner
  that found nothing looks like. Now it is a failure with the Check's own error
  as the reason, at the top of `SUMMARY.md` like any other. Found by 26.2.1.
- **Gitleaks runs in the same container as every other Scanner.** Its container
  had been built from its own flag list — no scratch tmpfs, no cache mounts and,
  on an SELinux-enforcing host, no label on its results mount. Unified (26.2.1).
- **The release pipeline runs the arm64 image, and verifies the provenance it
  makes.** The artifact job and CI's published-image job each run on both
  architectures natively; the pipeline verifies the image's signature and its
  SLSA provenance on each, and each distribution's attestation read back from
  PyPI after upload. The private-repository branches both workflows carried
  since before 2026-09-13 are gone (26.1.2, 26.1.3).
- **A release is validated before it is promoted.** `release.yml` now runs
  stage → validate → promote: the image is pushed under a candidate tag, signed
  and attested; the wheel and that digest are tested together; and only then is
  the digest re-tagged as the version and `latest`, the wheel uploaded to PyPI and
  the GitHub release created. Until now PyPI and `latest` moved first and the
  validation could only turn the run red afterwards. A failed validation leaves a
  candidate tag and nothing a user can install; the version number is not burned.
  Rehearsed end to end (26.1.1).
- **The Results Folder is one generation (F7.4).** Every document is written
  whole beside its name and renamed into place in one loop, `run.json` last, so
  a file is never partial; `findings.json`, `run.json`, `state.json` and
  `results.sarif` (as `automationDetails.guid`) carry one `generation` per scan,
  so files from two runs side by side are detectable rather than silent; and an
  `sbom.cdx.json` from a previous run no longer survives a run in which Syft did
  not produce one. Additive to `findings.json`'s schema 1 (26.0.3).
- **`scan_cancel` cannot be confirmed and dropped (F1.11).** Two races over MCP:
  a cancel that landed before the job's runner existed was acknowledged and then
  ignored — the scan ran to completion and reported DONE — and a second `scan`
  while the first was still stopping replaced it, so its CANCELLED was never
  reported. Now the cancel is honoured the moment the runner exists, a `scan`
  during `cancelling` is refused with *"still stopping — poll `scan_status`"*,
  and a cancel during a first run's fetches stops before the next fetch rather
  than after all of them. The reply says *"no container had started; the scan
  stops at its next step"* when that is what happened (26.0.2).
- **A report the adapter cannot read is one failed Scanner (F2.5).** A Scanner
  that exited 0 with a truncated or reshaped report — a container killed
  mid-write, a format change — raised out of the whole run: over MCP a FAILED job,
  on the CLI a traceback, the other Scanners' results thrown away, nothing
  written. Now that Scanner is recorded *report unreadable: <exception>*, named
  at the top of `SUMMARY.md` and on the MCP DONE line, its raw text kept under
  `raw/`, and the run continues incomplete like any other failure. Found by the
  second external review (26.0.1).
- **`0.1.0rc1` is yanked on PyPI** (2026-09-20), with the reason *"looks for a
  local development image; use 0.3.0"*. It was the release whose shim looked for a
  local `valvur:dev` image and could never have worked for anyone (22.G.1, fixed
  in `0.2.0`); a resolver no longer chooses it, and anyone pinning it exactly sees
  the reason.
- **`MaverickHQ/valvur-action` is tagged.** `v0.1`, and `v0` following it, on
  2026-09-20 — on a commit whose own self-test installs the `version` default,
  `0.3.0`, from PyPI, so the README's `uses: MaverickHQ/valvur-action@v0` resolves
  to something proven. This repository's self-scan pins the tagged commit by SHA
  and keeps `version: ""`, the shim from the tree under test.
- **Every workflow names its runner image.** `ubuntu-24.04`, not `ubuntu-latest`,
  which GitHub moves to 26.04 over a month from 2026-10-19: the runner was the one
  input under the build still floating while every action is a SHA and every base
  image a digest, and N1.1's and N1.4's numbers name it as the machine class they
  were measured on. A test refuses a floating label; the move to 26.04 is a diff
  that re-measures them. The action's own self-test runs on both images.

## [0.3.0] — 2026-09-20

What a stranger's first ten minutes meet, fixed before a stranger measures them.
An audit of the requirements against `0.2.0` the morning it shipped (Phase 24)
found the primary path's first `scan` finishing incomplete; this release makes a
first `scan` fetch what is absent and say so, adds `valvur doctor`, a scan budget,
`scan_cancel`, `valvur gate`, per-Scanner timing, a hash-locked Checkov in its own
venv, one bake file with native arm64 builds, a shim that carries the tree hash it
was built beside, the AI Artifact Check over the primary client's own files and
over hooks, and a release pipeline that tests the artifact rather than the tree.
Twenty-three tasks between `v0.2.0` and this tag, every one measured against a real
image, a real runner or the public corpus — which grew to thirteen repositories and
found two of the defects below on its own.

### Added

- **The AI Artifact Check reads the primary client's own files, and hooks.**
  `.kiro/steering/*.md`, `.kiro/settings/mcp.json` (`autoApprove`, mutable refs)
  and `.kiro/hooks/` join the list — a Kiro workspace was scanned by the Check that
  exists for it and could not have seen a poisoned steering file — with the clients
  the Check did not know: `.clinerules` (file or directory), `.roo/` (`alwaysAllow`
  in its `mcp.json`), `.continue/`, `.windsurf/`, `.roomodes`, `.aider.conf.yml`
  (`yes-always: true` is a permission bypass). And a new rule at high,
  `valvur.ai-artifact.hook-runs-command`: a committed hook that runs a shell command
  on an event — a Kiro hook of action type `command` (both hook formats), a Claude
  Code `type: command` handler in `.claude/settings.json`, aider's `lint-cmd` or
  `test-cmd` — makes every agent that opens the repository execute it unprompted,
  and is reported with the command as fenced evidence. `.kiro/specs/` is
  deliberately not read: the project's own documents, and this repository's own
  spec contains the phrase the injection rule matches (task 23.5.1; F3.6 amended).
- **OSV-Scanner 2.2.4 → 2.6.0**, by Dependabot's digest bump, completed: the
  version the shim reports, the golden fixture recaptured from the new image, and
  `--output-file` in place of the `--output` 2.6.0 deprecates. Two behaviour
  changes measured on the fixture and handled: 2.6.0 reads `package-lock.json`
  (2.2.4 reported nothing for it), and its findings land on Trivy's identities and
  merge; and it reports `requirements.txt` twice — the lockfile extractor's block
  and a second of `source.type: unknown` with PEP 440-normalised versions, `pyyaml
  5.1` beside `pyyaml 5.1.0` — so the adapter drops the `unknown` block where a
  typed one covers the same path, and keeps it where nothing else read the file.
  On smolagents' unpinned requirements 2.6.0 still evaluates the lower bounds: 97
  advisories dropped by 25.3, where 2.2.4's double read gave 193.
- **Unpinned requirements are not a check.** Found by the corpus on its thirteenth
  repository: a 39-line `requirements.txt` with no pins read as *checked* on
  `offline` — Trivy reads `==` lines and nothing else, and correctly reported
  nothing for a range — while on `full` OSV-Scanner evaluated every range at its
  lower bound and reported 193 advisories (110 after merging) against versions
  nothing installs. Now a requirements file counts only for its pinned lines: with
  no lockfile beside it, a file of ranges is the lockfile coverage note
  (`valvur.dependency.vulnerabilities-unchecked`, naming the file and how many of
  its lines are ranges; a mixed file is *partly* checked and says so) and the run
  is `inconclusive`; and OSV-Scanner's lower-bound advisories are dropped before
  merging, counted in `run.json` (`excluded_unpinned`) and `SUMMARY.md`, never shown
  as the project's. Options, comments, editable and direct references are neither
  pinned nor ranges (task 25.3).
- **The release pipeline tests the artifact, not the tree.** A final `artifact`
  job in `release.yml` installs the wheel from `dist/` into a clean environment
  with the source tree off the path — and proves it: `valvur._build` exists only
  in a built wheel — pulls the image by the digest the release job signed,
  verifies the signature, checks the pair's version label and build digest against
  each other, and runs the Phase 11 constraint suite, the whole e2e suite and the
  self-scan gate through that wheel and that image (task 12b.2, N2.5). The
  `verify` job still runs the same suite against the tree before anything is
  pushed; this is the other half, on what a user gets, rehearsed before every tag.
- **npm adoption on `full`: new AND unadopted is the slopsquat signal.** F3.3 asks
  for *first published recently and low adoption*; the adoption half was stated
  impossible because PyPI publishes no download counts without a third party. npm
  does — `api.npmjs.org/downloads/point/last-month/` is public and unauthenticated —
  so on `full` a name the registry has already dated under 90 days is asked for its
  last-month downloads (only those names; nothing new leaves the machine), and
  under 1,000 is reported at **high** with both numbers in the title; new but
  adopted at low; the API unreachable keeps the age-only finding at medium. PyPI,
  RubyGems, Packagist and crates.io stay age only and the evidence says why.
  `run.json`'s *what left the machine* now names api.npmjs.org — and, found on the
  way, RubyGems, Packagist and crates.io, which it had not named since their
  registries joined the age check in 23.2.2–3; `valvur doctor --network` probes
  api.npmjs.org with the rest (task 23.5.4).
- **The LLM-output-to-sink rules know six SDK families, and the corpus knows a
  repository that executes model output.** Sources for Anthropic, OpenAI (chat
  completions, the Responses API, the pre-1.0 module), Gemini, LangChain
  `invoke`/`predict`, litellm and ollama, anchored once for the three Python rules;
  sinks widened to the INFO inventory's (`yaml.load` without a safe loader,
  `pickle.loads`, `executemany`, `sqlalchemy.text`; `outerHTML`,
  `insertAdjacentHTML`, `document.write`). `valvur.llm.output-to-sql` is now a
  taint rule like the other three; the string-built-SQL pattern it used to be is the
  INFO inventory entry `valvur.python.string-built-sql`. The `innerHTML` rule had no
  fixture and had never fired anywhere; fifteen planted flows now fire across the
  fixture's `llm_app.py` and a new `chat.js`, and one planted shape — a helper that
  returns the model's text — is asserted *not* to fire, because Opengrep's taint
  tracking is intra-procedural. Measured on two real projects that execute model
  output, smolagents and pandas-ai: both route it across a class boundary, neither
  flow is reported, both `exec` sites are named by the inventory. smolagents joins
  the corpus as its thirteenth repository so that limit is measured weekly; the
  README says the inventory is what fires on real code (task 23.5.3).
- **The MCP `tools/list` reply is a committed snapshot.**
  `tests/fixtures/mcp/tools-list.json` is the JSON both clients see — every tool's
  name, description, input schema and read-only annotations — taken through the
  real server over stdio, and a test fails on any change until the file is
  regenerated deliberately (`UPDATE_MCP_SNAPSHOT=1`). The rc offered a `standard`
  Profile in that schema and nothing showed the rename until an agent chose it;
  now a schema change is a diff in review (task 23.5.2).
- **`valvur doctor`, and a `doctor` MCP tool.** Every precondition a first run has
  failed on for real, checked before a scan and named with the fix: the interpreter
  can verify TLS (python.org's macOS build has no CA bundle until its certificate
  script runs — 0 trusted roots, and every host-side fetch fails); the container
  runtime is found *and running* (a stopped daemon looks like a missing image to
  `image inspect`); the image is present, its version matches the shim's (F1.9), and
  a container of it actually starts; the vulnerability database and the name index
  are present and current, with each ecosystem's count; the SELinux label on the
  tree on an enforcing host; which Claude Code or Kiro configuration names the
  server, and whether it is disabled. One line per check, exit 1 if any would fail a
  scan. `--network` (or `network: true`) adds one bounded TCP connect per host a
  first run and `full` need, honouring every mirror setting; without it doctor opens
  no socket. A `scan_status` that reports FAILED now points at it.

- **How long each Scanner took.** `duration_s` on every entry of `run.json`'s
  `scanners`, on each line of `scan_status` (and on its "Completed so far" progress
  while a scan runs), and one line in `SUMMARY.md`: *"slowest: checkov 40.9s"*. The
  fleet runs concurrently, so the slowest Scanner is roughly what a scan costs. The
  corpus report gains `scan_s` and per-Scanner timings.

- **The shim carries the tree hash it was built beside.** A build hook writes
  `valvur/_build.py` into the wheel — the same digest over the same inputs the
  image records in `/etc/valvur/inputs.sha256` — and a scan compares the two,
  reading the image's once per image id. Different trees behind the same version
  (the hole `0.1.0rc1` fell through, which F1.9's version label cannot see) is now
  a warning in `run.json` (`build: {shim, image, match}`), `SUMMARY.md`,
  `scan_status` and `doctor`'s image line — never a refusal.
- **One bake file; each architecture built natively.** `docker-bake.hcl` is the
  one place the image build lives — `dev` for a local or CI image, `release` for a
  manifest pushed by digest — and `CONTRIBUTING.md`, `ci.yml`, `corpus.yml` and
  `release.yml` all build through it. The release builds amd64 and arm64 on their
  own native runners side by side and merges them into one index with
  `imagetools create`; QEMU is gone from the release.
- **Checkov 3.2.517 → 3.3.17**, through the lock: `requirements-checkov.in` moved,
  `scripts/lock-checkov.sh` regenerated the lock with the asteval override intact
  (Dependabot's own regeneration had dropped it, restoring the vulnerable pin —
  the self-scan gate refused that PR). Same 13 findings on the fixture. 3.3.17
  pulls in python-ecdsa, whose Minerva timing advisory (CVE-2024-23342) has no fix
  and none coming; accepted in `.security-scan.toml` with the reason and a
  one-year expiry, since Checkov never signs anything in a scan. ruff 0.16.7.
- **The three Checks run in one container.** `python -m valvur.checks batch` runs
  licence-file, ai-artifact and dependency-reality in one container start instead
  of three — nine container starts a scan became seven — with three ScannerRuns,
  three coverage contracts and each Check's findings and failures its own, as
  before. The batch carries the Profile's network grant (dependency-reality's on
  `full`, none on `offline`) and runs that Check last. Measured on the fixture on
  a loaded Mac: about four seconds off every scan.
- **Checkov hash-locked, in its own virtual environment.** `requirements-checkov.txt`
  pins Checkov and every one of its 96 transitive packages by version and sha256,
  and the image installs from it with `--require-hashes` into `/opt/checkov`, which
  shares nothing with valvur's interpreter — the system site-packages went from 96
  packages and 191MB to valvur alone. Regenerate with `scripts/lock-checkov.sh`;
  Dependabot watches the lock. The image is the same 576MB. Found on the way: the
  Dockerfile's `… && find … || true` let a failed `pip install` produce an image
  without Checkov and report success; scoped, and a test refuses the shape. And
  found by the lock's first self-scan: Checkov pins `asteval==1.0.6`, which has
  two sandbox-escape advisories fixed in 1.0.9 — the lock overrides it to 1.0.10
  (`requirements-checkov.overrides`, with the reason), so the image ships a
  Checkov that upstream's own users do not get.
- **`MaverickHQ/valvur-action`.** A composite GitHub Action: install the shim (a
  PyPI pin, a git source, or the `valvur` on PATH), install cosign so the name
  index's signature is verified, restore the index from the Actions cache, `valvur
  update`, `valvur scan`, read `run.json` into outputs, upload `results.sarif` to
  code scanning, `valvur gate`. One `uses:` line for CI adoption; this repository's
  own self-scan job uses it on every commit, with the shim from the tree under test.
- **A scan budget.** Over MCP a scan has a 300-second budget unless the client
  passes `budget_s` (0 for none); on the CLI none unless `--budget SECONDS`. Past
  it no new Scanner starts, the running ones are stopped, and the result is
  written incomplete with each cut Scanner named — *"cut by the 300s budget after
  300s"* / *"not started: the 300s budget was spent before its turn"* — in
  `run.json` (`budget: {seconds, cut}`), `SUMMARY.md`, `scan_status` and the gate.
  A cut is not a cancel: the Scanners that finished are a result.
- **`scan_cancel`, and `--jobs`.** A `scan_cancel` MCP tool stops a running scan
  the way Ctrl-C does on the command line (F1.11): its containers are killed — one
  `kill` for all of them, 2.7s for eight, measured — nothing is written, the
  previous results stand, and `scan_status` reads CANCELLING then CANCELLED rather
  than FAILED. A cancel stops that workspace's fleet, not another's. `valvur scan
  --jobs N` bounds how many Scanners run at once, honoured by the fleet's executor;
  `VALVUR_JOBS` sets the same default for the MCP server, for a Docker Desktop whose
  memory cannot start eight containers together.
- **`valvur gate` and `valvur cache`.** `gate [path] [--fail-on SEVERITY|any]
  [--no-inconclusive]` reads the last scan's `run.json` and `findings.json` and
  exits 1 if the result should not ship: an incomplete run, a lapsed suppression
  (at every threshold), an active finding at or above the threshold (default
  `high`; suppressed findings and coverage notes are never counted), or — asked for
  — an `inconclusive` scan. Exit 2 when there are no results. Under GitHub Actions
  each reason is a `::error::` annotation. It replaces the Python heredoc that
  `ci.yml` and `release.yml` each carried a copy of; the self-scan gate is now
  `valvur gate . --fail-on any --no-inconclusive`. `cache` lists the database, the
  index (with each ecosystem's count) and the KEV copy with size and age;
  `--clear` removes them under the exclusive cache lock, never the directory or
  the lock file.
- **`scan_status` names the next two moves.** After a scan with active findings:
  `explain_finding <fingerprint>` for the top-ranked one, with its location and
  title, and `REMEDIATION.md`'s first action (`action 1 of N: …`). An agent's
  first scan (22.G.1) never called `explain_finding` because nothing pointed at it.

### Changed

- **A licence valvur could not read is a coverage note, and casts no doubt.**
  `valvur.licence.dependencies-unreadable`, `dependency-unknown` and `unidentified`
  were active, low Findings, so a project with nothing wrong in it read `findings`
  — eight of the twelve corpus repositories carried one, and awesome-cursorrules
  read `findings` on a `LICENSE` valvur has no signature for and nothing else. They
  now join the coverage notes: never active, never seen by `valvur gate` at any
  threshold, counted as `not covered`, listed in `SUMMARY.md` under *What valvur
  could not read* — and, unlike the existence and lockfile gaps, they do not make a
  nil result `inconclusive`: a licence we could not read is not a vulnerability we
  did not look for. A missing licence file, a contradiction between `LICENSE` and
  the package metadata, and a copyleft dependency in a permissive project are facts
  about the project and stay Findings (task 23.5.5; F4.6 annotated).
- **`REMEDIATION.md` proposes actions for Findings, never for coverage notes.**
  Every note went through the action grouper, and the lockfile gap — *"npm
  dependencies were not checked for known vulnerabilities"* — came out as **"Remove
  the hallucinated dependencies"** on every repository without a lockfile, and from
  there into `scan_status`'s *"REMEDIATION.md, action 1 of N"*. Notes are now counted
  aside in one line and left to `SUMMARY.md`.
- **One upgrade target per action, the minimal one.** Trivy reports a fix per
  release line, comma-joined — `"2.2.2, 1.0.2"` for json5 1.0.1 — and the adapter
  copied the string, so the proposal read *"so `json5` reaches 2.2.2, 2.2.2,
  1.0.2"*. The adapter now takes the smallest fix above the installed version, as
  OSV's already did; and a root upgrade names what *each* transitive package must
  reach — *"Upgrade `webpack` so `json5` reaches 1.0.2 and `loader-utils` reaches
  1.4.2"* — where it used to write the highest fix in the group after whichever
  package the first finding named.
- **The README lists the four LLM-output-to-sink rules as what they are** —
  three taint rules whose only sources are the OpenAI, Anthropic and Gemini SDK
  calls, and one string-built-SQL pattern, none of which has fired on twelve real
  repositories including an LLM tool — rather than as a feature (task 24.2; F3.10
  annotated; `POSITIONING.md` records the measured limit).
- **The README says what OSV-Scanner adds, measured.** On twelve real repositories
  `full` added 121 Go standard-library advisories on the one Go project (keyed on
  `go.mod`'s `go` directive, which Trivy reports only from binaries), one disputed
  Python advisory, and nothing on the other ten. It stays on `full`, with that
  number beside it; `scripts/corpus.py compare` repeats the measurement from any
  two corpus reports, and the weekly corpus run uploads it.
- **A failure reason on `scan_status` is never cut mid-sentence.** It was cut at
  80 characters — *"…no package-name index for PyPI, so"* — which was the one
  sentence the agent needed whole. Now every line of the reason is shown, indented
  under the Scanner's name, and only the number of lines is bounded (six, then
  "… N more line(s) in run.json").
- **A first `scan` fetches what is absent, and says so.** Measured against `0.2.0`
  over MCP with an empty cache, the first `scan` finished `complete: False` — Trivy
  and the dependency-reality Check both failed, each naming `valvur update`, which
  an agent cannot run. Now a scan that finds the vulnerability database or the
  package-name index *absent* fetches it first — the way it already pulled an absent
  image — and reports it on `scan_status` (*"Now: fetching the vulnerability
  database (119MB) — the first run only"*) and on the terminal. Measured from an
  empty machine: **110s** to a complete result, one tool call. A *stale* database
  or index is still never refreshed by a scan; the warning stands and you decide.
  `valvur update` is unchanged and remains the way to refresh. A fetch that fails
  costs only the Scanner that needed it, and that Scanner's failure says what went
  wrong; a scan never starts the seven-minute registry walk `valvur update` falls
  back to. A refused index signature still stops the scan.

## [0.2.0] — 2026-09-13

The first release anyone can install: the repository and both GHCR packages are
public, the image is published for `linux/amd64` and `linux/arm64`, and the shim
pulls the published image rather than a local development tag. Everything below was
on `main` between the release candidate and this tag.

### Changed — BREAKING

- **A scan can now report `inconclusive`.** Previously `status` was `findings` or
  `clean`; there is now a third value, for a scan that found nothing against a
  vulnerability database too old for that to be evidence. Anything parsing `status`
  and treating "not `findings`" as "safe" needs updating. What was *found* is real
  however old the data — only absence needs current data to mean anything.

  Keep the database current cheaply; the check costs one file read when it is:

  ```bash
  valvur update --if-stale
  ```

- **`Ctrl-C` now stops a scan.** It previously left the scanner containers running to
  completion, because the container runtime's daemon owns their lifecycle. An
  interrupted scan writes no results and is not reported as a failure.

- **One scan per project at a time.** A second concurrent scan of the same directory
  is refused with a message rather than silently spoiling the first run's status diff.

- **The image is published for `linux/amd64` as well as `linux/arm64`.** `0.1.0rc1`
  was arm64 only — unusable on most CI, most Linux desktops and every Intel Mac.

- **Two profiles, `offline` and `full`, replacing `quick`/`standard`/`deep`**
  ([ADR-0016](docs/adr/0016-two-profiles-split-on-the-network-boundary.md)). The old
  set was split along *speed* while being described as a network boundary, and `deep`
  was byte-identical to `standard` — it promised more and delivered exactly
  `standard`.

  **The retired names still resolve, so existing configuration keeps working:**

  | old | new | |
  |---|---|---|
  | `quick` | `offline` | now also runs Checkov and Syft, which need no network |
  | `standard` | `full` | |
  | `deep` | `full` | it was never different |

  `offline` is now the **default**. The target market cannot send code or dependency
  manifests anywhere, and the dependency-reality check does transmit package names,
  so reaching the network is something you opt into rather than acquire by typing
  `valvur scan`.

- **`offline` now finds what `full` finds.** Trivy excludes development dependencies
  by default; valvur did not pass `--include-dev-deps`. Measured on a real project,
  `offline` reported 0 CVEs where `full` found 24 — the same 24, in the same
  lockfile, one flag apart. Build and test tooling runs on developer machines and in
  CI, which is precisely the supply-chain surface this tool exists to cover.

### Added

- **The package-name index is published, and `valvur update` pulls it.** Every name
  on PyPI, npm, RubyGems, Packagist and crates.io, built once a day by a workflow in
  this repository and pushed to `ghcr.io/maverickhq/valvur-index` as a cosign-signed
  OCI artifact — 34MB, seconds, instead of every machine walking the registries for
  eight minutes. The signature is verified when `cosign` is installed and its state is
  recorded; a refused signature stops the update. The walk remains as the fallback and
  as `valvur update --build-index`. `VALVUR_INDEX_REPOSITORY` and
  `VALVUR_INDEX_INSECURE` mirror it the way the database is mirrored
  ([ADR-0018](docs/adr/0018-offline-package-name-index.md), amended).
- **Ruby, PHP and Rust dependencies are checked for existence, offline.** `Gemfile`
  and `*.gemspec` against RubyGems (case-sensitive, as the registry is),
  `composer.json` against Packagist, `Cargo.toml` — every dependency table, workspace
  members and `package =` renames included — against crates.io, whose list is
  streamed out of its database dump. On `full` each also gets first-publish age.
  Five ecosystems offline; JVM and Go stay `full`-only.
- **`valvur update` pulls the image, and a scan that has to pull it says so.**
  The image was fetched silently by the runtime on the first *scan* — measured
  through Kiro, where the first tool call looked hung for as long as the pull took.
  Now `update` pulls it first, streaming the runtime's progress; a scan that finds it
  missing pulls it and reports *"pulling ghcr.io/…:0.2.0 (240MB) — the first run
  only"* on `scan_status` and on the CLI, with the size read from the registry's
  manifest when it states one. A failed pull is a named failure with the runtime's
  words and the command that fetches it by hand.
- **Checkov runs only where there is infrastructure to analyse.** It costs about ten
  seconds of fixed startup whatever it finds, so a repository with no Dockerfile,
  terraform, Kubernetes manifests, CI workflows or templates went from ~18s to ~7s.
  Detection is biased towards scanning when unsure, and the skip is reported in
  `SUMMARY.md` and `run.json` — a scanner that did not run must never look like one
  that ran and found nothing.
- **`[scan] exclude` in `.security-scan.toml`** — repo-relative paths a project has
  chosen not to scan, for deliberately vulnerable test fixtures and the like. Never a
  default: the count of excluded findings and the paths responsible both appear in
  the output.
- **`scripts/verify-offline.py`** — checks both halves of the non-exfiltration claim,
  the containers and the host shim, and reports what it cannot prove as well as what
  it can.
- **`run.json` now records** the profile, the scanners it did not run and why, the
  scanners skipped for having nothing to analyse, and what any exclusion cost.

### Fixed

- **`0.1.0rc1` could not find its own image.** The published shim had the image name
  hard-coded as `valvur:dev` — a local development tag nobody else has — and never
  pulled the published `ghcr.io/maverickhq/valvur:0.1.0rc1`. A fresh install's first
  scan failed with "image not found". Found on 2026-09-12 by running the rc through
  Kiro on a machine that happened to have a `valvur:dev`: it used that, months newer
  than the shim, and the version check passed because both said `0.1.0rc1`. The tag
  is now derived from the shim's version (task 12a.2), and the image records what it
  was built from so a mismatch is caught (22.C.1).

- **`scan_status` no longer returns instantly.** It waits up to fifteen seconds for
  the scan to settle before answering, because an agent polls exactly as fast as the
  tool lets it: Claude Code polled fourteen times, and Kiro ten — **two thirds of
  what a scan cost in model credits was polling**, measured against the rc.

- **Dependency findings now say what to upgrade to.** `fixed_version` was declared
  and never populated, so the remediation proposal restated that a vulnerability
  existed without saying what to do about it. It now names the *minimal* upgrade —
  OSV publishes a fix per release line, so `brace-expansion 1.1.15` carries fixes
  1.1.16, 2.1.2 *and* 5.0.7, and taking the first would advise a major-version jump
  where a patch exists.
- **Remediation no longer proposes a downgrade.** Distinct major lines of one package
  were merged into a single action, telling a 5.0.7 install to "upgrade to 1.1.18";
  and within a group the version named was whichever finding was grouped first rather
  than the one that clears them all. Case variants (`Pillow` vs `pillow`) were also
  proposed as two separate upgrades, the second undoing the first.
- **The same CVE from two scanners is now one finding.** Trivy reports the lockfile
  *format* (`pnpm`) where OSV reports the ecosystem (`npm`), so identical
  vulnerabilities never merged.
- **A missing report is a failure, not a clean result.** "No package sources found"
  — which OSV-Scanner emits for a project with a `pyproject.toml` and no lockfile —
  was treated as a crash, marking the whole run incomplete.
- **Dotfile paths keep their leading dot.** `lstrip("./")` takes a character set
  rather than a prefix, so `/.github/workflows/ci.yml` was reported as
  `github/workflows/ci.yml` — a path that does not exist, with a fingerprint no
  suppression could match.
- **A container that fails to start now says so.** The workspace probe discarded
  stderr, so a failed image pull was reported as "the container cannot read the
  workspace", sending the reader to check mount permissions for an authentication
  problem.
- **The licence check no longer states as fact what it cannot read.** npm licence
  metadata lives inside installed packages, not the lockfile; reporting "618
  dependencies declare no licence" asserted something unreadable rather than absent.
  Workflow files, lockfiles and GitHub Actions are no longer counted as dependencies.
- **Vendored code is excluded**, and its count reported. On a real project, 30% of
  findings came from a dependency's own test fixtures.
- **Secrets in gitignored files are ranked honestly** rather than as leaks.
- valvur no longer scans its own results folder, which produced findings about
  findings that compounded on every run.

### Security

- The version is now derived from package metadata in one place. It previously lived
  in five, and had already drifted: the shim ran as `0.1.0.dev0` while writing
  `0.1.0rc1` into `results.sarif` — a provenance artifact claiming a version the
  running code was not.

## [0.1.0rc1] — 2026-08-31

First published release candidate. Offline-first scanning, MCP server and CLI, the
layered results contract, exploit-aware ranking via CISA KEV and FIRST EPSS,
suppressions with mandatory expiry, and the checks built for AI-generated code:
slopsquat detection, agent-config auditing, hidden Unicode and LLM-output-to-sink
taint.
