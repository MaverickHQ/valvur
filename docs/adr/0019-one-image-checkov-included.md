# ADR-0019 — One image, with Checkov in it

**Status:** accepted 2026-09-18 (task 23.4.6). **Decided by measurement**, as the
task required, and recorded so the question is not reopened without new numbers.

## Context

Checkov is the largest and slowest thing in the image. The task that asked this
question (23.4.6, written 2026-09-12) put it as: *191MB of the image, the slowest
Scanner by ten seconds, and `applies_to` already knows when there is nothing for it
to read — yet every user pulls it and every scan of application code pays its
startup.* Two shapes were named to measure: a second image, `valvur-checkov`,
pulled the first time `applies_to` says yes; or a `slim` tag of the main image
without it. Either would put a smaller number in the README's first-run table for
"the common case".

## What was measured

**Size.** The image is 577MB uncompressed and **223MB (arm64) / 233MB (amd64)
compressed** — the number a first run pays. Checkov's layer is 164MB uncompressed
and **53MB compressed: 23% of the pull**. The other 77% is Trivy (46–51MB), Opengrep
(48–50MB), Syft (27–29MB), OSV-Scanner (18–20MB), Python (14MB), Gitleaks (12–13MB)
and Alpine (4MB).

**What a first run downloads.** The measured first run over MCP (24.1) is 110s from
an empty machine, of which the image pull is 22s; the vulnerability database
(119MB) and the name index (35MB) are fetched too, whichever image shape ships. A
slim image would cut the pull by about a fifth — **roughly 5s of 110s** — and the
first-run total from ~380MB to ~325MB.

**Who would use it.** `applies_to` runs Checkov when a Dockerfile, Terraform,
Kubernetes, CI or template file is present, and skips it otherwise with the skip
reported (§7). Measured on the public corpus (24.3, 23.3.2): **every one of the
thirteen real repositories carries a workflow file, so Checkov runs on all of
them** and finds things there (`CKV2_GHA_1` on five of smolagents' workflows). An
on-demand second image would therefore be pulled by every real user on their first
scan — the two pulls cost more than one — and a `slim` tag would serve only a
repository with no IaC *and* no CI workflow, which the corpus puts at 0 of 13. For
that repository `applies_to` already saves the runtime; only the 53MB remains.

**Time, which is the cost that is real.** On GitHub's Linux runner Checkov is
**97–100% of every scan**: 15–18s of a 15–18s scan on twelve application
repositories, where everything else finishes inside 3s, and 107s of 108s on the
Terraform module. That is not addressed by either image shape — a repository with a
workflow file pays it whichever image it pulled. One lever was measured on the way:
narrowing Checkov to the frameworks present (`--framework github_actions` on a
workflow-only repository) took a run from **9.3s to about 7.0s** on this Mac, twice
each way. Most of Checkov's time is its own startup — loading every check — not
the analysis, and a two-second lever on a 15-second Scanner is recorded here rather
than built.

## Decision

**One image, Checkov included. No second image, no `slim` tag.** The 53MB it would
save reaches nobody the corpus can find, and the cost that users actually pay —
Checkov's runtime — is unchanged by either shape.

Rejected:

- **`valvur-checkov`, pulled on demand.** Pulled by everyone (13 of 13), so it
  costs a second pull and a second signature to verify, a second tag to keep in
  step with the first (F1.9's compatibility check would need to cover two images),
  and a mid-scan pull on `offline` — which 24.1 allows for *absence* of the main
  image, but a second image absent on every first scan is not a corner case, it is
  the path. All of that for a number that reaches no one.
- **A `slim` tag.** Another artifact to build, sign, attest and rehearse on every
  release, for the repository with no IaC and no workflow, whose runtime
  `applies_to` already protects. Anyone who wants it can build it: the Checkov
  layer is one `RUN` in the Dockerfile.
- **Framework narrowing.** A real but small lever (about 2s), and it moves the
  decision of what Checkov looks at from Checkov's own file detection into
  valvur's, which is a second place for a detection gap to hide. Not taken now;
  the number is here if the runtime question is reopened.

## What reopens this

- A measured user for whom 53MB is the cost that matters — an air-gapped mirror
  with a hard size limit, say — rather than a hypothetical one.
- `applies_to` skipping Checkov on a meaningful share of real repositories, which
  today is 0 of 13.
- Checkov's startup growing past what a first run can absorb, or a faster IaC
  scanner with the same coverage under an acceptable licence (ADR-0005 rules out
  hadolint on GPL grounds).

## Consequences

P1's first-run number stays what 24.1 measured: one image, about 240MB, then the
database and the index. N1.1's exception for Terraform stands, and its cause is
named as Checkov's runtime, not its size. The README's first-run table does not gain
a smaller number for a case that does not occur. The Checkov layer stays where
23.4.1 put it — its own hash-locked venv, one `RUN` — so the option is a
Dockerfile edit away for anyone the numbers turn out to apply to.

## Amendment 2026-09-26 (task 28.2.1) — the runtime measured, and most of it was the image's

"Time, which is the cost that is real" above says most of Checkov's time is its
own startup, loading every check, and records a two-second framework lever. Task
28.2.1 was to measure that lever and an incremental skip on the corpus before
either became a change. The lever re-measured at **0.1 s of 10.6 s** on a
workflow-only tree, so a profile of the run (`cProfile` over `checkov.main`,
Docker Desktop, `--network=none`) was taken instead, and 11.5 s broke down as:

- **5.0 s in `getaddrinfo`.** `banner.py` calls the update checker at import and
  it asks PyPI for the latest version. The Dockerfile's
  `CHECKOV_DISABLE_UPDATE_CHECK=true` (23.4.1) is a variable this Checkov does not
  read — `env_vars_config.py` reads `CKV_SKIP_PACKAGE_UPDATE_CHECK` — so every
  start waited for DNS to fail under `--network=none`, and on `full` would have
  reached pypi.org.
- **2.6 s in `compile`.** The image deleted Checkov's `__pycache__` and runs it on
  a read-only root as a non-root user with `PYTHONDONTWRITEBYTECODE=1`, so every
  start compiled 3,913 modules from source: `checkov --version` 5.9 s cold, 1.3 s
  with bytecode.
- About 1.3 s of import proper, and under half a second of analysis.

Both causes are the image's, not Checkov's, and both are fixed there: the variable
Checkov reads, and `compileall` over the venv and the Checks' package with the
stdlib's shipped bytecode kept. **Measured as the runner runs it** (non-root,
read-only root, no network), the workflow-only tree took **10.2–10.7 s before and
3.0–3.3 s after**; the e2e suite, which scans on every test, 216 s → 152 s. The
corpus on Linux CI, before and after, is in 28.2.1's STATUS note.

**The size trade runs the other way from the decision above.** The bytecode is 61
MB uncompressed and **22 MB compressed: 220 → 242 MB**, about two seconds more on
a first pull, once, against about seven seconds less on every scan. The decision
stands — one image, Checkov in it — and one sentence of it is withdrawn: the cost
users pay was *not* unchanged by every image shape. It was mostly ours.
