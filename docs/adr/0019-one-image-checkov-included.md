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
