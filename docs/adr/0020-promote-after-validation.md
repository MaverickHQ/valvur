# ADR-0020 — Promote after validation: a candidate tag, re-tagged by digest

**Status:** accepted 2026-09-20 (task 26.1.1), rehearsed twice before it was
accepted and twice more since (26.1.2, 26.1.3); no real tag has run it yet — the
next one will. Recorded so the order is not reopened without the reason it was
changed.

## Context

The release pipeline (`release.yml`) grew in the order its parts were needed: the
image pushed and tagged, then signed and attested, then the wheel built and
uploaded to PyPI, then the GitHub release — and, last, from 12b.2, an `artifact`
job that installed the wheel from `dist/` into a clean environment and drove the
image by the digest just signed through the constraint suite, the e2e suite and
the self-scan gate (N2.5). That job was the first to test what a user gets rather
than the tree; its own comment said what it could not do: *"Nothing here can stop
a release that has already left; it can turn the run red and name why."*

The second external review (2026-09-20) called this the most dangerous single gap
in the project: `pip install valvur` served a version, and `:latest` pointed at an
image, before either had been validated as a pair. A red `artifact` job would have
been a post-mortem, not a gate — and PyPI uploads cannot be undone, only yanked
(24.4 had just done exactly that for `0.1.0rc1`).

## Decision

Three jobs where there was one, in the order the evidence arrives:

1. **`stage`** builds the index over the two architectures' digests and pushes it
   under **`:<version>-candidate`** — never `:<version>`, because the shim of that
   version pulls `:<version>` and the name must not resolve until the pair is
   proven. It signs the digest keylessly, attests SLSA provenance, generates the
   SBOM *from the digest*, builds `dist/`, and hands `dist` and the SBOMs on as run
   artifacts. Nothing a user can install or pull by the version's name exists yet.
2. **`artifact`** validates exactly as before — the wheel from `dist/` with the
   source tree deliberately off the path, the image by digest, the signature and
   the provenance verified, the label and the tree hash agreeing, the constraint
   suite, the e2e suite and the gate — on both architectures (26.1.2, F10.7).
3. **`promote`**, `needs: artifact`, carries the `release` environment and does the
   three things that cannot be taken back, cheapest to undo first: re-tags the
   signed digest as `:<version>` and `:latest` — a manifest re-push, so the
   signature and the attestation on the digest hold, and the step asserts both
   tags resolve to the validated digest — publishes to PyPI by trusted publishing
   and verifies the attestation PyPI serves back (26.1.3, F10.3), and creates the
   GitHub release.

A required reviewer on the `release` environment is therefore a brake **after the
evidence and before the irreversible step**, which is where a human check belongs.

## Alternatives

- **Validate before pushing at all.** Not possible: the digest the artifact job
  tests is the digest the registry assigns on push, and signing, attesting and
  the SBOM all need it. The push is the first step that produces the thing to be
  validated.
- **Push `:<version>` at stage and accept a burned number on failure.** The shape
  the task text proposed. A red `artifact` job would have left a signed
  `:<version>` image on GHCR with no wheel; the shim of that version would resolve
  it. Recovery would have meant deleting the tag through the packages API or
  burning the number. Rejected for the candidate tag, which costs nothing and
  leaves nothing a user resolves.
- **A candidate *package*** — a second GHCR name, `valvur-candidate`, promoted by
  copying. Two names to sign, verify and keep public, and a copy rather than a
  re-tag, so the digest a user pulls would not be the digest that was validated.
  Rejected.
- **Promote by re-tag (chosen).** One package, one digest, one signature, one
  attestation; the candidate tag stays behind pointing at the same digest as the
  version tag, harmless and undeletable on its own (GHCR deletes by version, which
  is the digest).

## Consequences

- A failed validation leaves a `-candidate` tag and nothing else; the version
  number is not burned. `RELEASING.md`'s failure table says so, row by row, and
  lost its "re-point `latest`" recovery because `latest` no longer moves before the
  evidence.
- The release takes about a minute longer than before (the re-tag, and the PyPI
  attestation read back), and `:latest` moves roughly seven minutes after the
  candidate is pushed — measured 7m22s on the first rehearsal.
- The rehearsal mode (`workflow_dispatch`) runs the same three jobs against the
  throwaway targets, so the order is proven before a real tag meets it. The first
  rehearsal of this order found a lint error in the new test; the second was
  green; the third and fourth (26.1.2, 26.1.3) found the publish action leaving
  each file's attestation bundle beside it in `dist/`.
- `promote` is the only job that publishes to PyPI and the only one that writes
  a version tag or `latest`; `stage` holds an OIDC token too — for signing and
  attesting — but its permissions do not reach the index or the release.

## What reopens this

- PyPI offering a staged or draft upload that can be validated before it is
  visible, which would let the wheel be tested on the index it will be served
  from rather than from `dist/`.
- A registry that refuses a manifest re-push under a second tag, or one whose
  signature is bound to a tag rather than a digest — neither is GHCR today.
