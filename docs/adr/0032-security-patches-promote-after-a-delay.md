# ADR-0032 — Security patches promote after a delay the owner can cancel

**Status:** proposed 2026-11-22, written by R45.1 from D81h, D81i and D81aa in
[the self-healing design](../../.kiro/specs/self-healing-supply-chain/design.md). The owner
gave a standing authorisation for this class of release on 2026-11-21, and accepted its
extension to image patches (D81aa) on 2026-11-22. The ADR itself waits for the owner's
acceptance, which is a row in that spec's `tasks.md` §3, with D81h's fallback beside it.
Requirements N2.5 and N4.3. Amends ADR-0020, and D62a and D64(e) of the main `tasks.md`,
for one class of release.

## Context

ADR-0020 put the owner's approval after the evidence and before the irreversible step, and
D64(e) kept the signed tag and the brake with the owner. On 2026-10-20 four advisories
reached the Checkov lock with fixes on PyPI. The published image stayed vulnerable for as
long as each step waited for the owner. On 2026-11-21 the nightly's scan of the published
1.6.1 image blocked on 51 vulnerabilities, and clearing them by hand took three sittings.

## Decision

1. **A release whose tag the heal signed promotes in the `release-security` environment,**
   which has a 12-hour wait timer and no reviewer. `release.yml` first verifies it as a
   patch release of patch-class commits whose only machinery change is the Checkov lock.
2. **A notice issue names the time,** and the owner can cancel the run until then.
3. **Every other release keeps the `release` environment and its reviewer,** and every gate
   runs for both.
4. **Extended on 2026-11-21, at the owner's word of that day:** the class also holds a
   release whose Dockerfile changed only in its base digest, its Go pin and its raises
   (D81x), on two conditions the release checks itself. Every track of the Score equals its
   baseline. Every Scanner gives the same output from the new image as from the last.
5. **A release that changes what valvur reports is never in this class.**

## Consequences

- The owner's veto becomes passive for one narrow class of release.
- A stolen heal key can at most start a patch release of `main`, which every gate and the
  timer still judge.
- D62a's rehearsal is skipped for this class: the run's own `artifact` validates before
  `promote`.

## Rejected

- **The owner's approval kept.** It is D81h's fallback: the owner as required reviewer on
  `release-security`. It is what left the image vulnerable while each step waited.
- **A maintenance branch.** A second line to release from, for a product with one.
- **Keyless tags.** `main`'s rule on tags asks for a signature the owner's ruleset can name.
