# ADR-0033 — A bar on maintained code decides which rules count toward the verdict

**Status:** proposed 2026-11-21, for the owner's checkpoint B; from D82a to D82h in
[the signal-and-adoption design](../../.kiro/specs/signal-and-adoption/design.md).
Requirements N4.1 and N4.2. Amends ADR-0029 and ADR-0026.

## Context

ADR-0029 ships a static-analysis rule when it has one true positive and precision of at
least 0.5, summed over the planted tracks and the corpus of maintained projects. The planted
cases carry a rule that is wrong on real code: `valvur.python.weak-hash` catches 37 planted
cases and is false in all 21 of its Findings on maintained code.

Measured on 2026-11-21, at `f0e7150`: of 171 judged Findings on 48 maintained projects, 3 are
true. Gitleaks' rules give 98 of the false ones, 85 of them under a test, fixture, example or
documentation path. Two static-analysis rules give 44. The eighth track scores 2.3.

The mechanism for showing a Finding without asserting it exists: the inventory (D47a).
Only Opengrep's adapter can use it today, from a rule's own YAML.

## Decision

1. **A second bar, on the corpus alone.** A rule is *measured there* with 5 or more judged
   Findings on the corpus, and *under the bar* when fewer than half of them are true.
   ADR-0029's bar still decides whether a rule ships at all.
2. **A rule under the bar is inventory:** reported for review, never active, never counted
   by the verdict or the gate. No rule is deleted.
3. **One table holds the tiers, for every Scanner's rules,** as package data. A row names a
   Scanner and a rule ID, and says `everywhere` or `test material`. A project cannot change
   it.
4. **`test material` is for a secrets rule that matches a shape** (a PEM block, a JWT, a
   high-entropy string beside a keyword). Under a test, fixture, example or documentation
   path its Finding is inventory, and it stays active elsewhere. **A rule that matches a
   provider's own format gets no row:** a live-format secret under a test path stays active.
5. **A rule of valvur's own under the bar is narrowed first,** and takes a row only if the
   narrower rule fails on the corpus or loses its planted category past the ratchet.
6. **A demoted rule takes its planted credit with it.** The Score counts active Findings
   only. The Python track is re-based once for `weak-hash` and the vendored `random` rule,
   from 40.9 to about 34.7, with both numbers and this reason recorded, as R29.6 re-based
   the eighth track.
7. **The eighth track keeps its population.** Checkov's and zizmor's Findings on the corpus
   are judged by rule in a table of their own, and are not pooled into the track.
8. **The eighth track's target is 33, with at most 8 false active Findings on the corpus.**
   The approved requirement says 50. With 3 true Findings in the corpus, 50 needs at most 4
   false ones left active, and 7 remain from rules with one to three Findings there, which
   item 1 does not measure.

## Consequences

- A `findings` verdict on maintained code is expected to be right about one time in three,
  from about one in sixty.
- A private key, a JWT or a generic high-entropy string under a test path no longer makes a
  verdict `findings`. A real one committed there is listed for review and is not asserted.
  `docs/RULES.md` and the README say so.
- The Python track's number falls by about 6 points on the day the two rules are demoted,
  and the Score as a whole rises by about 3.
- The eighth track's score moves 4 to 5 points for each false Finding while the corpus
  holds 3 true ones, so the count of false active Findings is reported beside it.

## Rejected

- **Path alone decides a secret's tier.** It would hide a live cloud key under `tests/`.
- **Deleting the two rules.** The inventory keeps them one flag away for a user who wants
  every `md5` call.
- **Counting inventory Findings as detections on the planted tracks.** The Python track
  would keep its number, and the Score would credit a Finding valvur does not assert.
- **Pooling Checkov and zizmor into the eighth track.** Most of their Findings are true by
  reading the file, so the track would pass 50 with nothing changed in valvur.
- **Keeping 50 as the target.** It could be met only by demoting rules on one label each,
  or by changing labels.
