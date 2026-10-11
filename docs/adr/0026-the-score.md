# ADR-0026 — The Score: detection measured, and held by a ratchet

**Status:** accepted 2026-09-29 by the owner, with the review of that day
(`docs/history/REVIEW-2026-09-29.md`); written by task R9.2 from `tasks.md` D21 and D22.
Requirements N4.1 to N4.4.

## Context

The goal every change is judged against says a report must be *trustworthy*, and nothing
measured whether it was. Ground truth was 22 planted expectations in the acceptance set;
the 13-repository corpus judged valvur's own behaviour and never whether a finding was
real; no precision or recall figure existed for any Scanner or finding class. A change
that halved what a Scanner found would pass every check the repository had.

## Decision

1. **One command, `scripts/eval.py`,** runs the image under test over nine **tracks**
   (eight until R41)
   and scores each from 0 to 100 by the OWASP Benchmark's formula: per category, the
   true-positive rate minus the false-positive rate, averaged (N4.1). A **case** is a
   path with a category and a label, vulnerable or safe; it is flagged when an active
   finding of its category lands on it.
2. **The tracks.**
   1. SAST-Python, the OWASP Benchmark for Python v0.1, 1,230 cases in 14 categories, a
      git checkout at a pinned commit in the build cache. It is GPL-3.0, so it is never
      vendored.
   2. SAST-JS, valvur's own vulnerable and safe twins over ten CWEs AI code gets wrong.
   3. Secrets, real formats assembled at runtime against decoys, in files and history.
   4. Dependencies, in seven ecosystems, with advisories over a year old, against their
      fixed twins, and `MAL-` packages from ossf/malicious-packages.
   5. Package reality: nonexistent, near-miss and malicious names against real and
      privately registered ones.
   6. Agent configuration: planted directives, hidden Unicode, blanket approval, hooks
      and leaking settings against benign twins and awesome-cursorrules' real files.
   7. Infrastructure and workflows, against fixed twins.
   8. Real-code precision on the corpus. Every active finding of a valvur-owned rule or
      of Gitleaks is labelled `tp` or `fp` with a reason, and the track is precision
      × 100. The rubric: `tp` when a maintainer would act on the finding (change code,
      rotate, pin). The labels are committed for review. Coverage notes are valvur's
      own limits and are not judged.

      *Amended 2026-09-29 by R9.5, on the first measurement:* the track is
      **smoothed precision**, 100 × (tp + 1) / (tp + fp + 1). The corpus's 24 judged
      findings held no true positive. Plain precision was therefore 0 for one false
      alarm and for forty, and 0/0 for none, so the ratchet could not see noise grow.
      With one imaginary true positive, a silent corpus scores 100 and each false
      alarm costs.
   9. *Added 2026-10-11 by R41 (D80):* model output reaching a sink, the cases of the four
      LLM-output rules, which until then no track held. Generated twins cover each sink
      (code execution, a shell, a query, the DOM) from each SDK the rules name, and the
      flows through a helper they are known to miss. Real cases are the vulnerable code
      of published advisories in LLM frameworks, pinned in `tests/eval/sources.toml`, and
      their fix where a clean one exists. The track is scored per sink like tracks 1 and
      2, and reports the two kinds apart, since valvur writes its own twins. It comes
      ninth so that tracks 1 to 8 keep their numbers.
3. **The Score** is the unweighted mean of the nine, so no weight can be tuned. Adding a
   track re-bases the Score, recorded with both numbers in `tests/eval/baseline.json`
   (`rebased`), never as a rise.
4. **Gates**, pass or fail: freshness, honesty (no `clean` while incomplete, no safe
   twin at high or critical), offline (`what_left_the_machine: nothing`), ranking (a
   known-exploited CVE above a development-only critical), and speed (the median warm
   scan within 110% of the baseline). Each gate is judged from the phase that builds
   what it checks, and recorded before.
5. **The ratchet** (N4.2): `tests/eval/baseline.json` holds each track. A comparison
   fails when a track falls more than 2 points under it or a gate fails. The baseline
   is re-recorded only upward, at a phase commit.
6. **Replication** (N4.4): external sources pinned by commit, generated cases seeded,
   the image named by digest, every dataset's age recorded. Trivy publishes no database
   history, so dependency cases use only advisories over a year old.
7. **When** (N4.3): at every phase exit on this Mac and on Linux, before a release, and
   weekly; after R9, before any change to detection, ranking, data or the reply.
8. **Targets for `1.2.0`** (D22), per track: SAST-Python 25, SAST-JS 50, secrets 90,
   dependencies 90, package reality 95, agent configuration 90, infrastructure and
   workflows 70, real-code precision 80. A target under the measured baseline is raised
   to it. A missed target is recorded for the owner and blocks nothing.

## Rejected

- **An exploit gym** (SecBench.js, BaxBench, CyberGym). Each scores an exploit run
  against live code: dynamic testing, which valvur refuses (`CLAUDE.md` §2).
- **Our own labels on third-party Scanners' findings throughout.** Their precision is
  their authors'; the Score labels what valvur owns and Gitleaks, whose noise users
  meet first.
- **A weighted Score.** Weights invite tuning towards the easy tracks.
- **Agent runs in the Score.** They cost money and are not deterministic.
