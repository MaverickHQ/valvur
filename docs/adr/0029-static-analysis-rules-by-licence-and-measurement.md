# ADR-0029 — Static-analysis rules, by licence and by measurement

**Status:** accepted 2026-09-29 by the owner, with the review of that day; written by
task R9.2 from `tasks.md` D29. Requirements F2.9 and F5.10. Amends ADR-0004's
consequences, which accepted a small rule set because nothing better could be licensed
cleanly.

## Context

Static analysis was 11 Opengrep rules. The taint rules never fired on real code, and a
reviewer accepted none of the 11 findings on real repositories that were not about
pinning (task 22.E.2). Injection, XSS, path traversal and SSRF, the classes AI-written
code most often gets wrong, went largely undetected.

Two rule sources were checked on 2026-09-29:
- **`opengrep-rules`** was archived on 2025-11-28, under LGPL-2.1 with the Commons
  Clause, and labelled "for research, testing & benchmarking". It is not usable.
- **GitLab's `sast-rules`** is MIT, in Semgrep syntax, and maintained.

## Decision

1. **Candidates:** GitLab's `sast-rules` at a pinned commit, for Python, JavaScript and
   TypeScript, Go and Java.
2. **Eligibility (F2.9):** a rule is eligible only if the project it was translated
   from, which its metadata names, is MIT, Apache-2.0 or BSD. Rules from flawfinder,
   find-sec-bugs, security-code-scan or Brakeman are excluded. So are `opengrep-rules`
   and Semgrep's registry (ADR-0004).
3. **A rule ships** when, over the Score's static-analysis tracks and the corpus
   (ADR-0026), it has at least one true positive and precision of at least 0.5.
4. **Where they live:** `rules/vendor/gitlab/`, with the licence, the commit and a
   manifest of each rule's origin, credited in `NOTICE`.
5. **CWE on findings (F5.10):** each finding carries its rule's CWE in `findings.json`
   and SARIF, as an optional field.
6. **Opengrep's intra-file cross-function taint** is adopted if the pinned Opengrep
   supports it and it raises the static-analysis tracks without raising their
   false-positive rate.
7. **Speed:** Opengrep's median time on the acceptance set may grow at most 30%. Past
   that, the slowest rules go first.

## Fallback

If no candidate is eligible, valvur writes its own rules (Apache-2.0) for the tracks'
categories, measured the same way.

## Rejected

- **Semgrep's maintained rules.** They carry a licence permitting no competing use
  (ADR-0004).
- **Shipping every eligible rule.** Unmeasured rules are how a scanner earns its noise.
