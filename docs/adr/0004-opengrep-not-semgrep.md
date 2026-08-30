# Opengrep replaces Semgrep for static analysis

We bundle Opengrep (LGPL-2.1) rather than Semgrep. In December 2024 Semgrep moved
its maintained rules to a licence permitting only internal, non-competing and
non-SaaS use. valvur is a published scanning tool, which is plausibly a competing
use, and redistributing those rules inside an image we distribute is legally murky.

## Consequences

Opengrep is the consortium fork (Aikido, Endor Labs, Jit, Orca) and keeps the same
rule syntax, so community rulesets still work.

This is a licensing constraint, invisible in the code, and the single most likely
decision for a future contributor to "fix" by swapping Semgrep back in. It should
not be reversed without legal advice.

We lose some Semgrep-maintained rule coverage. We do not claim parity with commercial
SAST, so this is an acceptable trade rather than a gap to paper over.
