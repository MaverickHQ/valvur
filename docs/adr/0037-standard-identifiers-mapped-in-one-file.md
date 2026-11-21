# ADR-0037 — Standard identifiers are mapped in one file, and worded as mapped

**Status:** proposed 2026-11-21, for the owner's checkpoint B; from D82o in
[the signal-and-adoption design](../../.kiro/specs/signal-and-adoption/design.md), which
brings back D69, parked on 2026-10-09. Requirements F5.10 and F7.9.

## Context

A Finding carries a CWE only when Opengrep reported it, and no OWASP category from any
Scanner. Tools that receive valvur's output, and the people who audit it, sort by those
identifiers. valvur's rule IDs come from seven sources, and three of them (Gitleaks',
Checkov's and zizmor's) cannot be listed from this repository.

A mapping is easily read as a claim of coverage or compliance, which valvur does not make
(`CLAUDE.md` §10).

## Decision

1. **One mapping file, as package data,** looked up by the rule's ID, then a rule prefix,
   then the Scanner, then the Finding Class.
2. **Every rule and Check valvur writes or vendors has an entry by ID.** Each other Scanner
   has one entry, and a rule of theirs may have its own. A dependency advisory takes the CWE
   its advisory gives.
3. **The lists:** CWE, the OWASP Top 10, the OWASP Top 10 for LLM applications and OWASP's
   agentic lists, each at the edition current when the file was last read, named with its
   date. An entry may be `none`, with the reason.
4. **On a Finding:** `owasp` beside `cwe`, additive in `findings.json`, in SARIF as
   taxonomies, relationships and tags, and in the reply. Neither is identity, so
   `fp_version` does not move.
5. **The wording is *mapped to*,** in every document and output. Never *covers*, *complies
   with* or *certified against*. A test holds it.
6. **A generated page lists every rule with its identifiers, and each list's categories
   that nothing maps to.**

## Consequences

- valvur's output sorts into the taxonomies DefectDojo, GitHub and auditors already use.
- The gaps are published beside the mapping, by the same generator.
- A new edition of a list is a change to one file, and a test names every rule it leaves
  without an entry.

## Rejected

- **Identifiers taken from each Scanner's own metadata alone.** Only Opengrep's rules carry
  any, and no Scanner carries the LLM or agentic lists.
- **A mapping per rule for Checkov's and Gitleaks' rules.** They can be listed only from the
  tools at runtime, and number in the thousands.
- **A coverage percentage per list.** It would be read as a compliance claim.
