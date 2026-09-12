# Layered results contract with one consumer per artifact

**Requirements:** F7.4 (the artifacts and their one consumer each), F7.5 (SUMMARY.md bounded), F7.6 (the machine-facing block first), N1.3 (readable inside a context window).

The Results Folder holds several projections of a single in-memory findings model,
each written for exactly one consumer: `SUMMARY.md` and `REMEDIATION.md` for humans
and agents, `findings.json` for programmatic queries, `results.sarif` for IDEs and
tooling, `run.json` for Provenance, and `raw/` for
verification.

## Considered Options

**SARIF only** — one standard file. Rejected because SARIF is deeply nested and
token-hungry; an agent cannot read it directly, so a second human-facing
serialisation would be needed anyway.

**Bespoke JSON plus Markdown** — two files, tuned for agents. Rejected because it
reinvents SARIF badly and forfeits IDE and enterprise tooling that reads SARIF
natively, which would then be a retrofit.

## Consequences

The consumer of this folder is a language model with a finite context window, while
raw Scanner output for a real project runs to tens of megabytes. Progressive
disclosure is therefore mandatory, not stylistic: `SUMMARY.md` is capped and always
readable, `REMEDIATION.md` is the work queue, `findings.json` is queried per finding,
and `raw/` is never read by an agent. The read path stays bounded no matter how large
the Scan Run.

Several artifacts can drift. They must be generated in one pass from one model, with
a test asserting every Finding in `findings.json` appears in the SARIF and is counted
in `SUMMARY.md`.

`raw/` is the largest part of the folder and the part most likely to contain secrets,
so pruning and Redaction both matter most there.


*(Updated 2026-08-30: `report.html` was cut before implementation by [ADR-0014](./0014-no-html-report.md). The one-consumer-per-artifact rule is why — it was the only artifact without one.)*
