# No `report.html`

The **Results Folder** contains no HTML report. `SUMMARY.md` and `REMEDIATION.md`
carry the same information as Markdown, which renders natively in every IDE, on
GitHub, and in the terminal.

## Considered Options

**Ship a self-contained `report.html`.** Planned from the outset, cited in ADR-0002's
artifact list and in ADR-0006 as the answer to visual comprehension when a graph
database was rejected. Dropped before implementation.

## Consequences

The decisive argument is that **the results are deliberately not shareable**. An HTML
report's real advantage over Markdown is handing someone a file they can open without
a toolchain — but the **Results Folder** is gitignored and local-only, made structural
by ADR-0011. The product's central design removes the artifact's main benefit.

It was also the worst risk-to-value ratio in the contract. Rendering untrusted
**Workspace** content in a browser is the largest security surface we would ship:
requirement F7.15 and two whole test cycles existed solely to make it safe, guarding
against a payload that executes as script or hides itself with styling while
remaining in the file. That is a real cost for a convenience.

And it was the only artifact with **no single identified consumer**, which is exactly
the rule ADR-0002 set for itself. `SUMMARY.md` serves humans and agents,
`findings.json` serves programmatic queries, SARIF serves IDEs, `raw/` serves
verification. `report.html` served "visual review", which is not a consumer.

ADR-0006's reasoning survives unchanged: rejecting a graph database rested on
findings being a flat table with predictable queries, and the alternative offered was
a *readable report*. Markdown is a readable report.

**F7.8 is deferred, not withdrawn.** It returns if the usability gate (task 10.0)
shows people want it, or if an enterprise buyer asks for a shareable artifact — at
which point it has an identified consumer and is built deliberately rather than
speculatively.

**F7.15 stays in force**, dormant. It is a standing rule for any artifact that
renders, and the guard should exist before someone adds one.
