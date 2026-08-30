# Findings are a table, not a graph

We do not use a graph database. Findings form a flat collection keyed by file,
package, rule and severity, and every query we need is known in advance.

## Considered Options

A knowledge-graph layer was proposed for exploring and visualising Findings. Rejected
on three grounds: graph databases earn their cost on unpredictable multi-hop
traversals, which we do not have; it would add a stateful service to a stateless
tool, with startup, persistence and backup concerns; and a force-directed graph of
even a few hundred Findings is a hairball nobody learns anything from.

## Consequences

The genuine need behind the proposal — making Findings easy to understand — is met by
`report.html`, a single self-contained file that opens offline, and by rendering the
Dependency Path as an indented tree.

The one graph-shaped structure in the domain is the dependency tree, and the SBOM
already contains it. We do not stand up a database to hold a structure we were handed.
