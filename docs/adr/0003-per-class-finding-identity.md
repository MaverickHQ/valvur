# Fingerprints derive from each Finding Class's natural key

A Fingerprint is computed from the natural identity of its Finding Class — a
dependency vulnerability by `(ecosystem, package, version, vuln_id)`, an IaC
misconfiguration by `(rule, path, resource_address)`, a secret by a hash of the
secret itself — and never from a line number. Only static-analysis Findings need a
content hash, and it covers the matched text alone.

## Consequences

Line-based identity would break the entire workflow: after a developer fixes the
first Finding, every Finding below it has shifted, and the next Scan Run reports one
fixed and forty new. The Status diff would be noise.

Most Finding Classes have a better key than a line hash already available. A CVE in
`lodash@4.17.11` has nothing to do with a location, and bumping the package marks it
`fixed` precisely and automatically — exactly the signal a developer needs to confirm
their own work.

Fingerprints must be byte-identical across machines, because Suppressions reference
them and are committed. Paths are therefore Workspace-relative.

The second benefit is reviewability, and it constrains how Suppressions are written.
Per-class identity means a Suppression can say what it is accepting —
`aws_s3_bucket.logs / CKV_AWS_18` is a decision a reviewer can weigh in a pull
request; `4e4dff39…` is not. **The Fingerprint is the matching key, never the whole
entry**: F8.2 requires human-readable context alongside it, or this advantage is
thrown away at the point it would be used.

**The algorithm is a compatibility surface from the first commit.** It carries an
`fp_version`, because changing it invalidates every Suppression in every project
using valvur. This is the most expensive thing in the system to get wrong.

Known limitation, accepted: identical patterns repeated in one file are
disambiguated by ordinal, so if one of three is fixed we know the count fell but not
which one. Renamed files appear as `fixed` plus `new` until Git rename detection is
added.
