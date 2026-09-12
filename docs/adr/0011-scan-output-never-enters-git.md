# Scan output never enters git history, on any branch

The **Results Folder** is never committed — not on a working branch, not on a build
branch, not anywhere. Three layers enforce it: the folder self-ignores via its own
`.gitignore` containing `*`, the project root `.gitignore` lists it as a visible
signal, and a tracked `pre-commit` hook refuses any staged path under
`.security-scan/`.

> **Scope, clarified 2026-09-12.** The second and third layers are *this
> repository's* — dogfooding. In a scanned **Workspace** valvur writes only the first:
> the self-ignoring folder (F7.2). It never edits the project's root `.gitignore`;
> F7.3, which asked it to, was retired unimplemented in task 22.C.2 because that is a
> write to a tracked file in the scanned tree.

## Considered Options

**Commit results on a build branch, publish a separate clean branch to the remote.**
Rejected — it does not work the way it appears to. Git objects are repo-wide, not
branch-scoped: blobs committed on a build branch live in the object store and are
reachable from any branch carrying that history. A "clean" publish branch removes
nothing retroactively, and a single `git push --all`, an accidental merge, or a pull
request opened from the wrong branch puts the data on the remote permanently. A
guarantee that depends on remembering which branch you are on is one that eventually
fails.

## Consequences

The payload is the reason this is absolute. Even with **Redaction** applied, a
`findings.json` is a map of a project's unpatched vulnerabilities — exact paths,
packages, versions and CVE identifiers. It is a targeting document, and it should not
exist in a place designed to distribute and retain data forever.

**`.gitignore` does not stop `git add -f`.** That gap is why the pre-commit hook
exists rather than relying on ignore files alone. The hook is tracked in `.githooks/`
with `core.hooksPath` set, so it is shared and reviewable rather than living
untracked in `.git/hooks`.

Builds do not need results committed. CI generates them inside the job and reads them
from the working directory — they are job artifacts. The Phase 11 self-scan release
gate works exactly this way.

The one thing that *is* published is a curated, signed SBOM and build provenance as
release assets (F10.3) — versioned artifacts with an audit trail, not raw scan output
on a branch.
