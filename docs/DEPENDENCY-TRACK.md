# valvur's SBOM in Dependency-Track

[README](../README.md) · [Documentation](README.md)

Dependency-Track takes `sbom.cdx.json` as valvur writes it: CycloneDX, from Syft, when a
scan is asked for one (`valvur scan . --sbom`, or `sbom = true` under `[scan]` in
`.security-scan.toml`). **valvur does not upload it.** It has no network access to do so and
no setting for one. Sending an SBOM to a server is your pipeline's step, with your API key,
to a Dependency-Track you chose. That step takes the SBOM off the machine that made it, so
it is yours to add.

What is on this page was measured against Dependency-Track itself, started from its
published images: the workflow `imports.yml` does it, on dispatch, and the record is
[`acceptance/r51.md`](acceptance/r51.md). A test validates the SBOM against the CycloneDX
schema of the version it declares.

## The step

After `valvur scan . --sbom`:

```bash
curl -fsS -X POST "$DEPENDENCY_TRACK_URL/api/v1/bom" \
  -H "X-Api-Key: $DEPENDENCY_TRACK_API_KEY" \
  -F autoCreate=true \
  -F projectName="my-service" -F projectVersion="$GIT_SHA" \
  -F bom=@.security-scan/sbom.cdx.json
```

**The key's team needs two permissions:** `BOM_UPLOAD`, and `PROJECT_CREATION_UPLOAD` for
`autoCreate` to make the project. As installed, the *Automation* team has the first and
not the second, so grant it.

The answer is a token. Dependency-Track processes the SBOM after it answers, and
`GET /api/v1/event/token/<token>` says when it has finished.

## What arrives

<!-- measured: dependency-track -->
With Dependency-Track 5.2.2, for the CycloneDX 1.7 SBOM of valvur's test fixture:

| what was sent | sent | arrived |
|---|---|---|
| components | 16 | 15 |
| of them libraries | 12, with 11 distinct package URLs | 11, each with its package URL |
| of them files | 4 | 4 |
| file hashes | 4 | 4 |
| licences | 0 | 0 |
| the same SBOM, uploaded again | 16 | 15, as before |

<!-- /measured -->

## What to know

- **A package that two lockfiles pin is one component.** Syft writes a component for each
  lockfile, with one package URL, and Dependency-Track keeps one.
- **The same SBOM again adds nothing** to the same project and version.
- **The SBOM carries no licence for a package read from a lockfile,** so none arrives. A
  lockfile states none, and valvur's `offline` Profile asks no registry.
- **The vulnerabilities Dependency-Track reports are its own analysis** of the components.
  They are not valvur's findings, which are in `findings.json` and `results.sarif`, and
  this measurement did not compare the two.
- **The files in the SBOM** are the ones Syft recorded, each with its hash.
