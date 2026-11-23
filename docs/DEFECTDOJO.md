# valvur's findings in DefectDojo

[README](../README.md) · [Documentation](README.md)

DefectDojo imports `results.sarif` as valvur writes it. **valvur does not upload it.** It
has no network access to do so and no setting for one. Sending a result to a server is your
pipeline's step, with your token, to a DefectDojo you chose. That step takes the result off
the machine that made it, so it is yours to add.

What is on this page was measured against DefectDojo itself, started from its published
images: the workflow `imports.yml` does it, on dispatch, and the record is
[`acceptance/r51.md`](acceptance/r51.md).

## The step

After `valvur scan .`, the first time, an import. It makes the product, the engagement and
the test, and its answer names the test:

```bash
curl -fsS -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DEFECTDOJO_TOKEN" \
  -F scan_type=SARIF \
  -F product_type_name="Engineering" -F product_name="my-service" \
  -F engagement_name="valvur" -F auto_create_context=true \
  -F minimum_severity=Info \
  -F file=@.security-scan/results.sarif
```

Every time after that, a re-import into that test:

```bash
curl -fsS -X POST "$DEFECTDOJO_URL/api/v2/reimport-scan/" \
  -H "Authorization: Token $DEFECTDOJO_TOKEN" \
  -F scan_type=SARIF -F test="$DEFECTDOJO_TEST" \
  -F minimum_severity=Info \
  -F file=@.security-scan/results.sarif
```

**Re-import, do not import again.** DefectDojo installs with deduplication off, and a
second import of the same file then files every finding a second time. A re-import files
none. With deduplication turned on in DefectDojo's system settings, a second import marks
each finding a duplicate instead.

## What arrives

<!-- measured: defectdojo -->
<!-- /measured -->

## What to know

- **One finding for each file.** A dependency vulnerability found through two lockfiles is
  one finding in valvur, with both paths, and two in DefectDojo, one for each lockfile.
  Both need the fix. DefectDojo keeps valvur's Fingerprint on neither of the two, so match
  those by rule and file.
- **The Fingerprint** is DefectDojo's *unique id from tool*, written
  `valvurFingerprint:<fingerprint>`. It is the same string `findings.json` and a
  Suppression in `.security-scan.toml` use.
- **A risk you accepted arrives inactive and marked a false positive.** That is how
  DefectDojo reads a SARIF suppression. Nobody judged it false: it is a Suppression in
  `.security-scan.toml`, where its reason and its expiry are. When it lapses, valvur
  reports the finding live again.
- **An ignore of your own that valvur did not accept arrives active.** An ignore with no
  reason and no expiry is not an accepted risk, so valvur writes no SARIF suppression for
  it and the finding is live in both. The case measured is a `.trivyignore` entry.
- **The CWE and the OWASP categories** arrive as the finding's CWE and as tags:
  `cwe-89`, `external/owasp/a05:2025`. Filter by them. They are what the rule is mapped to,
  as [`OWASP-MAPPING.md`](OWASP-MAPPING.md) lists.
- **An advisory's CVE** arrives as the finding's vulnerability id.
- **Severity** is valvur's. DefectDojo has no *unknown*, so that arrives as Medium.
- **A dependency's package and version** are in the finding's title. DefectDojo's SARIF
  import has no component field to put them in.
