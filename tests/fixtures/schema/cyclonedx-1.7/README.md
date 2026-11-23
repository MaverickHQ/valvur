# CycloneDX 1.7, the JSON schema

The schema of the `specVersion` Syft writes into `sbom.cdx.json`, and the three schemas it
refers to. `tests/test_sbom_schema.py` validates the SBOM against them (R51.6).

- **From:** `github.com/CycloneDX/specification`, the directory `schema/`, at the tag
  `1.7.2`, fetched on 2026-11-23. The files are as published, unedited.
- **Licence:** Apache-2.0, the specification's own.
- **When Syft writes another version,** the test fails and names it: vendor that version's
  schema beside this one, in a directory named for it.
