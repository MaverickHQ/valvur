"""Validate a CycloneDX document against the schema of the version it declares (R51.6).

The schemas are vendored under `tests/fixtures/schema/cyclonedx-<version>/`, as published.
A document of a version with no vendored schema is refused by name, so a Syft upgrade that
moves the version fails here and not in someone's Dependency-Track.
"""

from __future__ import annotations

import json
from pathlib import Path

SCHEMAS = Path(__file__).parent / "fixtures" / "schema"


class NoSchema(AssertionError):
    pass


def validate(document: dict) -> None:
    """Raises `jsonschema.ValidationError` when the document does not hold to its schema."""
    import jsonschema
    from referencing import Registry, Resource

    version = str(document.get("specVersion"))
    folder = SCHEMAS / f"cyclonedx-{version}"
    if not folder.is_dir():
        raise NoSchema(f"the SBOM declares CycloneDX {version}, and no schema of that version "
                       f"is vendored under {SCHEMAS.relative_to(SCHEMAS.parents[2])}")
    schemas = {path.name: json.loads(path.read_text(encoding="utf-8"))
               for path in folder.glob("*.schema.json")}
    main = schemas[f"bom-{version}.schema.json"]
    base = main["$id"].rsplit("/", 1)[0]
    registry = Registry().with_resources(
        (f"{base}/{name}", Resource.from_contents(schema)) for name, schema in schemas.items())
    jsonschema.Draft7Validator(main, registry=registry).validate(document)
