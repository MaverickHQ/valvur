"""The JSON Schema for `.security-scan.toml` (D10, R6.8), and the one check of it
valvur makes.

The schema ships in the package, for an editor's TOML support and for `doctor`.
The shim has no dependencies, so this validator covers the subset the schema
uses: `type`, `properties`, `additionalProperties: false`, `required`, `items`,
`enum`, `minLength` and `format: date`, where a TOML date arrives as a `date`.
It answers with the first problem, naming the key, or None.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

PATH = Path(__file__).parent / "data" / "security-scan.schema.json"

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}


def schema() -> dict:
    return json.loads(PATH.read_text(encoding="utf-8"))


def problem(document: dict) -> str | None:
    """The first way `document` breaks the schema, one sentence naming the key."""
    return _check(document, schema(), "")


def _check(value: Any, rule: dict, where: str) -> str | None:
    name = where or "the file"
    if "enum" in rule and value not in rule["enum"]:
        allowed = ", ".join(json.dumps(v) for v in rule["enum"])
        return f"`{name}` must be one of {allowed}; got {value!r}."
    expected = rule.get("type")
    if expected == "string" and rule.get("format") == "date" and isinstance(value, date):
        return None
    if expected is not None and not _is(value, expected):
        return f"`{name}` must be {_A.get(expected, expected)}; got {value!r}."
    if expected == "string" and len(value) < rule.get("minLength", 0):
        return f"`{name}` must not be empty."
    if expected == "object":
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    takes = ", ".join(properties) or "nothing"
                    return (f"`{_join(where, key)}` is not a key it takes; it takes "
                            f"{takes}.")
        for key in rule.get("required", ()):
            if key not in value:
                return f"`{_join(where, key)}` is required."
        for key, sub in properties.items():
            if key in value and (said := _check(value[key], sub, _join(where, key))):
                return said
    if expected == "array" and "items" in rule:
        for i, item in enumerate(value):
            if said := _check(item, rule["items"], f"{where}[{i}]"):
                return said
    return None


_A = {"object": "a table", "array": "a list", "string": "a string", "boolean": "true or false",
      "integer": "a whole number"}


def _is(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, _TYPES.get(expected, object))


def _join(where: str, key: str) -> str:
    return f"{where}.{key}" if where else key
