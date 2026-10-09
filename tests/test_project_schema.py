"""R6.8: a JSON Schema for `.security-scan.toml` (D10), and `doctor` names the
first invalid key.

The schema ships in the package for editors and for `doctor`, which checks a
project's file with it; the shim has no dependencies, so its validator covers
the schema's own subset, and this test holds the two together. Every example the
README gives, the repository's own file and `init`'s starter all validate.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

from valvur import project_schema

REPO = Path(__file__).resolve().parents[1]


def _readme_examples() -> list[str]:
    from user_docs import user_docs

    blocks = re.findall(r"```toml\n(.*?)```", user_docs(), re.S)
    return [b for b in blocks if "[scan]" in b or "[[suppress]]" in b]


def test_the_schema_is_json_schema_and_ships_in_the_package():
    schema = json.loads(project_schema.PATH.read_text())

    assert schema["$schema"].startswith("https://json-schema.org/")
    assert set(schema["properties"]) == {"scan", "suppress"}
    assert schema["additionalProperties"] is False


def test_every_example_the_readme_gives_validates():
    examples = _readme_examples()

    assert examples, "the README gives no .security-scan.toml example"
    for example in examples:
        assert project_schema.problem(tomllib.loads(example)) is None, example


def test_the_repositorys_own_file_and_inits_starter_validate(tmp_path):
    from valvur import initialize

    own = tomllib.loads((REPO / ".security-scan.toml").read_text())
    (tmp_path / "app.py").write_text("x = 1\n")
    starter = tomllib.loads(initialize.starter(tmp_path))

    assert project_schema.problem(own) is None
    assert project_schema.problem(starter) is None


@pytest.mark.parametrize(("text", "named"), [
    ('[scan]\nexclud = ["data"]\n', "scan.exclud"),
    ('[scan]\nexclude = "data"\n', "scan.exclude"),
    ('[scan]\nscope = "everything"\n', "scan.scope"),
    ('[[suppress]]\nrule = "r"\npath = "p"\nexpires = 2027-01-01\nreason = "r"\n',
     "suppress[0].fingerprint"),
    ('[scna]\n', "scna"),
])
def test_the_first_invalid_key_is_named(text, named):
    said = project_schema.problem(tomllib.loads(text))

    assert said is not None and said.startswith(f"`{named}`"), said


def test_doctor_names_the_first_invalid_key(tmp_path):
    from valvur import doctor

    (tmp_path / ".security-scan.toml").write_text('[scan]\nexclud = ["data"]\n')

    [line] = [c for c in doctor.run(tmp_path) if c.name == "project file"]

    assert line.level == "warn" and "`scan.exclud`" in line.detail
