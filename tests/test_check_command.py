"""R12.2: `valvur check`, the ninth command (D28, F3.16).

`valvur check <ecosystem> <name>[@version] …` prints each package's answer and exits 0
when none is flagged, 1 when any is, and 2 on an error, so a pre-install hook or a CI
step can stop on it. `--json` gives the answers as `check_package` does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import cli
from valvur.name_index import malicious

FIXTURE = Path(__file__).parent / "fixtures" / "malicious-packages"


@pytest.fixture(autouse=True)
def index(name_index):
    directory = name_index(pip=["requests", "flask"], npm=["react", "atez"])
    assert malicious._main(["build-malicious", str(directory), str(FIXTURE)]) == 0
    return directory


def test_every_package_real_exits_zero_and_says_each(capsys):
    assert cli.main(["check", "pip", "requests", "flask@3.0.0"]) == 0

    out = capsys.readouterr().out
    assert "exists" in out and "pip requests" in out and "pip flask@3.0.0" in out


def test_any_package_flagged_exits_one_and_names_why(capsys):
    assert cli.main(["check", "pip", "requests", "reqeusts"]) == 1

    out = capsys.readouterr().out
    assert "near-miss" in out and "'requests'" in out
    assert "1 of 2 flagged" in out


def test_a_malicious_npm_package_exits_one(capsys):
    assert cli.main(["check", "npm", "atez"]) == 1
    assert "MAL-2022-1153" in capsys.readouterr().out


def test_more_than_fifty_is_an_error_that_exits_two(capsys):
    assert cli.main(["check", "pip", *[f"p{i}" for i in range(51)]]) == 2
    assert "at most 50" in capsys.readouterr().err


def test_json_gives_the_answers_as_the_tool_does(capsys):
    assert cli.main(["check", "npm", "react@18.2.0", "atez", "--json"]) == 1

    reply = json.loads(capsys.readouterr().out)
    assert [a["verdict"] for a in reply["answers"]] == ["exists", "malicious"]
    assert reply["answers"][0]["version"] == "18.2.0"
    assert reply["flagged"] == 1


def test_the_projects_registry_configuration_is_read_from_project(tmp_path, capsys):
    project = tmp_path / "p"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "--extra-index-url https://pypi.acme.example/simple\n")

    assert cli.main(["check", "pip", "acme-billing", "--project", str(project)]) == 1
    assert "confusion" in capsys.readouterr().out
