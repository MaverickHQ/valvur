"""R51.5: `imports.yml`, which measures what DefectDojo and Dependency-Track keep (D82p).

It starts both tools from their published images and imports a scan of the fixture through
each one's own API. It runs when a person dispatches it and at no other time, holds no
secret, is granted nothing beyond reading the repository, and starts nothing that is not
pinned by digest. valvur itself uploads nothing: `egress.py` is no part of this.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "imports.yml"
COMPOSE = sorted((REPO / ".github" / "imports").glob("*.compose.yml"))
SCRIPT = REPO / "scripts" / "imports_measure.py"


def _code(text: str) -> str:
    """The workflow less its comments, which may name what the code must not."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_its_only_trigger_is_dispatch():
    code = _code(WORKFLOW.read_text(encoding="utf-8"))
    triggers = code.split("\non:\n", 1)[1].split("\n\n", 1)[0]

    assert triggers.strip() == "workflow_dispatch:"


def test_it_holds_no_secret_and_is_granted_only_a_read_of_the_repository():
    code = _code(WORKFLOW.read_text(encoding="utf-8"))

    assert "secrets." not in code and "github.token" not in code and "GITHUB_TOKEN" not in code
    assert "\npermissions: {}\n" in code, "nothing is granted to the workflow as a whole"
    grants = re.findall(r"^    permissions:\n((?:      .+\n)+)", code, re.M)
    assert len(grants) == code.count("\n    runs-on:") == 1
    assert grants == ["      contents: read\n"]
    assert "persist-credentials: false" in code


def test_every_action_is_pinned_by_commit():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text(encoding="utf-8"))

    assert uses
    assert all(one.startswith("./.github/actions/")
               or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", one) for one in uses), uses


@pytest.mark.parametrize("compose", COMPOSE, ids=lambda p: p.name)
def test_every_image_a_tool_starts_from_is_pinned_by_digest(compose):
    text = compose.read_text(encoding="utf-8")
    images = re.findall(r"^\s*image:\s*(\S+)", text, re.M)

    assert images and len(COMPOSE) == 2
    assert all(re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", one)
               for one in images), images
    ports = re.findall(r"^\s*ports:\n((?:\s+- .+\n)+)", text, re.M)
    assert ports, "the measurement reaches the tool on a published port"
    for published in re.findall(r"- (.+)", "".join(ports)):
        assert published.strip('"').startswith("127.0.0.1:"), "it listens beyond this machine"


def test_no_key_or_password_of_a_tools_own_is_written_but_its_quickstarts():
    """DefectDojo's two keys come from the environment, made for the run."""
    text = (REPO / ".github" / "imports" / "defectdojo.compose.yml").read_text()

    for key in ("DD_SECRET_KEY", "DD_CREDENTIAL_AES_256_KEY"):
        assert re.search(rf'{key}: "\$\{{{key}:\?', text), key


def test_every_argument_the_workflow_passes_is_one_the_script_takes():
    text = WORKFLOW.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    runs = text.split("python3 scripts/imports_measure.py")[1:]

    assert len(runs) == 2, "one measurement for each tool"
    for run in runs:
        passed = set(re.findall(r"(?<![\w-])(--[a-z][\w-]*)", run.split("\n\n", 1)[0]))
        assert passed >= {"--url", "--results", "--password-file"}
        for flag in passed:
            assert f'"{flag}"' in script, f"imports.yml passes {flag}, which the script lacks"
    assert "defectdojo.compose.yml" in text and "dependency-track.compose.yml" in text


def test_it_scans_the_fixture_with_the_image_built_from_the_tree_and_asks_for_the_sbom():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "docker buildx bake dev" in text and "VALVUR_IMAGE: valvur:dev" in text
    assert "scripts/fixtures.py broken-repo" in text
    assert re.search(r"valvur scan .*--sbom", text)
