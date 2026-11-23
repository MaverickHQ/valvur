"""R51.6: `sbom.cdx.json` holds to the CycloneDX schema of the version it declares.

Dependency-Track and every other reader of an SBOM validates it, or fails on it later. A
scan's SBOM is validated here against the published schema, vendored, of its own
`specVersion`: 1.7 from Syft 1.57.1.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import PINNED_VERSIONS, golden
from cyclonedx import NoSchema, validate

from valvur.adapters import GitleaksAdapter, SyftAdapter
from valvur.engine_host import LocalRuntime
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


def test_a_document_with_a_required_field_removed_fails():
    import jsonschema

    document = json.loads(golden("syft"))
    validate(document)

    del document["bomFormat"]
    with pytest.raises(jsonschema.ValidationError, match="bomFormat"):
        validate(document)


def test_a_component_with_no_name_fails():
    """One level down: the schema is followed into a component, not only the root."""
    import jsonschema

    document = json.loads(golden("syft"))
    del document["components"][0]["name"]

    with pytest.raises(jsonschema.ValidationError, match="name"):
        validate(document)


def test_a_licence_that_is_no_spdx_id_fails():
    """The schema's reference to SPDX's list resolves, from the vendored copy."""
    import jsonschema

    document = json.loads(golden("syft"))
    document["components"][0]["licenses"] = [{"license": {"id": "Not-A-Licence-1.0"}}]

    with pytest.raises(jsonschema.ValidationError):
        validate(document)


def test_a_version_with_no_vendored_schema_is_refused_by_name():
    document = json.loads(golden("syft"))
    document["specVersion"] = "9.9"

    with pytest.raises(NoSchema, match=r"CycloneDX 9\.9"):
        validate(document)


class _SyftFromItsGolden(SyftAdapter):
    """Syft's adapter, with its command writing the committed golden: what Syft 1.57.1
    wrote for the fixture."""

    def command(self, workspace):
        return Invocation(tool=self.name, version=PINNED_VERSIONS["syft"], report="sbom.json",
                          timeout=60, argv=("fake-report", "0", golden("syft"),
                                            "/results/sbom.json"))


def test_the_sbom_a_scan_writes_holds_to_its_schema(tmp_path, monkeypatch):
    from valvur import api, cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS),
             adapters=[GitleaksAdapter(), _SyftFromItsGolden(enabled=True)])

    written = json.loads((ws / ".security-scan" / "sbom.cdx.json").read_text())
    assert (written["bomFormat"], written["specVersion"]) == ("CycloneDX", "1.7")
    assert written["components"]
    validate(written)


@pytest.mark.e2e
def test_the_sbom_syft_itself_writes_holds_to_its_schema(mountable_tmp):
    """Once against the image: the golden is a copy, and Syft is what users run."""
    from valvur import api
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.19.1\nurllib3==1.24.1\n")
    api.scan(ws, runner=ContainerRuntime(), adapters=[SyftAdapter(enabled=True)],
             profile="offline")

    written = json.loads((ws / ".security-scan" / "sbom.cdx.json").read_text())
    assert {c["name"] for c in written["components"]} >= {"requests", "urllib3"}
    validate(written)
