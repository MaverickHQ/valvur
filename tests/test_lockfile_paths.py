"""R50.7: one dependency Finding lists every lockfile it was found through (D82n, ADR-0036).

A dependency vulnerability's identity is its ecosystem, package, version and advisory
(`CLAUDE.md` §8), so the same advisory through two lockfiles has always been one Finding. It
kept the first lockfile and dropped the other, and a reader who fixed the one named saw the
Finding stay. It now names each, sorted. Its Fingerprint, which has never held a path, is
what it was, and so is `path`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api, operations
from valvur.engine_host import LocalRuntime
from valvur.findings import Dependency, Finding
from valvur.invocation import Invocation

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"
CVE = "CVE-2026-0001"
#: `fingerprint.derive("pip", "requests", "2.19.1", CVE)`, written down before this change.
FINGERPRINT = "13594a29ba60bfed11ac4ffec4559a7d"


def _through(lockfile: str, source: str) -> Finding:
    return Finding(rule=CVE, path=lockfile, line=0, title="requests: a flaw", severity="high",
                   fingerprint=FINGERPRINT, sources=(source,),
                   dependency=Dependency(ecosystem="pip", package="requests", version="2.19.1"))


class _Scanner:
    artifact = None
    kind = "scanner"
    version = "1"
    network = False

    def __init__(self, name: str, found: list[Finding]):
        self.name, self.found = name, found

    def applies_to(self, workspace, context=None):
        return True, ""

    def for_profile(self, *, network):
        return self

    def command(self, workspace):
        return Invocation(tool=self.name, version="1", report=f"{self.name}.json", timeout=60,
                          argv=("fake-report", "0", "{}", f"/results/{self.name}.json"))

    def parse(self, output):
        return list(self.found)


@pytest.fixture
def scanned(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    ws = tmp_path / "ws"
    for name in ("services/api/requirements.txt", "requirements.txt", "worker/requirements.txt"):
        (ws / name).parent.mkdir(parents=True, exist_ok=True)
        (ws / name).write_text("requests==2.19.1\n")
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[_Scanner("trivy", [
        _through("services/api/requirements.txt", "trivy"),
        _through("requirements.txt", "trivy"),
        _through("worker/requirements.txt", "trivy")])])
    return ws


def test_an_advisory_through_three_lockfiles_is_one_finding_that_names_each(scanned):
    [record] = json.loads((scanned / RESULTS / "findings.json").read_text())["findings"]

    assert record["fingerprint"] == FINGERPRINT
    assert record["dependency"]["paths"] == [
        "requirements.txt", "services/api/requirements.txt", "worker/requirements.txt"]


def test_its_path_is_what_it_was(scanned):
    [record] = json.loads((scanned / RESULTS / "findings.json").read_text())["findings"]

    assert record["path"] == "services/api/requirements.txt", "the first reported, as before"


def test_sarif_carries_a_location_for_each(scanned):
    sarif = json.loads((scanned / RESULTS / "results.sarif").read_text())
    [result] = sarif["runs"][0]["results"]

    assert [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in result["locations"]] \
        == ["services/api/requirements.txt", "requirements.txt", "worker/requirements.txt"]
    assert result["partialFingerprints"]


def test_the_reply_carries_the_paths_and_its_schema_is_still_two(scanned):
    from valvur.mcp.tools import registry

    _text, reply = operations.findings_reply({"workspace": str(scanned)})

    [entry] = reply["findings"]
    assert entry["paths"] == ["requirements.txt", "services/api/requirements.txt",
                              "worker/requirements.txt"]
    assert entry["path"] == "services/api/requirements.txt"
    # Additive: the reply's schema is 2, as it was (ADR-0024).
    [scan] = [t for t in registry() if t.name == "scan"]
    assert scan.output_schema["properties"]["schema"] == {"const": 2}
    [tool] = [t for t in registry() if t.name == "findings"]
    entry_shape = tool.output_schema["properties"]["findings"]["items"]["properties"]
    assert entry_shape["paths"] == {"type": "array", "items": {"type": "string"},
                                    "description": entry_shape["paths"]["description"]}


def test_a_finding_through_one_lockfile_has_no_paths(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.19.1\n")
    api.scan(ws, runner=LocalRuntime(FAKE_TOOLS),
             adapters=[_Scanner("trivy", [_through("requirements.txt", "trivy")]),
                       _Scanner("osv-scanner", [_through("requirements.txt", "osv-scanner")])])

    [record] = json.loads((ws / RESULTS / "findings.json").read_text())["findings"]
    assert "paths" not in record["dependency"] and record["sources"] == ["trivy", "osv-scanner"]
    _text, reply = operations.findings_reply({"workspace": str(ws)})
    assert "paths" not in reply["findings"][0]
