"""R14.3: reuse in a scan (D32, N1.5, ADR-0030).

A second scan of an unchanged repository asks neither Trivy nor OSV-Scanner: their
answers are the last scan's, taken from the host cache under the reuse key, and every
fingerprint is the same. `run.json` names each reused result and the run it came
from, so a reader can tell reused from fresh. `--fresh` on the CLI and `fresh: true`
on the `scan` tool run everything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from valvur import api
from valvur.adapters import OsvAdapter, TrivyAdapter
from valvur.engine_host import LocalRuntime

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


@pytest.fixture
def repository_8(tmp_path, monkeypatch) -> Path:
    """Acceptance repository 8's shape, and a log each fake Scanner writes as it runs."""
    root = tmp_path / "8-malicious-dependency"
    root.mkdir()
    (root / "package.json").write_text(json.dumps(
        {"name": "acceptance-8", "dependencies": {"@hyperion-util/cookies": "77.77.79"}}))
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/@hyperion-util/cookies": {"version": "77.77.79"}}}))
    (root / "index.js").write_text("module.exports = 1\n")
    monkeypatch.setenv("FAKE_TOOL_LOG", str(tmp_path / "ran.log"))
    return root


def _ran(root: Path) -> list[str]:
    log = root.parent / "ran.log"
    ran = log.read_text().split() if log.exists() else []
    log.unlink(missing_ok=True)
    return ran


def _scan(root: Path, **kwargs):
    return api.scan(root, runner=LocalRuntime(FAKE_TOOLS),
                    adapters=[TrivyAdapter(), OsvAdapter(offline=True)], **kwargs)


def test_a_second_scan_of_an_unchanged_repository_runs_neither_and_finds_the_same(
        repository_8):
    first = _scan(repository_8)
    assert sorted(_ran(repository_8)) == ["osv-scanner", "trivy"]

    second = _scan(repository_8)

    assert _ran(repository_8) == []
    assert sorted(f.fingerprint for f in second.findings) == \
        sorted(f.fingerprint for f in first.findings)
    assert second.findings


def test_run_json_names_each_reused_result_and_its_run(repository_8):
    first = _scan(repository_8)
    _scan(repository_8)

    record = json.loads((repository_8 / ".security-scan" / "run.json").read_text())
    reused = {s["tool"]: s.get("reused_from") for s in record["scanners"]}

    assert reused == {"trivy": first.generation, "osv-scanner": first.generation}


def test_a_changed_lockfile_runs_them_again(repository_8):
    _scan(repository_8)
    _ran(repository_8)
    (repository_8 / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')

    _scan(repository_8)

    assert sorted(_ran(repository_8)) == ["osv-scanner", "trivy"]


def test_a_changed_source_file_does_not(repository_8):
    _scan(repository_8)
    _ran(repository_8)
    (repository_8 / "index.js").write_text("module.exports = eval(process.argv[2])\n")

    _scan(repository_8)

    assert _ran(repository_8) == []


def test_fresh_runs_everything(repository_8):
    _scan(repository_8)
    _ran(repository_8)

    run = _scan(repository_8, fresh=True)

    assert sorted(_ran(repository_8)) == ["osv-scanner", "trivy"]
    assert not any(s.reused_from for s in run.scanners)


def test_the_cli_and_the_tool_take_fresh(repository_8, monkeypatch):
    from valvur import cli, engine_host
    from valvur.mcp.tools import registry

    monkeypatch.setattr(engine_host, "for_scan", lambda: LocalRuntime(FAKE_TOOLS))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [TrivyAdapter(), OsvAdapter(offline=True)])
    cli.main(["scan", str(repository_8)])
    _ran(repository_8)

    cli.main(["scan", str(repository_8), "--fresh"])

    assert sorted(_ran(repository_8)) == ["osv-scanner", "trivy"]
    scan_tool = next(t for t in registry() if t.name == "scan")
    assert scan_tool.schema["properties"]["fresh"]["type"] == "boolean"
