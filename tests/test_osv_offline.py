"""R4.6: OSV-Scanner's offline database on `offline` (F3.2; D8, ADR-0023).

R4.1 measured it: with `--network=none` and the npm database fetched once (207 MB),
OSV-Scanner reported repository 8's `@hyperion-util/cookies` as MAL-2023-1. So the
database is fetched, for the ecosystems in the File Set and only when absent, into
the host cache in the layout OSV-Scanner reads, and recorded like Trivy's; the
network is faked, as everywhere in this suite.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from valvur import osv_offline


def _words(said: list[str]):
    """A progress callback keeping each event's words."""
    return lambda event: said.append(str(event))



@pytest.fixture
def cache_root(tmp_path, monkeypatch):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    return tmp_path / "cache"


def test_the_file_sets_lockfiles_name_the_databases_needed():
    files = ["package-lock.json", "api/requirements.txt", "svc/Cargo.lock", "go.mod",
             "README.md", "web/package.json"]
    assert osv_offline.needed(files) == ["Go", "PyPI", "crates.io", "npm"]
    assert osv_offline.needed(["README.md"]) == []


def test_an_absent_database_is_fetched_into_the_layout_osv_scanner_reads(cache_root):
    asked: list[str] = []

    def opener(url, timeout):
        asked.append(url)
        return io.BytesIO(b"PK\x03\x04 a zip")

    record = osv_offline.fetch("npm", opener=opener)
    assert asked == [f"{osv_offline.base_url()}/npm/all.zip"]
    stored = cache_root / "osv" / "osv-scalibr" / "npm" / "all.zip"
    assert stored.read_bytes() == b"PK\x03\x04 a zip"
    assert record["what"] == "OSV database (npm)" and record["source"] == asked[0]
    assert osv_offline.absent(["npm", "PyPI"]) == ["PyPI"]


def test_a_failed_fetch_leaves_nothing_half_written(cache_root):
    def opener(url, timeout):
        raise OSError("unreachable")

    with pytest.raises(OSError):
        osv_offline.fetch("PyPI", opener=opener)
    assert not (cache_root / "osv" / "osv-scalibr" / "PyPI").exists() or not any(
        (cache_root / "osv" / "osv-scalibr" / "PyPI").iterdir())
    assert osv_offline.absent(["PyPI"]) == ["PyPI"]


def test_offline_runs_osv_against_the_cache_with_no_network(tmp_path):
    from valvur import profiles
    from valvur.adapters import DEFAULT_ADAPTERS

    [osv] = [a for a in profiles.select(DEFAULT_ADAPTERS, profiles.OFFLINE)
             if a.name == "osv-scanner"]
    invocation = osv.command(tmp_path)
    assert invocation.network is False
    assert "--offline-vulnerabilities" in invocation.argv
    assert ("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/cache/osv") in invocation.env
    [networked] = [a for a in profiles.select(DEFAULT_ADAPTERS, profiles.FULL)
                   if a.name == "osv-scanner"]
    assert networked.command(tmp_path).network is True
    assert profiles.not_run(profiles.OFFLINE) == ()


def test_the_scan_container_mounts_the_osv_cache_read_only(tmp_path, monkeypatch):
    from valvur import cache
    from valvur.engine_host import ContainerRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    argv = ContainerRuntime(image="x/y:1", runtime="/usr/local/bin/docker").command(tmp_path)
    mounts = [argv[i + 1] for i, flag in enumerate(argv) if flag == "-v"]
    assert f"{tmp_path / 'cache' / 'osv'}:/cache/osv:ro" in mounts


def test_a_malicious_package_advisory_is_critical():
    import json

    from valvur.adapters import OsvAdapter
    from valvur.findings import Severity
    from valvur.invocation import ScannerOutput

    lockfile = {"path": "/workspace/package-lock.json", "type": "lockfile"}
    report = {"results": [{"source": lockfile,
                           "packages": [{"package": {"name": "@hyperion-util/cookies",
                                                     "version": "77.77.79",
                                                     "ecosystem": "npm"},
                                         "vulnerabilities": [{
                                             "id": "MAL-2023-1",
                                             "summary": "Malicious code"}]}]}]}
    [finding] = OsvAdapter().parse(ScannerOutput("osv-scanner", "2.6.0", json.dumps(report), "", 0))
    assert finding.rule == "MAL-2023-1" and finding.severity is Severity.CRITICAL
    assert finding.path == "package-lock.json"


def test_a_first_offline_scan_fetches_what_the_file_set_needs_and_records_it(
        cache_root, tmp_path, monkeypatch):
    from valvur import api, cache
    from valvur.adapters import OsvAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "db_present", lambda: True)
    monkeypatch.setattr(cache, "name_index_present", lambda: True)
    fetched: list[str] = []

    def fake_fetch(name, opener=None):
        fetched.append(name)
        path = osv_offline.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"zip")
        return {"what": f"OSV database ({name})", "source": "u", "size_mb": 1, "seconds": 0.1}

    monkeypatch.setattr(osv_offline, "fetch", fake_fetch)

    class Runtime(LocalRuntime):
        fetches = True                 # it fetches before a scan (24.1)

        def update_db(self):                      # a runtime that can fetch
            raise AssertionError("the Trivy database is present")

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "package-lock.json").write_text('{"packages": {}}')
    said: list[str] = []
    run = api.scan(ws, runner=Runtime(Path(__file__).parent / "fixtures" / "fake-tools"),
                   adapters=[OsvAdapter().for_profile(network=False)], on_progress=_words(said))
    assert fetched == ["npm"]
    assert any(r["what"] == "OSV database (npm)" for r in run.fetched)
    assert any(line.startswith("fetching the OSV database for npm") for line in said), said
