"""The scripts that judge a scan from outside call it the way the product does.

R3.9 made the Scan Container the only way a scan runs, and two scripts kept the
old runner: the corpus, whose weekly run then scanned nothing, and the offline
verification, the reviewer's independent check of the moat's first claim, which
then failed on a signature. Neither is imported by the package, so only a test
that runs them notices.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_offline_check_reads_the_scan_containers_own_command(monkeypatch, tmp_path,
                                                                 capsys):
    from valvur import runner

    monkeypatch.setenv("VALVUR_CACHE", str(tmp_path / "cache"))
    # The runtime is faked: the flags are what is judged, not the machine's memory.
    monkeypatch.setattr(runner, "runtime_resources", lambda runtime: (None, None))
    monkeypatch.setattr(runner, "memory_ceiling_note", lambda runtime: None)
    verify = _load("verify-offline.py")

    assert verify.check_containers_have_no_network() is True
    said = capsys.readouterr().out
    assert "[PASS] the Scan Container is launched with --network=none" in said
    assert "FAIL" not in said


def test_the_corpus_scans_through_a_runtime_the_scan_accepts(monkeypatch, tmp_path):
    from valvur import api, cache

    corpus = _load("corpus.py")
    handed = []
    monkeypatch.setattr(cache, "name_index_present", lambda: True)
    monkeypatch.setattr(api, "scan", lambda target, runner, profile: handed.append(runner))
    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "run.json").write_text("{}")
    (results / "findings.json").write_text('{"findings": []}')

    corpus._scan(tmp_path, "offline")

    [runner] = handed
    from valvur.engine_host import RuntimeDefaults

    assert isinstance(runner, RuntimeDefaults) and runner.engine is True, type(runner).__name__
