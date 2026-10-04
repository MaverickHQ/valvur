"""R27.4: every crash the fuzzers found, fixed, with the input that found it (D63c).

Each parser of untrusted text answers for any input: a lockfile of the wrong shape
holds no pins, a `.security-scan.toml` that is not UTF-8 or not the right shape is a
problem reported and the defaults used, and results that are not valvur's are a
gate that refuses, never an exception. Found by `fuzz/` under atheris, 60 s each, on
2026-10-04, and by reading the code beside each crash for its siblings.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# The module behind the package's `locked` function. Importing it by name would set
# the package's `locked` to the module and break every later `ecosystems.locked()`
# in this process, so the function is resolved first, the package's way.
from valvur import ecosystems, exclusions, gate, suppressions
from valvur.results import RESULTS_DIR

ecosystems.locked  # noqa: B018 — resolves the function, which imports its module
locked = sys.modules["valvur.ecosystems.locked"]


@pytest.mark.parametrize("name,text", [
    ("package-lock.json", '{"packages": [1]}'),
    ("package-lock.json", '{"dependencies": [1]}'),
    ("package.json", '{"dependencies": [1]}'),
    ("Pipfile.lock", '{"default": [1]}'),
    ("poetry.lock", "package = 1"),
    ("uv.lock", '[[package]]\nname = 1\nversion = []'),
    ("composer.lock", '{"packages": {"a": 1}}'),
])
def test_a_lockfile_of_the_wrong_shape_holds_no_pins_and_raises_nothing(tmp_path, name, text):
    (tmp_path / name).write_text(text)

    pins = locked.locked(tmp_path)

    assert all(isinstance(v, str) for _, name_, v, _ in pins for v in (name_, v))


@pytest.mark.parametrize("data", [b"\xdc", b"[scan]\nexclude = 5", b"scan = 3",
                                  b"suppress = 3", b"suppress = [1, 'x']"])
def test_a_project_file_that_cannot_be_used_is_a_problem_not_an_exception(tmp_path, data):
    (tmp_path / ".security-scan.toml").write_bytes(data)

    settings = exclusions.load_scan_settings(tmp_path)
    policy = suppressions.load(tmp_path)

    assert isinstance(settings.exclude, tuple)
    if data.startswith((b"\xdc", b"suppress")):
        assert policy.problems, "the file's problem goes unreported"


@pytest.mark.parametrize("text", ["7", "[]", '{"findings": [1, "x", null]}',
                                  '{"findings": {"a": 1}}',
                                  '{"findings": [{"severity": 5, "rule": []}]}'])
def test_results_that_are_not_valvurs_are_a_gate_that_refuses(tmp_path, text):
    results = tmp_path / RESULTS_DIR
    results.mkdir()
    (results / "run.json").write_text(json.dumps({"complete": True, "status": "findings"}))
    (results / "findings.json").write_text(text)

    verdict = gate.evaluate(tmp_path, fail_on="any")

    assert verdict.exit_code == 2
    assert "findings.json" in " ".join(verdict.failures)


def test_the_fuzzers_seeds_carry_every_crash_found(tmp_path):
    """So a fuzzer starts from what once broke its target."""
    import importlib.util

    fuzz = Path(__file__).resolve().parent.parent / "fuzz"
    seeds = {}
    for path in fuzz.glob("fuzz_*.py"):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        seeds[path.stem] = module.SEEDS
    assert b"\xdc" in seeds["fuzz_project_config"]
    assert b"7" in seeds["fuzz_findings"]
    assert b"\x00" + b'{"packages": [1]}' in seeds["fuzz_lockfiles"]


@pytest.mark.parametrize("text", ["7", "[]", '{"findings": [1]}', '{"findings": [], "groups": 3}'])
def test_the_scan_reply_over_results_that_are_not_valvurs_raises_nothing(tmp_path, text):
    from valvur import reply

    results = tmp_path / RESULTS_DIR
    results.mkdir()
    (results / "run.json").write_text(json.dumps({"complete": True, "status": "findings"}))
    (results / "findings.json").write_text(text)

    fields = reply.fields(tmp_path)

    assert fields["state"] == "done" and reply.next_moves(tmp_path) == []
    assert isinstance(reply.text(fields), str)
