"""R50.3: `valvur gate --new-since <ref>` fails on new Findings only (D82k, D82l, ADR-0034).

A project with years of Findings cannot adopt a gate that fails on all of them on its first
day. So the gate can compare with a base: it scans the base's tree itself, with
`scan --ref`, into the cache, and a Finding whose Fingerprint the base already has is
*already there* and not gated on. No baseline file: a list of accepted Findings in git
would be scan output in git.

Everything else about the gate stands. An incomplete Scan Run of either tree fails it, a
lapsed Suppression fails it, and two Scan Runs that did not use the same image, Profile and
data are not compared.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_scan_ref import FAKE_TOOLS, KEY, RESULTS, _commit, _git, _write

from valvur import cli, gate


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """`v1` holds `old.env`. The working tree, scanned, holds it and `new.env`."""
    from valvur import api, cache, engine_host
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(engine_host, "for_scan", lambda: LocalRuntime(FAKE_TOOLS))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {"old.env": f"KEY={KEY['old']}\n", ".gitignore": ".security-scan/\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "one")
    _git(root, "tag", "v1")
    _write(root, {"new.env": f"KEY={KEY['new']}\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "two")
    assert cli.main(["scan", str(root)]) in (0, 1)
    return root


def _gate(repo: Path, capsys, *args: str) -> tuple[int, str]:
    capsys.readouterr()
    code = cli.main(["gate", str(repo), "--fail-on", "any", *args])
    return code, capsys.readouterr().out


def test_without_the_option_the_gate_is_what_it_was(repo, capsys):
    code, said = _gate(repo, capsys)

    assert code == 1 and "old.env" in said and "new.env" in said
    assert "gate: 2 finding(s) at or above any" in said and "since" not in said


def test_a_finding_the_base_has_passes_and_one_it_has_not_fails(repo, capsys):
    code, said = _gate(repo, capsys, "--new-since", "v1")

    assert code == 1
    failures = [line for line in said.splitlines() if " in " in line and "—" in line]
    assert len(failures) == 1 and "new.env" in failures[0]


def test_the_output_names_the_base_its_commit_and_what_was_not_gated_on(repo, capsys):
    _code, said = _gate(repo, capsys, "--new-since", "v1")

    commit = _git(repo, "rev-parse", "v1")[:7]
    assert (f"gate: 1 new finding(s) at or above any since v1 ({commit}); 1 were already "
            "there and were not gated on") in said


def test_every_finding_old_passes(repo, capsys):
    code, said = _gate(repo, capsys, "--new-since", "HEAD")

    assert code == 0 and "gate: passed" in said
    assert "gate: 0 new finding(s) at or above any since HEAD" in said
    assert "2 were already there" in said


def test_a_finding_suppressed_in_the_base_and_active_now_was_already_there(repo, capsys):
    [old] = [f for f in json.loads((repo / RESULTS / "findings.json").read_text())["findings"]
             if f["path"] == "old.env"]
    _commit(repo, "accepting", {".security-scan.toml": (
        f'[[suppress]]\nfingerprint = "{old["fingerprint"]}"\nrule = "{old["rule"]}"\n'
        'path = "old.env"\nexpires = 2099-01-01\nreason = "a key for the test"\n')})

    code, said = _gate(repo, capsys, "--new-since", "accepting")

    assert code == 1 and "old.env" not in said.split("gate:")[0]
    assert "1 were already there" in said


def test_a_ref_that_does_not_resolve_fails_the_gate_and_names_the_fetch_depth(repo, capsys):
    code, said = _gate(repo, capsys, "--new-since", "origin/main")

    assert code == 1
    assert "`origin/main` names no commit" in said and "fetch-depth: 0" in said
    assert "gate: FAILED" in said


def test_a_second_gate_on_the_same_base_runs_no_scanner_for_it(repo, capsys, monkeypatch):
    from valvur import service

    scans = []
    real = service.run_scan
    monkeypatch.setattr(service, "run_scan",
                        lambda *a, **kw: (scans.append(kw.get("ref")), real(*a, **kw))[1])

    first = _gate(repo, capsys, "--new-since", "v1")
    second = _gate(repo, capsys, "--new-since", "v1")

    assert scans == ["v1"] and first == second


def test_a_dataset_that_changed_makes_the_base_scan_run_again(repo, capsys, monkeypatch):
    """The working tree was scanned again on newer data: the base's result, which rests
    on the older copy, is not reused. Here the newer copy is only in the record, so the
    base scanned again still differs, and the gate says the two cannot be compared."""
    from valvur import service

    scans = []
    real = service.run_scan
    monkeypatch.setattr(service, "run_scan",
                        lambda *a, **kw: (scans.append(kw.get("ref")), real(*a, **kw))[1])
    _gate(repo, capsys, "--new-since", "v1")
    path = repo / RESULTS / "run.json"
    record = json.loads(path.read_text())
    record["data_built"] = {"database": 1_800_000_000}
    path.write_text(json.dumps(record))

    code, said = _gate(repo, capsys, "--new-since", "v1")

    assert scans == ["v1", "v1"]
    assert code == 1 and "cannot be compared" in said and "data: database" in said


def test_under_github_actions_only_the_new_findings_are_annotations(repo, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    _code, said = _gate(repo, capsys, "--new-since", "v1")

    annotated = [line for line in said.splitlines() if line.startswith("::error::")]
    assert len(annotated) == 1 and "new.env" in annotated[0]


# ---- the reader: two Results Folders, one doctored


def _base(repo: Path, tmp_path: Path, capsys, **doctored) -> gate.Base:
    out = tmp_path / "base"
    cli.main(["scan", str(repo), "--ref", "HEAD", "--out", str(out)])
    capsys.readouterr()
    record = json.loads((out / RESULTS / "run.json").read_text())
    record.update(doctored)
    (out / RESULTS / "run.json").write_text(json.dumps(record))
    return gate.Base("HEAD", _git(repo, "rev-parse", "HEAD"), out)


def test_an_incomplete_scan_run_of_the_base_fails_it(repo, tmp_path, capsys):
    verdict = gate.evaluate(repo, fail_on="any", base=_base(repo, tmp_path, capsys, complete=False))

    assert verdict.exit_code == 1
    assert any("the Scan Run of the base HEAD" in f and "incomplete" in f
               for f in verdict.failures)


@pytest.mark.parametrize("doctored, named", [
    ({"profile": "full"}, "Profile: offline here, full for the base"),
    ({"build": {"shim": "x", "image": "another-image"}}, "image"),
    ({"data_built": {"database": 1_700_000_000}}, "data: database"),
])
def test_two_scan_runs_that_differ_are_not_compared(repo, tmp_path, capsys, doctored, named):
    verdict = gate.evaluate(repo, fail_on="any", base=_base(repo, tmp_path, capsys, **doctored))

    assert verdict.exit_code == 1
    [said] = [f for f in verdict.failures if "cannot be compared" in f]
    assert named in said and "scan the working tree again" in said


def test_a_lapsed_suppression_fails_it_though_every_finding_is_old(repo, tmp_path, capsys):
    path = repo / RESULTS / "findings.json"
    document = json.loads(path.read_text())
    document["findings"].append({"rule": "valvur.suppression.expired", "path":
                                 ".security-scan.toml", "title": "a Suppression expired",
                                 "severity": "low", "fingerprint": "f" * 32,
                                 "suppressed": None, "sources": ["valvur"]})
    path.write_text(json.dumps(document))

    verdict = gate.evaluate(repo, fail_on="high", base=_base(repo, tmp_path, capsys))

    assert verdict.exit_code == 1
    assert any("lapsed suppression" in f for f in verdict.failures)


def test_each_dataset_has_the_instant_it_was_built_and_an_absent_one_has_none(
        tmp_path, monkeypatch):
    from valvur import cache, osv_offline, staleness

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    path = osv_offline.path("PyPI")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"zip")

    built = staleness.data_built(provider=None, osv=["PyPI", "npm"])

    assert abs(built["osv PyPI"] - path.stat().st_mtime) <= 2
    assert "osv npm" not in built


def test_two_instants_a_moment_apart_are_one_copy():
    run = {"profile": "offline", "data_built": {"database": 1_700_000_000}}

    assert gate.differences(run, {**run, "data_built": {"database": 1_700_000_003}}) == []
    assert gate.differences(run, {**run, "data_built": {"database": 1_700_000_090}}) == [
        "data: database is not the same copy in both"]
    assert gate.differences(run, {**run, "data_built": {}}) == [
        "data: database is not the same copy in both"]
