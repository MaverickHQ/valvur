"""Supportability (28.3.6, O2): what a bug report needs, without a source tree.

Three things nothing offered: the command line behind each Scanner's raw output
(`run.json` recorded a version and a duration, and the Invocation held the argv
the snapshots prove stable), a way to see the container commands as they run,
and a way to hand a maintainer the facts of a failed scan without handing over
the repository.
"""

from __future__ import annotations

import json
import subprocess
import tarfile
from pathlib import Path

from valvur import doctor, provenance
from valvur import runner as _runner
from valvur.api import ScanRun
from valvur.invocation import Invocation, ScannerOutput
from valvur.provenance import ScannerRun

# ------------------------------------------------------- argv on every surface

def test_the_runner_records_the_argv_it_launched_on_the_output(tmp_path, monkeypatch):
    launched: list[list[str]] = []

    def fake_launch(self, cmd, **kwargs):
        launched.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr="")

    monkeypatch.setattr(_runner.ContainerRunner, "_launch", fake_launch)
    monkeypatch.setattr(_runner.ContainerRunner, "_base_flags", lambda self, *a, **k: ["run"])
    container = _runner.ContainerRunner(runtime="/usr/local/bin/docker", image="valvur:test")
    invocation = Invocation(tool="gitleaks", version="8.30.1",
                            argv=("gitleaks", "dir", "/workspace", "--report-format", "json"))

    output = container.run(invocation, tmp_path)

    assert output.argv == invocation.argv
    assert launched and launched[0][-5:] == list(invocation.argv), \
        "the argv launched is the argv recorded"


def test_a_scanner_run_carries_the_argv_of_the_output_it_came_from():
    from valvur.adapters.gitleaks import GitleaksAdapter
    from valvur.api import _outcome

    output = ScannerOutput("gitleaks", "8.30.1", "[]", "", 0,
                           argv=("gitleaks", "dir", "/workspace"))

    outcome = _outcome(GitleaksAdapter(), output)

    assert outcome.scanner.argv == ("gitleaks", "dir", "/workspace")


def test_run_json_records_each_scanners_command_line():
    run = ScanRun(findings=[], profile="offline", scanners=[
        ScannerRun("gitleaks", ok=True, version="8.30.1",
                   argv=("gitleaks", "dir", "/workspace", "--report-format", "json")),
        ScannerRun("checkov", ok=True, skipped=True, reason="no infrastructure to analyse"),
    ])

    scanners = json.loads(provenance.render(run))["scanners"]

    assert scanners[0]["argv"] == ["gitleaks", "dir", "/workspace", "--report-format", "json"]
    assert scanners[1]["argv"] == [], "a Scanner that did not run launched nothing"


# ------------------------------------------------------------- VALVUR_DEBUG=1

def test_debug_echoes_each_container_command_to_stderr_and_only_then(monkeypatch, capsys):
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    container = _runner.ContainerRunner(runtime="/usr/local/bin/docker", image="valvur:test")

    monkeypatch.delenv(_runner.DEBUG_ENV, raising=False)
    container._launch(["/usr/local/bin/docker", "run", "--rm", "valvur:test", "true"])
    assert capsys.readouterr().err == "", "silent unless asked"

    monkeypatch.setenv(_runner.DEBUG_ENV, "1")
    container._launch(["/usr/local/bin/docker", "run", "--rm", "valvur:test", "true"])
    err = capsys.readouterr().err
    assert err.startswith("valvur: /usr/local/bin/docker run --rm valvur:test true"), err
    assert len(calls) == 2, "the echo is beside the launch, never instead of it"


# ----------------------------------------------------------- doctor --bundle

ALLOWED = {"doctor.txt", "versions.txt", "run.json"}


def _members(archive: Path) -> dict[str, bytes]:
    with tarfile.open(archive, "r:gz") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers()  # type: ignore[union-attr]
                if m.isfile()}


def test_the_bundle_holds_the_report_the_versions_and_the_last_run_and_nothing_else(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "app.py").write_text("SECRET = 'AKIA...'\n")
    results = workspace / ".security-scan"
    results.mkdir()
    (results / "run.json").write_text('{"schema": 1, "status": "clean"}')
    (results / "raw").mkdir()
    (results / "raw" / "gitleaks.json").write_text('[{"Secret": "AKIA..."}]')
    (results / "findings.json").write_text('{"findings": []}')
    checks = [doctor.Check("runtime", "ok", "docker 29"),
              doctor.Check("image", "fail", "absent", "pull")]

    archive = doctor.bundle(workspace, checks, tmp_path / "out")
    members = _members(archive)

    assert archive.name.startswith("valvur-doctor-") and archive.suffix == ".gz"
    assert set(members) == ALLOWED, sorted(members)
    assert b"image" in members["doctor.txt"] and b"absent" in members["doctor.txt"]
    assert b"valvur " in members["versions.txt"] and b"python " in members["versions.txt"]
    assert json.loads(members["run.json"]) == {"schema": 1, "status": "clean"}
    joined = b"".join(members.values())
    assert b"AKIA" not in joined and b"app.py" not in joined, \
        "the bundle carries source or raw output"


def test_the_bundle_without_a_scan_says_so_rather_than_inventing_one(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()

    members = _members(doctor.bundle(workspace, [doctor.Check("runtime", "ok", "docker 29")],
                                     tmp_path / "out"))

    assert set(members) == {"doctor.txt", "versions.txt"}
    assert b"no scan" in members["doctor.txt"].lower()


def test_the_cli_writes_the_bundle_beside_the_report(tmp_path, capsys, monkeypatch):
    from valvur.cli import main

    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setattr(doctor, "run",
                        lambda ws, network=False: [doctor.Check("runtime", "ok", "x")])
    out = tmp_path / "bundles"

    assert main(["doctor", str(workspace), "--bundle", str(out)]) == 0
    text = capsys.readouterr().out

    [archive] = list(out.glob("valvur-doctor-*.tar.gz"))
    assert str(archive) in text
    assert "never source" in text.lower() or "no source" in text.lower()
