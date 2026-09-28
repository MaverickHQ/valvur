"""R8.1: the image scans on its own (D15; F1.10).

`valvur scan` runs inside the image on a mounted or cloned checkout, with no
container runtime to reach: the same engine runs as a process in the image, its
container paths pointed at directories there, and the results can go to a mounted
directory while the checkout stays read-only.
"""

from __future__ import annotations

import sys
from pathlib import Path

from valvur.engine_host import LocalRuntime, snapshot
from valvur.invocation import Invocation


def test_the_engine_maps_the_cache_in_arguments_and_in_a_tools_environment(tmp_path):
    """Trivy is told `--cache-dir /cache/trivy`, OSV-Scanner reads its database from
    `/cache/osv` by a variable: in the image the cache is a directory of the job's,
    so both forms are pointed at it. Without a cache the paths stay the container's."""
    from valvur.engine import _mapped

    ws, results, cache = tmp_path / "ws", tmp_path / "results", tmp_path / "cache"
    assert _mapped("/cache/trivy", ws, results, cache) == f"{cache}/trivy"
    assert _mapped("--cache-dir=/cache/trivy", ws, results, cache) == \
        f"--cache-dir={cache}/trivy"
    assert _mapped("/cache/trivy", ws, results) == "/cache/trivy"
    assert _mapped("/cached", ws, results, cache) == "/cached"

    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    LocalRuntime(cache=cache).run(
        [Invocation(tool="env", version="0", report="env.txt",
                    argv=(sys.executable, "-c",
                          "import os, sys; open(sys.argv[1], 'w').write(os.environ['DB'])",
                          "/results/env.txt"),
                    env=(("DB", "/cache/osv"),))],
        snapshot(source, ["a.py"]), scratch)

    assert (scratch / "env.txt").read_text() == f"{cache}/osv"


def test_the_name_check_is_told_where_the_index_is_so_the_engine_can_move_it(tmp_path):
    """The Check read `/cache/names` from a constant unless a variable said otherwise;
    its invocation now says it, and the engine maps it with the rest of the cache."""
    from valvur.adapters import CheckAdapter
    from valvur.checks.dependency_reality import INDEX_ENV, INDEX_MOUNT

    invocation = CheckAdapter("dependency-reality", uses_network=True,
                              network=True).command(tmp_path)

    assert (INDEX_ENV, INDEX_MOUNT) in invocation.env


def _repository(tmp_path):
    import subprocess

    ws = tmp_path / "repo"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "PATH": __import__("os").environ["PATH"], "HOME": str(tmp_path)}
    for argv in (["init", "-q"], ["add", "app.py"], ["commit", "-qm", "one"]):
        subprocess.run(["git", "-C", str(ws), *argv], env=env, check=True)
    return ws


def test_a_repository_without_git_to_ask_is_walked_and_says_why(tmp_path, monkeypatch):
    """The image carries no `git` (ADR-0005). A checkout scanned inside it was a
    git view that raised; it is a walk of the folder, which reads ignored files
    too, and the scope says so."""
    from valvur import fileset

    ws = _repository(tmp_path)
    monkeypatch.setattr(fileset, "git", lambda: None)

    chosen = fileset.build(ws)

    assert chosen.scope == "tree"
    assert chosen.files == ["app.py"]
    assert "git" in (chosen.note or "")
    assert chosen.manifest(ws)["note"] == chosen.note


def test_history_unread_for_want_of_git_is_said_on_the_report(tmp_path, monkeypatch):
    import json

    from valvur import api, fileset
    from valvur.adapters import GitleaksAdapter

    fake_tools = Path(__file__).parent / "fixtures" / "fake-tools"
    ws = _repository(tmp_path)
    monkeypatch.setattr(fileset, "git", lambda: None)

    api.scan(ws, runner=LocalRuntime(fake_tools), adapters=[GitleaksAdapter()])

    run = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert "git" in run["history"]["unavailable"]
    summary = (ws / ".security-scan" / "SUMMARY.md").read_text()
    assert "Git history was not read for secrets" in summary
