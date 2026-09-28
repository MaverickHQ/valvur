"""R8.2: the image as a step in someone else's pipeline.

A pipeline fetches with a network, then scans with none. OSV's databases were
fetched only by a scan, since only a project names its ecosystems; a scan with no
network could not fetch them, OSV-Scanner failed and the gate failed an incomplete
run. `valvur update PATH` fetches them for PATH's lockfiles as well.
"""

from __future__ import annotations

from pathlib import Path

from test_update_tool import machine  # noqa: F401 — the fixture, registered by import


def test_update_with_a_path_fetches_osvs_databases_for_its_lockfiles(machine, tmp_path,  # noqa: F811
                                                                     monkeypatch, capsys):
    from valvur import cli, osv_offline

    fetched = []

    def fetch(name, opener=None, timeout=600):
        osv_offline.path(name).parent.mkdir(parents=True, exist_ok=True)
        osv_offline.path(name).write_bytes(b"zip")
        fetched.append(name)
        return {"what": f"OSV database ({name})", "source": "test", "size_mb": 1,
                "seconds": 0.1}

    monkeypatch.setattr(osv_offline, "fetch", fetch)
    ws = tmp_path / "project"
    ws.mkdir()
    (ws / "requirements.txt").write_text("six==1.16.0\n")
    (ws / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}\n')

    assert cli.main(["update", str(ws)]) == 0

    assert sorted(fetched) == ["PyPI", "npm"]
    assert "OSV database fetched for PyPI" in capsys.readouterr().out
    assert cli.main(["update", str(ws), "--if-stale"]) == 0
    assert sorted(fetched) == ["PyPI", "npm"], "a current database was fetched again"


def test_update_without_a_path_fetches_no_osv_database(machine, monkeypatch):  # noqa: F811
    from valvur import cli, osv_offline

    monkeypatch.setattr(osv_offline, "fetch", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("fetched with no project to name an ecosystem")))

    assert cli.main(["update"]) == 0
    assert not Path(osv_offline.directory()).exists() or not any(
        Path(osv_offline.directory()).rglob("all.zip"))


REPO = Path(__file__).resolve().parent.parent
GITHUB_EXAMPLE = REPO / "docs" / "examples" / "github-actions.yml"
GITLAB_EXAMPLE = REPO / "docs" / "examples" / "gitlab-ci.yml"


def _run_blocks(workflow: Path) -> list[str]:
    """Each `run: |` block of the example, in order, as the shell will see it."""
    blocks: list[str] = []
    lines = workflow.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.strip() != "run: |":
            continue
        indent = len(line) - len(line.lstrip())
        body = []
        for following in lines[i + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following)
        depth = min(len(b) - len(b.lstrip()) for b in body if b.strip())
        blocks.append("\n".join(b[depth:] for b in body).strip() + "\n")
    return blocks


def test_the_examples_name_the_image_this_release_publishes():
    from valvur.version import __version__

    reference = f"ghcr.io/maverickhq/valvur:{__version__}"
    for example in (GITHUB_EXAMPLE, GITLAB_EXAMPLE):
        assert reference in example.read_text(encoding="utf-8"), example.name
    assert len(_run_blocks(GITHUB_EXAMPLE)) == 3


import pytest  # noqa: E402


@pytest.mark.e2e
def test_the_github_example_runs_against_the_image(mountable_tmp):
    """R8.2: the example's own steps, in order, with the image built from this tree:
    fetch with a network, scan with none, gate. The checkout stays read-only."""
    import json
    import os
    import subprocess

    from valvur.runner import IMAGE

    checkout = mountable_tmp / "checkout"
    checkout.mkdir()
    (checkout / "app.py").write_text("print('hello')\n")
    (checkout / "requirements.txt").write_text("six==1.16.0\n")
    temp = mountable_tmp / "runner-temp"
    temp.mkdir()
    env = {**os.environ, "GITHUB_WORKSPACE": str(checkout), "RUNNER_TEMP": str(temp),
           "VALVUR_IMAGE": IMAGE}

    for block in _run_blocks(GITHUB_EXAMPLE):
        done = subprocess.run(["bash", "-e", "-c", block], env=env, capture_output=True,
                              text=True, timeout=1200, check=False)
        assert done.returncode == 0, f"{block}\n{done.stdout}\n{done.stderr}"

    run = json.loads((temp / "valvur-out" / ".security-scan" / "run.json").read_text())
    assert run["network"]["boundary"] == "this job's container, with no network"
    assert run["complete"] is True, run.get("status_reason")
    assert sorted(p.name for p in checkout.iterdir()) == ["app.py", "requirements.txt"]
