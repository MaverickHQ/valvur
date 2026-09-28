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
