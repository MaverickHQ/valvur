"""R14.4: where reused results live, and how they go (D32, ADR-0030).

In the host cache, beside the data they were answered from, never in the Workspace:
a scan still writes nothing there but the Results Folder. `valvur update --clear`
removes them with the rest; `--prune` removes those that can never match again,
because the Scanner's version or its data has moved on, and those unused for thirty
days, each listed before it goes.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from test_first_run import host_cache  # noqa: F401 — the fixture, registered by import
from test_reuse_in_a_scan import FAKE_TOOLS, _scan, repository_8  # noqa: F401

from valvur import cache, reuse
from valvur.adapters.trivy import VERSION as TRIVY_VERSION


def _files(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")
            if p.is_file() and ".security-scan" not in p.parts}


def test_results_live_in_the_host_cache_and_the_workspace_holds_only_its_own(
        repository_8):  # noqa: F811
    before = _files(repository_8)

    _scan(repository_8)

    stored = sorted(p.parent.name for p in reuse.directory().rglob("*.json"))
    assert stored == ["osv-scanner", "trivy"]
    assert reuse.directory().is_relative_to(cache.root())
    assert _files(repository_8) == before


def test_clear_removes_them_with_the_rest(host_cache):  # noqa: F811
    """A cache of this test's own (`host_cache`): `clear` removes every entry, and
    the suite's shared database and index are not this test's to remove."""
    _stored("trivy", "any")

    removed = cache.clear()

    assert "reuse" in removed and not reuse.directory().exists()


def _stored(tool: str, key: str, **entry) -> Path:
    reuse.save(tool, key, raw="{}", version=entry.pop("version", TRIVY_VERSION),
               generation="g", data=entry.pop("data", reuse.data(tool, [])))
    return reuse.directory() / tool / f"{key}.json"


def test_prune_removes_what_can_never_match_again_and_keeps_what_can():
    current = _stored("trivy", "current")
    old_version = _stored("trivy", "old-version", version="0.1.0")
    old_data = _stored("trivy", "old-data", data="db:2020-01-01T00:00:00Z;java-db:")
    unused = _stored("trivy", "unused")
    month_ago = time.time() - 31 * 86400
    os.utime(unused, (month_ago, month_ago))

    listed = reuse.superseded()
    removed = reuse.prune()

    assert sorted(listed) == sorted([old_version, old_data, unused])
    assert sorted(Path(p) for p in removed) == sorted(listed)
    assert current.exists() and not old_version.exists()


def test_update_prune_lists_them_before_they_go(capsys, monkeypatch):
    from valvur import cli

    class NoImages:                      # never the machine's runtime (see conftest)
        def list(self, repository):
            return []

        def remove(self, reference):
            raise AssertionError(reference)

    monkeypatch.setattr(cache, "local_images", lambda runtime: NoImages())
    old = _stored("trivy", "old-version", version="0.1.0")

    assert cli.main(["update", "--prune"]) == 0

    assert f"removing reused result {old}" in capsys.readouterr().out
    assert not old.exists()


def test_a_reuse_refreshes_its_age(repository_8):  # noqa: F811
    _scan(repository_8)
    [stored] = list((reuse.directory() / "trivy").glob("*.json"))
    month_ago = time.time() - 31 * 86400
    os.utime(stored, (month_ago, month_ago))

    _scan(repository_8)

    assert stored.stat().st_mtime > time.time() - 60
    assert json.loads(stored.read_text())["generation"]


def test_the_cache_listing_names_them(repository_8, capsys):  # noqa: F811
    from valvur import cli

    assert cli.main(["cache"]) == 0                 # none yet: said, not a crash
    assert "reuse" in capsys.readouterr().out
    _scan(repository_8)

    entries = {e.name: e for e in cache.inventory()}

    assert entries["reuse"].present and entries["reuse"].detail == "2 results"


def test_no_unit_test_can_remove_an_image_from_the_machine():
    """The guard in conftest, held: the owner's pulled images are not the suite's."""
    import pytest

    with pytest.raises(AssertionError, match="tried to remove the image"):
        cache.RuntimeImages("docker").remove("ghcr.io/maverickhq/valvur:0.4.0")
