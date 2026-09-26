"""`valvur cache --prune` (28.3.7, O4).

`~/.cache/valvur` was never pruned and the container runtime kept every image
tag a shim had ever pulled: `:0.2.0` stayed when `:0.3.0` arrived, and `valvur
cache` could inventory and not clean. A flag, never a default: `--prune` removes
the published image's local tags that are not this shim's version, and the
index files the metadata no longer names — each listed before it goes. `valvur
cache` without the flag removes nothing, and `doctor` names what is superseded.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import write_name_index

from valvur import cache, runner
from valvur.version import IMAGE_REPOSITORY, __version__


@pytest.fixture
def host_cache(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    monkeypatch.setattr(cache, "root", lambda: root)
    monkeypatch.setattr(cache, "trivy_db", lambda: root / "trivy")
    monkeypatch.setattr(cache, "name_index", lambda: root / "names")
    return root


def _fill(root: Path) -> None:
    """The three things `valvur update` fetches, as `test_gate_cache` lays them out."""
    db = root / "trivy" / "db"
    db.mkdir(parents=True)
    (db / "trivy.db").write_bytes(b"x" * 3_000)
    now = datetime.now(UTC)
    (db / "metadata.json").write_text(json.dumps({
        "UpdatedAt": (now - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")}))
    write_name_index(root / "names", pip=["requests", "flask"], npm=["react"], gem=["rack"],
                     composer=["monolog/monolog"], cargo=["serde"])
    (root / "kev.json").write_text('{"entries": {}, "count": 1500}')
    (root / ".lock").write_bytes(b"")


class FakeImages:
    """The runtime's image store, as `cache.LocalImages` sees it."""

    def __init__(self, tags: list[str], repository: str = IMAGE_REPOSITORY):
        self.repository = repository
        self.tags = list(tags)
        self.removed: list[str] = []

    def list(self, repository: str) -> list[str]:
        assert repository == self.repository, repository
        return [f"{repository}:{tag}" for tag in self.tags]

    def remove(self, reference: str) -> None:
        self.removed.append(reference)
        self.tags.remove(reference.rsplit(":", 1)[1])


def test_superseded_is_every_local_tag_of_the_published_image_but_this_shims():
    images = FakeImages(["0.2.0", __version__, "latest", "0.1.0rc1", "<none>"])

    assert cache.superseded_images(images) == [
        f"{IMAGE_REPOSITORY}:0.1.0rc1", f"{IMAGE_REPOSITORY}:0.2.0", f"{IMAGE_REPOSITORY}:latest",
    ]


def test_nothing_is_superseded_when_only_this_shims_image_is_local():
    assert cache.superseded_images(FakeImages([__version__])) == []
    assert cache.superseded_images(FakeImages([])) == []


def _strays(root: Path) -> list[Path]:
    names = root / "names"
    retired = names / "retired.txt"
    retired.write_text("x\n")
    partial = names / "npm.txt.part"
    partial.write_bytes(b"\x00" * 10)
    return [partial, retired]


def test_stray_index_files_are_the_ones_the_metadata_does_not_name(host_cache):
    _fill(host_cache)
    strays = _strays(host_cache)

    assert cache.stray_index_files() == strays
    named = json.loads((host_cache / "names" / "metadata.json").read_text())["ecosystems"]
    assert set(named) == {"pip", "npm", "gem", "composer", "cargo"}, "the fixture changed"


def test_prune_removes_exactly_the_superseded_images_and_the_strays(host_cache):
    _fill(host_cache)
    strays = _strays(host_cache)
    images = FakeImages(["0.2.0", __version__, "latest"])

    removed_images, removed_files = cache.prune(images)

    assert removed_images == images.removed == [f"{IMAGE_REPOSITORY}:0.2.0",
                                                f"{IMAGE_REPOSITORY}:latest"]
    assert images.tags == [__version__], "this shim's own image was removed"
    assert removed_files == [str(p) for p in strays]
    assert not any(p.exists() for p in strays)
    for kept in ("pypi.txt", "npm.txt", "rubygems.txt", "packagist.txt", "crates.txt",
                 "metadata.json"):
        assert (host_cache / "names" / kept).is_file(), f"{kept} was pruned"
    assert (host_cache / "trivy" / "db" / "trivy.db").is_file(), "the database was pruned"
    assert (host_cache / "kev.json").is_file()


def test_prune_without_a_runtime_still_prunes_the_files(host_cache):
    _fill(host_cache)
    strays = _strays(host_cache)

    assert cache.prune(None) == ([], [str(p) for p in strays])


def test_prune_takes_the_exclusive_cache_lock(host_cache, monkeypatch):
    from valvur import locking

    _fill(host_cache)
    taken: list[tuple[bool, bool]] = []
    real = locking.held

    def recording(path, *, exclusive=True, wait=True, busy_message=""):
        taken.append((exclusive, wait))
        return real(path, exclusive=exclusive, wait=wait, busy_message=busy_message)

    monkeypatch.setattr(locking, "held", recording)
    cache.prune(FakeImages([__version__]))

    assert taken == [(True, True)]


def test_the_cli_without_the_flag_removes_nothing(host_cache, capsys, monkeypatch):
    from valvur.cli import main

    _fill(host_cache)
    strays = _strays(host_cache)
    images = FakeImages(["0.2.0", __version__])
    monkeypatch.setattr(cache, "local_images", lambda runtime: images)

    assert main(["cache"]) == 0

    assert images.removed == [] and all(p.exists() for p in strays)
    assert "prune" not in capsys.readouterr().out.lower() or "--prune" in capsys.readouterr().out


def test_the_cli_lists_each_item_before_removing_it(host_cache, capsys, monkeypatch):
    from valvur.cli import main

    _fill(host_cache)
    strays = _strays(host_cache)
    images = FakeImages(["0.2.0", __version__])
    monkeypatch.setattr(cache, "local_images", lambda runtime: images)
    monkeypatch.setattr(runner, "detect_runtime", lambda: "/usr/local/bin/docker")

    assert main(["cache", "--prune"]) == 0
    out = capsys.readouterr().out

    listed = [line for line in out.splitlines() if line.startswith("  removing ")]
    assert listed == [f"  removing image {IMAGE_REPOSITORY}:0.2.0",
                      *(f"  removing file {p}" for p in strays)]
    assert images.removed == [f"{IMAGE_REPOSITORY}:0.2.0"]
    assert not any(p.exists() for p in strays)
    assert f"pruned: 1 image, {len(strays)} files" in out


def test_the_cli_says_when_there_is_nothing_to_prune(host_cache, capsys, monkeypatch):
    from valvur.cli import main

    _fill(host_cache)
    monkeypatch.setattr(cache, "local_images", lambda runtime: FakeImages([__version__]))
    monkeypatch.setattr(runner, "detect_runtime", lambda: "/usr/local/bin/docker")

    assert main(["cache", "--prune"]) == 0
    assert "nothing to prune" in capsys.readouterr().out


def test_doctor_names_the_superseded_images(monkeypatch):
    from valvur import compat, doctor

    monkeypatch.delenv("VALVUR_IMAGE", raising=False)
    monkeypatch.setattr(doctor, "_image_present", lambda runtime, image: True)
    monkeypatch.setattr(doctor, "_image_label", lambda runtime, image: __version__)
    monkeypatch.setattr(doctor, "_image_protocol", lambda runtime, image: None)
    monkeypatch.setattr(doctor, "_image_starts", lambda runtime, image: (True, "0be0b0f0456f7f"))
    monkeypatch.setattr(compat, "shim_inputs", lambda: "0be0b0f0456f7f")
    monkeypatch.setattr(doctor, "_superseded_images",
                        lambda runtime: [f"{IMAGE_REPOSITORY}:0.2.0", f"{IMAGE_REPOSITORY}:latest"])

    check, _ = doctor._check_image("/usr/local/bin/docker")

    assert check.level == "ok"
    assert "superseded: 0.2.0, latest" in check.detail
    assert "valvur cache --prune" in check.detail


def test_doctor_says_nothing_about_images_when_none_is_superseded(monkeypatch):
    from valvur import compat, doctor

    monkeypatch.delenv("VALVUR_IMAGE", raising=False)
    monkeypatch.setattr(doctor, "_image_present", lambda runtime, image: True)
    monkeypatch.setattr(doctor, "_image_label", lambda runtime, image: __version__)
    monkeypatch.setattr(doctor, "_image_protocol", lambda runtime, image: None)
    monkeypatch.setattr(doctor, "_image_starts", lambda runtime, image: (True, "0be0b0f0456f7f"))
    monkeypatch.setattr(compat, "shim_inputs", lambda: "0be0b0f0456f7f")
    monkeypatch.setattr(doctor, "_superseded_images", lambda runtime: [])

    check, _ = doctor._check_image("/usr/local/bin/docker")

    assert "superseded" not in check.detail


@pytest.mark.e2e
def test_the_real_runtime_lists_and_only_lists(monkeypatch):
    """The subprocess half, against the real runtime: listing this repository's
    tags is a read, and the listing is the shape `superseded_images` sorts."""
    from valvur.runner import detect_runtime

    images = cache.local_images(detect_runtime())
    listed = images.list(IMAGE_REPOSITORY)

    assert all(ref.startswith(f"{IMAGE_REPOSITORY}:") for ref in listed), listed
