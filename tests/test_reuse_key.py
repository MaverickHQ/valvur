"""R14.2: the reuse key (D32, N1.5, ADR-0030).

Trivy and OSV-Scanner read a project's dependency files and their own database, and
nothing else of it. Their answer cannot change while those do not, so a scan can
reuse the last one. The key is everything the answer depends on: the Scanner, its
version, the Profile, the bytes of every dependency file they read, and the data
they answered from. A source file is not in it.
"""

from __future__ import annotations

from pathlib import Path

from valvur import reuse


def _project(root: Path, **files: str) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    defaults = {"package-lock.json": '{"lockfileVersion": 3}', "package.json": "{}",
                "src/app.js": "console.log(1)\n", "README.md": "# demo\n"}
    for name, text in {**defaults, **files}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return reuse.inputs(root, sorted(p.relative_to(root).as_posix()
                                     for p in root.rglob("*") if p.is_file()))


def _key(inputs: dict[str, str], **overrides: str) -> str:
    base = {"tool": "trivy", "version": "0.74.0", "profile": "offline",
            "data": "2026-09-30T06:12:00Z"}
    return reuse.key(**{**base, **overrides}, inputs=inputs)


def test_the_key_reads_dependency_files_and_not_source(tmp_path):
    inputs = _project(tmp_path / "p")

    assert set(inputs) == {"package-lock.json", "package.json"}


def test_a_lockfiles_byte_change_changes_the_key(tmp_path):
    before = _project(tmp_path / "a")
    after = _project(tmp_path / "b", **{"package-lock.json": '{"lockfileVersion": 2}'})

    assert _key(before) != _key(after)


def test_a_new_or_moved_dependency_file_changes_the_key(tmp_path):
    before = _project(tmp_path / "a")
    after = _project(tmp_path / "b", **{"web/yarn.lock": "# yarn\n"})

    assert _key(before) != _key(after)


def test_the_databases_built_time_changes_the_key(tmp_path):
    inputs = _project(tmp_path / "p")

    assert _key(inputs) != _key(inputs, data="2026-10-01T06:12:00Z")


def test_the_scanners_version_changes_the_key(tmp_path):
    inputs = _project(tmp_path / "p")

    assert _key(inputs) != _key(inputs, version="0.75.0")


def test_the_profile_changes_the_key(tmp_path):
    inputs = _project(tmp_path / "p")

    assert _key(inputs) != _key(inputs, profile="full")


def test_a_source_files_change_does_not(tmp_path):
    before = _project(tmp_path / "a")
    after = _project(tmp_path / "b", **{"src/app.js": "eval(input)\n", "README.md": "# x\n"})

    assert _key(before) == _key(after)


def test_every_lockfile_valvur_names_is_a_key_file():
    from valvur import ecosystems

    for patterns in ecosystems.VULNERABILITY_MANIFESTS.values():
        for pattern in patterns:
            example = pattern.replace("*", "dev")
            assert reuse.reads(example), example


def test_only_the_dependency_scanners_are_reused_and_osv_only_offline():
    assert reuse.reusable("trivy", "offline") and reuse.reusable("trivy", "full")
    assert reuse.reusable("osv-scanner", "offline")
    assert not reuse.reusable("osv-scanner", "full")      # the live API has no stamp
    for tool in ("opengrep", "gitleaks", "checkov", "zizmor", "syft", "dependency-reality"):
        assert not reuse.reusable(tool, "offline"), tool
