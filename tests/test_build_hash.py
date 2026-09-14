"""Task 23.4.4 — the shim carries the tree hash it was built beside.

`0.1.0rc1` fell through a hole F1.9 cannot see: the same version string on a shim
and an image built from different code. The version label answers "which
release?"; the build hash answers "which tree?". `release.yml` builds the wheel and
the image from one checkout, so a generated `valvur/_build.py` in the wheel and
`/etc/valvur/inputs.sha256` in the image are the same digest — and a scan that
finds them different says so, in `run.json` and `SUMMARY.md`, as a warning and
never a refusal: a mismatch is a diagnosis, not a reason to hide results.
"""

from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from valvur import compat, tree_hash

REPO = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------- the wheel's hash


def test_the_generated_file_is_never_an_input_to_the_hash(tmp_path):
    """`_build.py` sits in `src/valvur`, which is hashed. It must not move the
    digest it records, on either side of the build."""
    parts = {"valvur": tmp_path / "pkg"}
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n")
    before = tree_hash.digest(parts)
    (tmp_path / "pkg" / "_build.py").write_text('INPUTS_SHA256 = "deadbeef"\n')

    assert tree_hash.digest(parts) == before


def test_the_generated_file_is_ignored_by_git_and_by_the_image():
    """Never committed (the task's rule) and never copied into the image, where a
    stale host value would sit beside the real digest file."""
    assert "src/valvur/_build.py" in Path(REPO / ".gitignore").read_text()
    assert "src/valvur/_build.py" in Path(REPO / ".dockerignore").read_text()



def test_a_built_wheel_carries_the_trees_digest(tmp_path):
    """The real thing: `uv build` runs the hook, the wheel holds `_build.py`, and
    the digest it holds is the one the image would record from this same tree."""
    out = tmp_path / "dist"
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(out)], cwd=REPO,
                   check=True, capture_output=True, text=True, timeout=300)
    [wheel] = out.glob("*.whl")

    with zipfile.ZipFile(wheel) as z:
        text = z.read("valvur/_build.py").decode()

    expected = tree_hash.digest(tree_hash.tree_parts(REPO))
    assert f'INPUTS_SHA256 = "{expected}"' in text
    assert not (REPO / "src" / "valvur" / "_build.py").exists(), (
        "the hook left its generated file in the source tree")


def test_the_shim_answers_from_the_generated_file_when_it_has_one(monkeypatch, tmp_path):
    import sys
    import types

    module = types.ModuleType("valvur._build")
    module.INPUTS_SHA256 = "a" * 64  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "valvur._build", module)

    assert compat.shim_inputs() == "a" * 64


def test_a_source_tree_answers_by_hashing_itself_and_an_installed_shim_without_the_file_by_none(
    monkeypatch,
):
    """Editable installs and the test suite have no `_build.py`; they sit beside
    the Dockerfile, so the tree is hashed live — what the e2e guard does. A wheel
    without the file (built before 23.4.4) has nothing to say, and says nothing."""
    import sys

    monkeypatch.setitem(sys.modules, "valvur._build", None)   # import fails
    assert compat.shim_inputs() == tree_hash.digest(tree_hash.tree_parts(REPO))

    monkeypatch.setattr(compat, "_source_tree", lambda: None)
    assert compat.shim_inputs() is None


# ------------------------------------------------------------ the image's hash


def test_the_images_digest_is_read_once_per_image_id_and_then_from_the_cache(
    monkeypatch, tmp_path
):
    """A container start costs 2-5s on Docker Desktop; the image id costs
    milliseconds and changes exactly when the image does."""
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    launched: list[list[str]] = []

    def run(cmd, **kwargs):
        launched.append(cmd)
        if cmd[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, "sha256:" + "1" * 64 + "\n", "")
        if cmd[1] == "run":
            return subprocess.CompletedProcess(cmd, 0, "b" * 64 + "\n", "")
        raise AssertionError(cmd)

    monkeypatch.setattr(subprocess, "run", run)

    first = compat.image_inputs("/usr/local/bin/docker", "x/y:1")
    second = compat.image_inputs("/usr/local/bin/docker", "x/y:1")

    assert first == second == "b" * 64
    assert [c[1] for c in launched] == ["image", "run", "image"], (
        "the second read started a container")
    cached = tmp_path / "cache" / "image-inputs" / ("sha256:" + "1" * 64)
    assert cached.read_text().strip() == "b" * 64


def test_an_image_without_the_file_answers_none_and_is_not_asked_again(monkeypatch, tmp_path):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    calls: list[str] = []

    def run(cmd, **kwargs):
        calls.append(cmd[1])
        if cmd[1] == "image":
            return subprocess.CompletedProcess(cmd, 0, "sha256:" + "2" * 64 + "\n", "")
        # `cat` on a missing file: exit 1, and whatever else the container printed
        # on stdout is not a digest.
        return subprocess.CompletedProcess(cmd, 1, "not a digest\n",
                                           "cat: can't open '/etc/valvur/inputs'")

    monkeypatch.setattr(subprocess, "run", run)

    assert compat.image_inputs("/usr/local/bin/docker", "old:1") is None
    assert compat.image_inputs("/usr/local/bin/docker", "old:1") is None
    assert calls == ["image", "run", "image"]


def test_a_container_that_did_not_start_is_asked_again_next_time(monkeypatch, tmp_path):
    """Exit 125 is the runtime failing to start the container — a stopped daemon,
    an image mid-pull — not the image's answer, so nothing is remembered."""
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    runs: list[str] = []

    def run(cmd, **kwargs):
        runs.append(cmd[1])
        if cmd[1] == "image":
            return subprocess.CompletedProcess(cmd, 0, "sha256:" + "3" * 64 + "\n", "")
        return subprocess.CompletedProcess(cmd, 125, "", "docker: Error response from daemon")

    monkeypatch.setattr(subprocess, "run", run)

    assert compat.image_inputs("/usr/local/bin/docker", "x/y:1") is None
    assert compat.image_inputs("/usr/local/bin/docker", "x/y:1") is None
    assert runs == ["image", "run", "image", "run"]
    assert not (tmp_path / "cache" / "image-inputs").exists()


def test_a_runtime_that_cannot_answer_is_none_not_an_error(monkeypatch, tmp_path):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, "", "no daemon"))

    assert compat.image_inputs("/usr/local/bin/docker", "x/y:1") is None


# ---------------------------------------------------------------- the surfaces


class _Runner:
    image = "ghcr.io/maverickhq/valvur:9.9.9"
    runtime = "/usr/local/bin/docker"

    def __init__(self, shim, image):
        self._pair = (shim, image)

    def build_provenance(self):
        return self._pair

    def run_gitleaks(self, workspace):
        from valvur.runner import ScannerOutput

        return ScannerOutput("gitleaks", "8.30.1", "[]", "", 0)


def _scan(tmp_path, monkeypatch, shim, image):
    from valvur import api, cache
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    run = api.scan(ws, runner=_Runner(shim, image), adapters=[GitleaksAdapter()])
    return run, ws / ".security-scan"


def test_a_matching_pair_is_recorded_and_says_nothing_loud(tmp_path, monkeypatch):
    run, results = _scan(tmp_path, monkeypatch, "c" * 64, "c" * 64)

    data = json.loads((results / "run.json").read_text())
    assert data["build"] == {"shim": "c" * 64, "image": "c" * 64, "match": True}
    assert "different trees" not in (results / "SUMMARY.md").read_text()
    assert run.shim_built_from == "c" * 64 and run.image_built_from == "c" * 64


def test_a_mismatched_pair_is_a_warning_on_every_surface_and_never_a_refusal(
    tmp_path, monkeypatch
):
    """The rc1 hole: same version, different code. Said in run.json, SUMMARY.md and
    scan_status — and the scan still ran, because a mismatch is a diagnosis."""
    from valvur.operations import scan_status

    run, results = _scan(tmp_path, monkeypatch, "a" * 64, "b" * 64)

    assert not run.failures
    data = json.loads((results / "run.json").read_text())
    assert data["build"] == {"shim": "a" * 64, "image": "b" * 64, "match": False}
    summary = (results / "SUMMARY.md").read_text()
    assert "built from different trees" in summary
    assert "aaaaaaaaaaaa" in summary and "bbbbbbbbbbbb" in summary
    assert "docker pull" in summary or "pip install" in summary
    status = scan_status({"workspace": str(tmp_path / "ws")})
    assert "built from different trees" in status


def test_a_pair_with_one_side_unknown_is_recorded_as_unknown_not_as_a_mismatch(
    tmp_path, monkeypatch
):
    """An image from before the digest file, or a wheel from before the hook:
    nothing to compare, and no warning invented from nothing."""
    _, results = _scan(tmp_path, monkeypatch, "a" * 64, None)

    data = json.loads((results / "run.json").read_text())
    assert data["build"] == {"shim": "a" * 64, "image": None, "match": None}
    assert "different trees" not in (results / "SUMMARY.md").read_text()


def test_a_runner_without_provenance_records_nothing(tmp_path, monkeypatch):
    from conftest import FakeRunner

    from valvur import api, cache
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = tmp_path / "ws"
    ws.mkdir()
    api.scan(ws, runner=FakeRunner(), adapters=[GitleaksAdapter()])

    data = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert data["build"] == {"shim": None, "image": None, "match": None}


def test_doctor_says_whether_the_image_matches_the_shim(monkeypatch, tmp_path):
    from valvur import doctor
    from valvur.version import __version__

    monkeypatch.setattr(doctor, "_find_runtime", lambda: "/usr/local/bin/docker")
    monkeypatch.setattr(doctor, "_runtime_version", lambda r: "Docker version 29.2.1")
    monkeypatch.setattr(doctor, "_runtime_running", lambda r: (True, ""))
    monkeypatch.setattr(doctor, "_image_present", lambda r, i: True)
    monkeypatch.setattr(doctor, "_image_label", lambda r, i: __version__)
    monkeypatch.setattr(doctor, "_image_starts", lambda r, i: (True, "b" * 64))
    monkeypatch.setattr(compat, "shim_inputs", lambda: "b" * 64)

    check = doctor._check_image("/usr/local/bin/docker")[0]
    assert "built from bbbbbbbb, the tree this shim was built from" in check.detail
    assert check.level == "ok"

    monkeypatch.setattr(compat, "shim_inputs", lambda: "a" * 64)
    check = doctor._check_image("/usr/local/bin/docker")[0]
    assert check.level == "warn"
    assert "built from bbbbbbbb; this shim was built from aaaaaaaa" in check.detail
    assert "F1.9" in check.fix or "pull" in check.fix
