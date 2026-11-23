"""R50.2: `valvur scan --ref`: a commit's tree, read and never checked out (D82k, ADR-0034).

A gate on new Findings needs the Findings of the base, and a baseline file would be scan
output in git, which ADR-0011 forbids. So valvur scans the base itself. `scan --ref` reads
a commit with git's plumbing, which writes nothing to the repository, scans exactly that
tree with that commit's own `.security-scan.toml`, and writes the result where it is told:
never into the Workspace, whose own result is of the working tree.

The Scanner is the real Gitleaks adapter over the fake tool, as `tests/test_cli_parity.py`
runs it. Each key is assembled at runtime.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from valvur import cli

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
RESULTS = ".security-scan"
KEY = {name: "AK" + "IA" + (letter * 16) for name, letter in
       (("old", "A"), ("only_ref", "B"), ("gone", "C"), ("new", "D"), ("wip", "E"),
        ("vendored", "F"))}


def _git(root: Path, *args: str) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "HOME": str(root)}
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True, env=env).stdout.strip()


def _write(root: Path, files: dict[str, str | None]) -> None:
    for name, text in files.items():
        path = root / name
        if text is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """Three commits and an untracked file. `v1` is the second commit."""
    from valvur import api, cache, engine_host
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(engine_host, "for_scan", lambda: LocalRuntime(FAKE_TOOLS))
    monkeypatch.setattr(api, "DEFAULT_ADAPTERS", [GitleaksAdapter()])
    monkeypatch.delenv("VALVUR_JOBS", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {"old.env": f"KEY={KEY['old']}\n", "gone.env": f"KEY={KEY['gone']}\n",
                  "only_ref.env": f"KEY={KEY['only_ref']}\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "one")
    _write(root, {"gone.env": None})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "two")
    _git(root, "tag", "v1")
    _write(root, {"only_ref.env": None, "new.env": f"KEY={KEY['new']}\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "three")
    _write(root, {"wip.env": f"KEY={KEY['wip']}\n"})
    return root


def _findings(out: Path) -> list[dict]:
    return json.loads((out / RESULTS / "findings.json").read_text())["findings"]


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def test_the_refs_tree_is_scanned_and_not_the_working_tree(repo, tmp_path):
    out = tmp_path / "out"

    assert cli.main(["scan", str(repo), "--ref", "v1", "--out", str(out)]) in (0, 1)

    in_files = sorted(f["path"] for f in _findings(out) if "history" not in f["title"])
    assert in_files == ["old.env", "only_ref.env"]


def test_nothing_under_git_changes_and_the_workspace_holds_no_result(repo, tmp_path):
    before = _tree_hash(repo / ".git")
    listed = sorted(p.name for p in repo.iterdir())

    cli.main(["scan", str(repo), "--ref", "v1", "--out", str(tmp_path / "out")])

    assert _tree_hash(repo / ".git") == before
    assert sorted(p.name for p in repo.iterdir()) == listed and not (repo / RESULTS).exists()


@pytest.mark.parametrize("where", ["none", "the workspace", "its results folder", "inside it"])
def test_a_ref_is_refused_without_an_out_of_its_own(repo, tmp_path, capsys, where):
    out = {"none": [], "the workspace": ["--out", str(repo)],
           "its results folder": ["--out", str(repo / RESULTS)],
           "inside it": ["--out", str(repo / RESULTS / "base")]}[where]

    assert cli.main(["scan", str(repo), "--ref", "v1", *out]) == 2

    said = capsys.readouterr().err
    assert ("--ref needs --out DIR" in said) if where == "none" else (
        "is the workspace's own Results Folder" in said)
    assert not (repo / RESULTS).exists()


def test_a_ref_that_does_not_resolve_is_an_error_that_names_it(repo, tmp_path, capsys):
    out = tmp_path / "out"

    assert cli.main(["scan", str(repo), "--ref", "no-such-branch", "--out", str(out)]) == 2

    assert "`no-such-branch` names no commit" in capsys.readouterr().err
    assert not out.exists()


def test_a_ref_that_looks_like_an_option_is_never_handed_to_git(repo, tmp_path, capsys):
    assert cli.main(["scan", str(repo), "--ref=--output=/tmp/x", "--out",
                     str(tmp_path / "out")]) == 2
    assert "names no commit" in capsys.readouterr().err


def test_the_record_names_the_ref_and_its_commit(repo, tmp_path):
    out = tmp_path / "out"
    cli.main(["scan", str(repo), "--ref", "v1", "--out", str(out)])

    record = json.loads((out / RESULTS / "run.json").read_text())
    assert record["tree"] == {"ref": "v1", "commit": _git(repo, "rev-parse", "v1")}


def test_a_scan_of_the_working_tree_names_no_tree(repo):
    cli.main(["scan", str(repo)])

    assert "tree" not in json.loads((repo / RESULTS / "run.json").read_text())


def _commit(repo: Path, branch: str, files: dict[str, str | None], at: str = "v1") -> None:
    _git(repo, "checkout", "-q", "-b", branch, at)
    _write(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", branch)
    _git(repo, "checkout", "-q", "main")


def test_the_refs_own_project_file_gives_the_excludes(repo, tmp_path):
    """The working tree's file excludes nothing; the ref's excludes `vendor`."""
    _commit(repo, "with-vendor", {"vendor/k.env": f"KEY={KEY['vendored']}\n"})
    _commit(repo, "excluding", {".security-scan.toml": '[scan]\nexclude = ["vendor"]\n'},
            at="with-vendor")

    cli.main(["scan", str(repo), "--ref", "with-vendor", "--out", str(tmp_path / "a")])
    cli.main(["scan", str(repo), "--ref", "excluding", "--out", str(tmp_path / "b")])

    assert "vendor/k.env" in {f["path"] for f in _findings(tmp_path / "a")}
    assert "vendor/k.env" not in {f["path"] for f in _findings(tmp_path / "b")}


def test_the_refs_own_project_file_gives_the_suppressions(repo, tmp_path):
    cli.main(["scan", str(repo), "--ref", "v1", "--out", str(tmp_path / "a")])
    [old] = [f for f in _findings(tmp_path / "a") if f["path"] == "old.env"]
    assert old["suppressed"] is None
    _commit(repo, "accepting", {".security-scan.toml": (
        f'[[suppress]]\nfingerprint = "{old["fingerprint"]}"\nrule = "{old["rule"]}"\n'
        'path = "old.env"\nexpires = 2099-01-01\nreason = "a key for the test"\n')})

    cli.main(["scan", str(repo), "--ref", "accepting", "--out", str(tmp_path / "b")])

    [accepted] = [f for f in _findings(tmp_path / "b") if f["path"] == "old.env"]
    assert accepted["suppressed"] and accepted["fingerprint"] == old["fingerprint"]


def test_history_is_read_up_to_the_ref_and_no_further(repo, tmp_path):
    """`gone.env` was deleted before `v1`: its key is in the history `v1` has. `new.env`
    was added after it, and is no part of `v1`."""
    out = tmp_path / "out"
    cli.main(["scan", str(repo), "--ref", "v1", "--out", str(out)])

    evidence = json.dumps(_findings(out))
    in_history = [f for f in _findings(out) if "in git history" in f["title"]]
    assert [f["path"] for f in in_history] == ["gone.env"]
    assert "new.env" not in evidence and "wip.env" not in evidence
    record = json.loads((out / RESULTS / "run.json").read_text())
    assert record["history"]["commits"] == 2


@pytest.mark.e2e
def test_once_against_the_image_a_refs_tree_and_its_history(mountable_tmp):
    """The same through the Scan Container and the real Gitleaks: the commit's files reach
    it as a Snapshot, and its history as the directory the host wrote."""
    live = {name: "AK" + "IA" + body for name, body in
            (("old", "V7Q2XR4TVBN6WLKJ"), ("gone", "Z5M3KD2QPLX7RNB4"),
             ("wip", "T6H2WQ7XKC4PMV3J"))}
    root = mountable_tmp / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {"config/old.env": f"AWS_ACCESS_KEY_ID={live['old']}\n",
                  "config/gone.env": f"AWS_ACCESS_KEY_ID={live['gone']}\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "one")
    _write(root, {"config/gone.env": None})
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "two")
    _git(root, "tag", "v1")
    _write(root, {"config/wip.env": f"AWS_ACCESS_KEY_ID={live['wip']}\n"})
    before, out = _tree_hash(root / ".git"), mountable_tmp / "out"

    assert cli.main(["scan", str(root), "--ref", "v1", "--out", str(out)]) in (0, 1)

    secrets = [f for f in _findings(out) if "gitleaks" in f["sources"]]
    assert sorted({f["path"] for f in secrets}) == ["config/gone.env", "config/old.env"]
    assert ["in git history" in f["title"] for f in sorted(secrets, key=lambda f: f["path"])] \
        == [True, False]
    record = json.loads((out / RESULTS / "run.json").read_text())
    assert record["tree"] == {"ref": "v1", "commit": _git(root, "rev-parse", "v1")}
    assert record["complete"] is True
    assert _tree_hash(root / ".git") == before and not (root / RESULTS).exists()


def test_without_git_the_error_says_so_and_not_that_the_ref_is_wrong(repo, tmp_path, capsys,
                                                                    monkeypatch):
    """Inside the image there is no git (ADR-0005). A ref cannot be read there at all, and
    saying it names no commit would send the reader to check a branch that exists."""
    from valvur import fileset

    monkeypatch.setattr(fileset, "git", lambda: None)

    assert cli.main(["scan", str(repo), "--ref", "v1", "--out", str(tmp_path / "out")]) == 2

    said = capsys.readouterr().err
    assert "git is not on PATH here" in said and "names no commit" not in said
    assert "the image carries none" in said
