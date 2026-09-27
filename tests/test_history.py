"""R3.7: secrets in history (D3; F2.1, P2; ADR-0021).

The host writes each commit's added lines into a file in valvur's scratch
directory, on all refs, bounded at 5,000 commits or 200 MB, and keeps where each
commit's lines for each path begin, so a Gitleaks hit maps back to both. Only
added lines: a removed line was added by an earlier commit, which is scanned.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from valvur import history

KEY = "AKIAV7Q2XR4TVBN6WLKJ"


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=env).stdout.strip()


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "commit.gpgsign", "false")
    return root


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _line_of(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines(), start=1) if needle in line)


def test_a_removed_secret_is_in_the_history_with_its_commit_and_path(repo, tmp_path):
    added = _commit(repo, {"config.py": f"KEY = '{KEY}'\n"}, "add a key")
    _commit(repo, {"config.py": "KEY = ''\n"}, "remove it")
    written = history.write(repo, tmp_path / "history.txt")
    assert written is not None
    text = written.path.read_text()
    assert text.count(KEY) == 1                       # added once; the removal is not a line
    assert written.locate(_line_of(text, KEY)) == (added, "config.py")
    assert written.commits == 2
    assert written.bounded is None
    assert written.bytes == len(written.path.read_bytes())


def test_every_ref_is_read_not_only_the_branch_checked_out(repo, tmp_path):
    _commit(repo, {"app.py": "x = 1\n"}, "first")
    _git(repo, "checkout", "-q", "-b", "side")
    side = _commit(repo, {"deploy/keys.py": f"KEY = '{KEY}'\n"}, "a key on a side branch")
    _git(repo, "checkout", "-q", "main")
    written = history.write(repo, tmp_path / "history.txt")
    assert written is not None
    text = written.path.read_text()
    assert written.locate(_line_of(text, KEY)) == (side, "deploy/keys.py")


def test_each_path_in_a_commit_maps_to_itself(repo, tmp_path):
    sha = _commit(repo, {"a b/ü.py": "first = 1\n", "z.py": f"KEY = '{KEY}'\n"}, "two files")
    written = history.write(repo, tmp_path / "history.txt")
    assert written is not None
    text = written.path.read_text()
    assert written.locate(_line_of(text, "first = 1")) == (sha, "a b/ü.py")
    assert written.locate(_line_of(text, KEY)) == (sha, "z.py")


def test_past_the_commit_bound_the_newest_are_read_and_the_bound_is_named(repo, tmp_path):
    for i in range(3):
        _commit(repo, {f"f{i}.py": f"n = {i}\n"}, f"commit {i}")
    written = history.write(repo, tmp_path / "history.txt", max_commits=2)
    assert written is not None
    assert written.commits == 2
    assert written.bounded == "the 2-commit bound"
    assert "n = 0" not in written.path.read_text()     # the oldest was not read


def test_past_the_byte_bound_writing_stops_and_the_bound_is_named(repo, tmp_path):
    for i in range(5):
        _commit(repo, {f"f{i}.py": "x" * 1000 + "\n"}, f"commit {i}")
    written = history.write(repo, tmp_path / "history.txt", max_bytes=2500)
    assert written is not None
    assert written.bounded == "the 2,500-byte bound"
    assert written.bytes <= 2500
    assert written.commits < 5


def test_a_directory_that_is_not_a_repository_has_no_history(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert history.write(plain, tmp_path / "history.txt") is None


def test_the_bounds_are_the_decisions(repo):
    assert history.MAX_COMMITS == 5000
    assert history.MAX_BYTES == 200 * 2**20


# ------------------------------------------------ Gitleaks reads it (behaviour 2)

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"


def _scan(ws: Path, monkeypatch):
    from valvur import api
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import LocalRuntime

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    said: list[str] = []
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()],
                   on_progress=said.append)
    return run, said


def test_a_secret_only_in_history_is_reported_at_its_path_with_its_commit(repo, monkeypatch):
    added = _commit(repo, {"config.py": f"KEY = '{KEY}'\n"}, "add a key")
    _commit(repo, {"config.py": "KEY = ''\n"}, "remove it")
    run, said = _scan(repo, monkeypatch)
    [finding] = [f for f in run.findings if f.rule == "aws-access-token"]
    assert finding.path == "config.py"
    assert finding.commit == added
    assert added[:12] in finding.title
    assert KEY not in finding.evidence                       # redacted, as in the tree
    assert run.history == {"commits": 2, "bytes": run.history["bytes"], "bounded": None}
    assert any(line.startswith("history: 2 commits") for line in said), said


def test_a_secret_still_in_the_tree_is_one_finding_at_its_line(repo, monkeypatch):
    _commit(repo, {"config.py": f"x = 1\nKEY = '{KEY}'\n"}, "add a key")
    run, _ = _scan(repo, monkeypatch)
    [finding] = [f for f in run.findings if f.rule == "aws-access-token"]
    assert (finding.path, finding.line, finding.commit) == ("config.py", 2, None)


def test_history_respects_the_projects_excludes_and_its_path_allowlist(repo, monkeypatch):
    _commit(repo, {".security-scan.toml": '[scan]\nexclude = ["archive"]\n',
                   ".gitleaks.toml": "[extend]\nuseDefault = true\n\n[allowlist]\n"
                                     "paths = ['''^tests/''']\n",
                   "archive/old.py": f"KEY = '{KEY}'\n",
                   "tests/keys.py": f"KEY = '{KEY}'\n"}, "planted")
    _commit(repo, {"archive/old.py": "", "tests/keys.py": ""}, "emptied")
    run, _ = _scan(repo, monkeypatch)
    assert [f for f in run.findings if f.rule == "aws-access-token"] == []


def test_a_folder_that_is_not_a_repository_reads_no_history(tmp_path, monkeypatch):
    ws = tmp_path / "plain"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    run, _ = _scan(ws, monkeypatch)
    assert run.history is None


# ------------------------------------------------ e2e: repository 3 (behaviour 3)

@pytest.mark.e2e
def test_repository_3s_removed_credential_is_reported_with_its_commit(
        mountable_tmp, monkeypatch):
    import importlib.util
    import sys

    from valvur import api
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import ContainerRuntime

    path = Path(__file__).parent.parent / "scripts" / "acceptance" / "generate.py"
    spec = importlib.util.spec_from_file_location("acceptance_generate", path)
    generate = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance_generate"] = generate
    spec.loader.exec_module(generate)  # type: ignore[union-attr]
    ws = generate.build(mountable_tmp / "set", only="3")["3-history-secret"]
    added = _git(ws, "rev-list", "--max-parents=0", "HEAD")

    monkeypatch.setenv("VALVUR_ENGINE", "2")
    run = api.scan(ws, runner=ContainerRuntime(), adapters=[GitleaksAdapter()])
    [finding] = [f for f in run.findings if f.rule == "aws-access-token"]
    assert (finding.path, finding.commit) == ("config.py", added)
    assert run.history is not None and run.history["commits"] == 2
    assert all(s.ok for s in run.scanners), run.scanners


# ------------------------------------------------ off, and said (behaviour 4)

def test_history_false_reads_none_and_says_so(repo, monkeypatch):
    _commit(repo, {".security-scan.toml": "[scan]\nhistory = false\n",
                   "config.py": f"KEY = '{KEY}'\n"}, "add a key")
    _commit(repo, {"config.py": "KEY = ''\n"}, "remove it")
    run, said = _scan(repo, monkeypatch)
    assert [f for f in run.findings if f.rule == "aws-access-token"] == []
    assert run.history == {"off": "[scan] history = false"}
    assert "history: not read ([scan] history = false)" in said


def test_the_record_and_the_summary_say_what_history_was_read(tmp_path):
    import json

    from valvur import provenance, summary
    from valvur.api import ScanRun

    bounded = ScanRun(history={"commits": 5000, "bytes": 3 * 2**20,
                               "bounded": "the 5,000-commit bound"})
    assert json.loads(provenance.render(bounded))["history"] == bounded.history
    text = summary.render(bounded)
    assert "the 5,000-commit bound" in text and "older commits were not read" in text
    off = summary.render(ScanRun(history={"off": "[scan] history = false"}))
    assert "Git history was not read" in off and "history = false" in off
    whole = summary.render(ScanRun(history={"commits": 12, "bytes": 2048, "bounded": None}))
    assert "12 commits" in whole
