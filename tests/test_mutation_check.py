"""Mutation in CI (28.4.4, X1): every hunk of a change, reverted in turn.

Five tests on 2026-09-22 passed against the defect each was written for, and
all five were caught by hand mutation — one person's habit. This is the habit
as a script: for each hunk the change makes under `src/valvur`, put the old
lines back, run the unit suite, and report the hunks no test noticed. A hunk
that changes only comments or docstrings is skipped, because reverting it
changes nothing a test could see.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mutation_check.py"


@pytest.fixture
def harness():
    import importlib.util

    spec = importlib.util.spec_from_file_location("mutation_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # Registered before it runs: the script's dataclasses resolve their string
    # annotations through sys.modules[<module>].
    sys.modules["mutation_check"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


DIFF = textwrap.dedent("""\
    diff --git a/src/valvur/a.py b/src/valvur/a.py
    index 1111111..2222222 100644
    --- a/src/valvur/a.py
    +++ b/src/valvur/a.py
    @@ -3 +3 @@ def f():
    -    return 1
    +    return 2
    @@ -7,0 +8,2 @@ def g():
    +    if x:
    +        return 3
    diff --git a/src/valvur/b.py b/src/valvur/b.py
    index 3333333..4444444 100644
    --- a/src/valvur/b.py
    +++ b/src/valvur/b.py
    @@ -1,2 +1 @@
    -# old comment
    -# another
    +# new comment
    """)


def test_a_diff_is_read_as_one_hunk_per_change(harness):
    hunks = harness.hunks(DIFF)

    assert [(h.path, h.header) for h in hunks] == [
        ("src/valvur/a.py", "@@ -3 +3 @@ def f():"),
        ("src/valvur/a.py", "@@ -7,0 +8,2 @@ def g():"),
        ("src/valvur/b.py", "@@ -1,2 +1 @@"),
    ]
    assert hunks[0].body == ["-    return 1", "+    return 2"]
    assert hunks[2].added == ["# new comment"] and hunks[2].removed == ["# old comment", "# another"]


def test_a_reverting_patch_is_that_hunk_alone_with_its_file_headers(harness):
    [first, second, _] = harness.hunks(DIFF)

    patch = harness.revert_patch(second)

    assert patch.startswith("--- a/src/valvur/a.py\n+++ b/src/valvur/a.py\n@@ -7,0 +8,2 @@")
    assert "return 1" not in patch, "the first hunk leaked into the second's patch"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True, env={"HOME": str(repo), "PATH": "/usr/bin:/bin",
                                           "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout


@pytest.fixture
def repo(tmp_path):
    """A throwaway repository shaped like this one: `src/valvur/`, a test, one commit
    on `main`, and a branch that changes two things — one a test covers, one none does."""
    root = tmp_path / "repo"
    (root / "src" / "valvur").mkdir(parents=True)
    (root / "tests").mkdir()
    _git(root.parent, "init", "-q", "-b", "main", str(root))
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "config", "commit.gpgsign", "false")
    (root / "src" / "valvur" / "__init__.py").write_text("")
    (root / "src" / "valvur" / "m.py").write_text(textwrap.dedent('''\
        """A module."""


        def covered(x):
            return x + 1


        def uncovered(x):
            return x * 2
        '''))
    (root / "tests" / "test_m.py").write_text(textwrap.dedent('''\
        import sys
        sys.path.insert(0, "src")
        from valvur.m import covered


        def test_covered():
            assert covered(1) == 3
        '''))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "checkout", "-q", "-b", "change")
    (root / "src" / "valvur" / "m.py").write_text(textwrap.dedent('''\
        """A module, described better."""


        def covered(x):
            return x + 2


        def uncovered(x):
            return x * 3
        '''))
    _git(root, "commit", "-q", "-am", "change both, and the docstring")
    return root


def test_the_hunk_a_test_covers_is_caught_and_the_others_verdict_is_named(harness, repo):
    """The test asserts `covered(1) == 3`, which only the changed line makes true:
    reverting it fails the test — caught. Nothing asserts on `uncovered`, so its
    reverted hunk passes the suite — survived, which is the finding."""
    report = harness.run(repo, base="main", pytest_args=[sys.executable, "-m", "pytest", "-q",
                                                         "-p", "no:cacheprovider", "tests"])

    verdicts = {(h.path, h.header.split(" @@")[0]): verdict for h, verdict in report}
    assert verdicts[("src/valvur/m.py", "@@ -5 +5")] == "caught"
    assert verdicts[("src/valvur/m.py", "@@ -9 +9")] == "survived"
    assert verdicts[("src/valvur/m.py", "@@ -1 +1")] == "no code change"
    assert (repo / "src" / "valvur" / "m.py").read_text().count("x + 2") == 1, \
        "the tree was not restored"
    assert _git(repo, "status", "--porcelain") == ""


def test_a_hunk_of_comments_or_docstrings_is_no_code_change(harness):
    before = '"""Old."""\n\n# a comment\ndef f():\n    """Doc."""\n    return 1\n'
    after = '"""New."""\n\n# another comment\ndef f():\n    """Better doc."""\n    return 1\n'
    assert not harness.code_changed(before, after)
    assert harness.code_changed(before, after.replace("return 1", "return 2"))


def test_the_ci_job_runs_it_on_pull_requests_and_does_not_gate():
    ci = (SCRIPT.parent.parent / ".github" / "workflows" / "ci.yml").read_text()
    job = ci.split("\n  mutation:", 1)
    assert len(job) == 2, "ci.yml has no mutation job"
    body = job[1].split("\n  selfscan:", 1)[0]
    assert "scripts/mutation_check.py" in body
    assert "github.event_name == 'pull_request'" in body
    assert "fetch-depth: 0" in body, "the base branch has to be present to diff against"
    assert "continue-on-error: true" in body, "non-required at first: it reports, it does not gate"
