"""R28.2 (D64a): a Dependabot update lands itself once every required check passes.

`scripts/dependabot_auto_merge.py` decides from `gh pr view --json files,commits` whether
a pull request may: it changes only dependency files, and every commit carries
Dependabot's `update-type`, none of them a major version. Read from Dependabot's own
pull requests on 2026-10-04: #200 changed `requirements-checkov.in` beside the lock, and
earlier ones that someone else had added code to touched `src/` and `tests/`, which must
wait for the owner. `.github/workflows/dependabot-auto-merge.yml` runs it and asks
GitHub to squash: R28.1 measured that `main` takes signed commits and linear history,
and GitHub signs the commit it squashes.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "dependabot_auto_merge.py"
WORKFLOW = REPO / ".github" / "workflows" / "dependabot-auto-merge.yml"


def _script():
    spec = importlib.util.spec_from_file_location("dependabot_auto_merge", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["dependabot_auto_merge"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _commit(*update_types: str) -> dict:
    deps = "".join(f"- dependency-name: x{i}\n  update-type: {kind}\n"
                   for i, kind in enumerate(update_types))
    return {"messageHeadline": "chore: bump x", "messageBody":
            f"Bumps x.\n\n---\nupdated-dependencies:\n{deps}...\n\nSigned-off-by: dependabot[bot]"}


def _view(files, *commits):
    return {"files": [{"path": f} for f in files], "commits": list(commits)}


def test_a_patch_update_to_dependency_files_alone_may_land_itself():
    """#200's shape: the Checkov lock and its input, one patch update."""
    eligible, reason = _script().decide(_view(
        ["requirements-checkov.in", "requirements-checkov.txt"],
        _commit("version-update:semver-patch")))

    assert eligible, reason


def test_a_grouped_update_of_minors_and_patches_may_land_itself():
    eligible, _ = _script().decide(_view(
        ["uv.lock"], _commit("version-update:semver-minor", "version-update:semver-patch")))

    assert eligible


@pytest.mark.parametrize("path", ["Dockerfile", ".clusterfuzzlite/Dockerfile", "uv.lock",
                                  "requirements-zizmor.txt"])
def test_each_dependency_file_is_allowed(path):
    assert _script().decide(_view([path], _commit("version-update:semver-patch")))[0]


@pytest.mark.parametrize("path", [
    "src/valvur/adapters/osv.py", "tests/conftest.py", "pyproject.toml", "CHANGELOG.md",
    # A merge made with the workflow's own token cannot change a workflow file, so an
    # Actions update would sit enabled and unmerged: it waits for the owner instead.
    ".github/workflows/ci.yml", ".github/actions/version/action.yml",
])
def test_any_other_file_leaves_it_for_the_owner_and_says_which(path):
    eligible, reason = _script().decide(_view(
        ["uv.lock", path], _commit("version-update:semver-patch")))

    assert not eligible and path in reason


def test_a_major_update_anywhere_in_it_leaves_it_for_the_owner():
    eligible, reason = _script().decide(_view(
        ["uv.lock"], _commit("version-update:semver-patch", "version-update:semver-major")))

    assert not eligible and "major" in reason


def test_a_commit_without_dependabots_update_type_leaves_it_for_the_owner():
    """A commit someone else pushed onto Dependabot's branch carries no metadata."""
    plain = {"messageHeadline": "fix: adapt the parser", "messageBody": ""}
    eligible, reason = _script().decide(_view(
        ["uv.lock"], _commit("version-update:semver-patch"), plain))

    assert not eligible and "update-type" in reason


def test_nothing_to_judge_is_never_eligible():
    assert not _script().decide(_view([]))[0]
    assert not _script().decide(_view(["uv.lock"]))[0]


def test_the_command_line_reads_the_view_on_stdin_and_answers_by_exit_code(capsys):
    import io
    import json

    script = _script()
    ok = json.dumps(_view(["uv.lock"], _commit("version-update:semver-minor")))
    major = json.dumps(_view(["uv.lock"], _commit("version-update:semver-major")))

    assert script.main(stdin=io.StringIO(ok)) == 0
    assert script.main(stdin=io.StringIO(major)) == 1
    assert script.main(stdin=io.StringIO("not json")) == 2
    assert "major" in capsys.readouterr().out


def _workflow() -> str:
    assert WORKFLOW.is_file(), "no dependabot-auto-merge workflow"
    return WORKFLOW.read_text()


def test_it_runs_on_pull_request_and_never_on_pull_request_target():
    """`pull_request_target` would run with a write token in the base repository's
    context for any pull request, the classic way such workflows are abused."""
    text = _workflow()

    assert re.search(r"^on:\n  pull_request:\n", text, re.M)
    assert "pull_request_target" not in text and "workflow_run" not in text


def test_only_dependabots_pull_requests_and_no_more_privilege_than_the_merge_needs():
    text = _workflow()

    assert re.search(r"^permissions: \{\}$", text, re.M), "no write at the top level"
    job = re.search(r"^    permissions:\n((?:      \S.*\n)+)", text, re.M)
    assert job, "the job declares its permissions"
    granted = {line.split(":")[0].strip() for line in job.group(1).splitlines()}
    assert granted == {"contents", "pull-requests"}
    # The pull request's author, which a commit message or a re-run cannot change:
    # `github.actor` names whoever triggered the run.
    assert "if: github.event.pull_request.user.login == 'dependabot[bot]'" in text
    assert "github.actor" not in text


def test_it_runs_the_base_branchs_script_without_credentials_and_asks_for_a_squash():
    text = _workflow()

    assert "ref: ${{ github.event.pull_request.base.sha }}" in text
    assert "persist-credentials: false" in text
    assert "python3 scripts/dependabot_auto_merge.py" in text
    assert re.search(r'gh pr merge --auto --squash "\$PR_URL"', text)


def test_no_expression_is_expanded_inside_a_shell_command():
    """Values reach `run:` through `env:` only, so nothing from the pull request is ever
    spliced into a script."""
    text = _workflow()
    for block in re.findall(r"run: \|\n((?:          .*\n)+)", text):
        assert "${{" not in block, block
