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


def _job(workflow: Path, job: str) -> list[str]:
    """The lines of one job of the example."""
    lines = workflow.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"  {job}:")
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("  ") and not lines[i].startswith("   ")
                and lines[i].rstrip().endswith(":")), len(lines))
    return lines[start:end]


def _run_blocks(workflow: Path, job: str = "scan") -> list[str]:
    """Each `run: |` block of one job of the example, in order, as the shell will see it."""
    blocks: list[str] = []
    lines = _job(workflow, job)
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


def test_the_example_gates_a_pull_request_on_what_it_adds():
    """R50.4: where a team would copy it from. The gate reads the base with git, which
    the image does not carry (ADR-0005), so this job installs valvur on the runner, at
    the version of the image the example names, and checks out the base's commits."""
    job = "\n".join(_job(GITHUB_EXAMPLE, "new-findings"))

    assert "if: github.event_name == 'pull_request'" in job
    assert "fetch-depth: 0" in job and "persist-credentials: false" in job
    assert 'pipx install "valvur==${VALVUR_IMAGE##*:}"' in job
    scan, gate = _run_blocks(GITHUB_EXAMPLE, "new-findings")
    assert scan.splitlines() == ["valvur update .", "valvur scan ."]
    assert gate.strip() == 'valvur gate . --new-since "origin/$GITHUB_BASE_REF" --fail-on high'
    # One pin for both jobs: the image's tag is the shim's version.
    text = GITHUB_EXAMPLE.read_text()
    assert text.count("ghcr.io/maverickhq/valvur:") == 1 and "valvur==1" not in text


def test_the_ci_page_states_what_the_gate_on_new_findings_does_not_do():
    page = " ".join((REPO / "docs" / "CI.md").read_text().split())

    assert "`valvur gate --new-since origin/main`" in page
    assert ("A finding in a file that was renamed, or a static-analysis finding whose matched "
            "text changed, has a new fingerprint and counts as new") in page
    assert ("It needs git and the base's commits: `fetch-depth: 0` on the checkout, and "
            "valvur on the runner, not the image as a step of its own, which carries no "
            "git") in page


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


@pytest.mark.e2e
def test_the_new_findings_job_fails_a_pull_request_that_adds_a_secret(mountable_tmp):
    """R50.4: the job's own two blocks, with the valvur of this tree and the image built
    from it, in a clone whose `origin/main` is the base: a pull request that adds a key
    fails, and one that adds nothing passes though the base has a key already."""
    import os
    import subprocess

    from valvur.runner import IMAGE

    git_env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

    def git(where: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(where), *args], check=True, capture_output=True,
                       env=git_env)

    origin, checkout = mountable_tmp / "origin.git", mountable_tmp / "checkout"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    subprocess.run(["git", "clone", "-q", str(origin), str(checkout)], check=True,
                   capture_output=True)
    (checkout / "config").mkdir()
    (checkout / "config" / "old.env").write_text(
        "AWS_ACCESS_KEY_ID=" + "AK" + "IA" + "V7Q2XR4TVBN6WLKJ\n")
    (checkout / ".gitignore").write_text(".security-scan/\n")
    git(checkout, "add", "-A")
    git(checkout, "commit", "-q", "-m", "the base")
    git(checkout, "push", "-q", "origin", "main")
    env = {**os.environ, "GITHUB_BASE_REF": "main", "VALVUR_IMAGE": IMAGE}
    scan, gate = _run_blocks(GITHUB_EXAMPLE, "new-findings")

    def job() -> subprocess.CompletedProcess[str]:
        done = subprocess.run(["bash", "-e", "-c", scan], cwd=checkout, env=env,
                              capture_output=True, text=True, timeout=1200, check=False)
        assert done.returncode == 0, f"{scan}\n{done.stdout}\n{done.stderr}"
        return subprocess.run(["bash", "-e", "-c", gate], cwd=checkout, env=env,
                              capture_output=True, text=True, timeout=1200, check=False)

    git(checkout, "checkout", "-q", "-b", "adds-nothing")
    (checkout / "README.md").write_text("# a change with no finding in it\n")
    git(checkout, "add", "-A")
    git(checkout, "commit", "-q", "-m", "docs")
    quiet = job()
    assert quiet.returncode == 0, quiet.stdout + quiet.stderr
    assert "since origin/main" in quiet.stdout and "were already there" in quiet.stdout

    git(checkout, "checkout", "-q", "-b", "adds-a-key")
    (checkout / "config" / "new.env").write_text(
        "AWS_ACCESS_KEY_ID=" + "AK" + "IA" + "T6H2WQ7XKC4PMV3J\n")
    git(checkout, "add", "-A")
    git(checkout, "commit", "-q", "-m", "a key")
    loud = job()
    assert loud.returncode == 1, loud.stdout + loud.stderr
    assert "config/new.env" in loud.stdout and "config/old.env" not in loud.stdout.split(
        "gate:")[0]


def test_valvurs_own_pull_requests_are_gated_on_what_they_add():
    """R50.4's proof, held: the self-scan job fetches the base branch's tip and runs
    `gate --new-since` on a pull request. The job's own gate fails on any finding at
    all, so this one can only agree with it; it is there to be run, on every pull
    request, as a user's would be. The base's name reaches the shell as a variable."""
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    job = ci.split("\n  selfscan:\n", 1)[1]
    step = job.split("Gate this pull request on what it adds", 1)[1].split("\n      - name:", 1)[0]

    assert "if: github.event_name == 'pull_request'" in step
    assert "BASE_REF: ${{ github.base_ref }}" in step
    run = step.split("run: |", 1)[1]
    assert 'git fetch -q --no-tags --depth=1 origin "$BASE_REF"' in run
    assert 'valvur gate . --fail-on any --new-since "origin/$BASE_REF"' in run
    assert "${{" not in run
