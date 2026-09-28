"""R8.1: the image scans on its own (D15; F1.10).

`valvur scan` runs inside the image on a mounted or cloned checkout, with no
container runtime to reach: the same engine runs as a process in the image, its
container paths pointed at directories there, and the results can go to a mounted
directory while the checkout stays read-only.
"""

from __future__ import annotations

import sys
from pathlib import Path

from valvur.engine_host import LocalRuntime, snapshot
from valvur.invocation import Invocation


def test_the_engine_maps_the_cache_in_arguments_and_in_a_tools_environment(tmp_path):
    """Trivy is told `--cache-dir /cache/trivy`, OSV-Scanner reads its database from
    `/cache/osv` by a variable: in the image the cache is a directory of the job's,
    so both forms are pointed at it. Without a cache the paths stay the container's."""
    from valvur.engine import _mapped

    ws, results, cache = tmp_path / "ws", tmp_path / "results", tmp_path / "cache"
    assert _mapped("/cache/trivy", ws, results, cache) == f"{cache}/trivy"
    assert _mapped("--cache-dir=/cache/trivy", ws, results, cache) == \
        f"--cache-dir={cache}/trivy"
    assert _mapped("/cache/trivy", ws, results) == "/cache/trivy"
    assert _mapped("/cached", ws, results, cache) == "/cached"

    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    LocalRuntime(cache=cache).run(
        [Invocation(tool="env", version="0", report="env.txt",
                    argv=(sys.executable, "-c",
                          "import os, sys; open(sys.argv[1], 'w').write(os.environ['DB'])",
                          "/results/env.txt"),
                    env=(("DB", "/cache/osv"),))],
        snapshot(source, ["a.py"]), scratch)

    assert (scratch / "env.txt").read_text() == f"{cache}/osv"



def test_a_path_after_a_scheme_is_mapped_too(tmp_path):
    """Syft is told `dir:/workspace`: run as a process, it scanned the image's own
    empty `/workspace` and wrote an SBOM of nothing, measured on acceptance
    repository 2 (0 components against the host's 16)."""
    from valvur.engine import _mapped

    ws, results = tmp_path / "ws", tmp_path / "results"
    assert _mapped("dir:/workspace", ws, results) == f"dir:{ws}"
    assert _mapped("https://example.invalid/workspace", ws, results) == \
        "https://example.invalid/workspace"

def test_the_name_check_is_told_where_the_index_is_so_the_engine_can_move_it(tmp_path):
    """The Check read `/cache/names` from a constant unless a variable said otherwise;
    its invocation now says it, and the engine maps it with the rest of the cache."""
    from valvur.adapters import CheckAdapter
    from valvur.checks.dependency_reality import INDEX_ENV, INDEX_MOUNT

    invocation = CheckAdapter("dependency-reality", uses_network=True,
                              network=True).command(tmp_path)

    assert (INDEX_ENV, INDEX_MOUNT) in invocation.env


def _repository(tmp_path):
    import subprocess

    ws = tmp_path / "repo"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "PATH": __import__("os").environ["PATH"], "HOME": str(tmp_path)}
    for argv in (["init", "-q"], ["add", "app.py"], ["commit", "-qm", "one"]):
        subprocess.run(["git", "-C", str(ws), *argv], env=env, check=True)
    return ws


def test_a_repository_without_git_to_ask_is_walked_and_says_why(tmp_path, monkeypatch):
    """The image carries no `git` (ADR-0005). A checkout scanned inside it was a
    git view that raised; it is a walk of the folder, which reads ignored files
    too, and the scope says so."""
    from valvur import fileset

    ws = _repository(tmp_path)
    monkeypatch.setattr(fileset, "git", lambda: None)

    chosen = fileset.build(ws)

    assert chosen.scope == "tree"
    assert chosen.files == ["app.py"]
    assert "git" in (chosen.note or "")
    assert chosen.manifest(ws)["note"] == chosen.note


def test_history_unread_for_want_of_git_is_said_on_the_report(tmp_path, monkeypatch):
    import json

    from valvur import api, fileset
    from valvur.adapters import GitleaksAdapter

    fake_tools = Path(__file__).parent / "fixtures" / "fake-tools"
    ws = _repository(tmp_path)
    monkeypatch.setattr(fileset, "git", lambda: None)

    api.scan(ws, runner=LocalRuntime(fake_tools), adapters=[GitleaksAdapter()])

    run = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert "git" in run["history"]["unavailable"]
    summary = (ws / ".security-scan" / "SUMMARY.md").read_text()
    assert "Git history was not read for secrets" in summary


def _fake_trivy(tmp_path):
    """A `trivy` that records its arguments and succeeds."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    trivy = bin_dir / "trivy"
    trivy.write_text(f"#!{sys.executable}\nimport sys\n"
                     f"open({str(tmp_path / 'argv.txt')!r}, 'w').write(' '.join(sys.argv[1:]))\n")
    trivy.chmod(0o755)
    return bin_dir


def test_inside_the_image_a_scan_runs_the_engine_as_a_process(tmp_path, monkeypatch):
    """No runtime to start a container from inside a container: the same engine
    runs as a process there, the job's cache at `/cache`, and there is no image to
    pull and no second tree to compare."""
    from valvur import cache, engine_host

    monkeypatch.setenv("VALVUR_IN_IMAGE", "1")
    monkeypatch.setenv("VALVUR_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("PATH", f"{_fake_trivy(tmp_path)}:{__import__('os').environ['PATH']}")

    runtime = engine_host.for_scan()

    assert isinstance(runtime, engine_host.ImageRuntime)
    assert runtime.cache == cache.root()
    assert runtime.image_present() is True
    runtime.verify_compatible()
    shim, image = runtime.build_provenance()
    assert shim == image
    fetched = runtime.update_db()
    assert fetched.exit_code == 0
    argv = (tmp_path / "argv.txt").read_text()
    assert f"--cache-dir {cache.root()}/trivy" in argv
    assert "--download-db-only" in argv


def test_outside_the_image_a_scan_starts_a_scan_container(monkeypatch):
    from valvur import engine_host

    monkeypatch.delenv("VALVUR_IN_IMAGE", raising=False)

    assert isinstance(engine_host.for_scan(), engine_host.ContainerRuntime)


def test_the_results_can_go_to_a_directory_of_their_own(tmp_path):
    """A checkout mounted read-only into a pipeline step cannot hold
    `.security-scan/`: `--out DIR` writes it under DIR, the next scan's new and
    fixed are read from there, and `gate` reads DIR as it reads a workspace."""
    import json
    import os

    from valvur import cli

    fake_tools = Path(__file__).parent / "fixtures" / "fake-tools"
    ws = tmp_path / "checkout"
    ws.mkdir()
    (ws / "config.py").write_text('AWS = "AKIA' + "Q" * 16 + '"\n')
    out = tmp_path / "out"
    out.mkdir()
    ws.chmod(0o555)
    try:
        for _ in range(2):
            assert cli.main(["scan", str(ws), "--out", str(out)],
                            runner=LocalRuntime(fake_tools)) == 0
    finally:
        ws.chmod(0o755)

    assert not (ws / ".security-scan").exists()
    findings = json.loads((out / ".security-scan" / "findings.json").read_text())["findings"]
    assert [f["status"] for f in findings if f["rule"] == "aws-access-token"] == ["persisting"]
    assert (out / ".security-scan" / ".gitignore").read_text() == "*\n"
    assert cli.main(["gate", str(out), "--fail-on", "high"]) == 1
    assert os.access(ws, os.W_OK)


def test_in_the_image_the_boundary_is_the_jobs_and_the_report_says_which(tmp_path, monkeypatch):
    """The Scan Container has no network interface on `offline`; a job's container
    has whatever the job gave it. The Scanners run offline either way, but only a
    job with no network makes that structural, so the run says which it had."""
    from valvur import engine_host

    net = tmp_path / "net"
    # What `--network=none` leaves, measured in the image: the loopback, the kernel's
    # tunnel devices, down, and a file that is not an interface.
    for name, flags in (("lo", "0x9"), ("sit0", "0x80"), ("tunl0", "0x80")):
        (net / name).mkdir(parents=True)
        (net / name / "flags").write_text(flags + "\n")
    (net / "bonding_masters").write_text("\n")
    assert engine_host.job_boundary(net) == "this job's container, with no network"
    (net / "eth0").mkdir()
    (net / "eth0" / "flags").write_text("0x1003\n")
    assert engine_host.job_boundary(net) == "this job's container, with a network: eth0"


def test_a_scan_records_its_boundary_and_the_summary_names_a_network_on_offline(tmp_path):
    import json

    from valvur import api
    from valvur.adapters import GitleaksAdapter

    class JobRuntime(LocalRuntime):
        def boundary(self):
            return "this job's container, with a network: eth0"

    fake_tools = Path(__file__).parent / "fixtures" / "fake-tools"
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("x = 1\n")

    api.scan(ws, runner=JobRuntime(fake_tools), adapters=[GitleaksAdapter()])

    run = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert run["network"]["boundary"] == "this job's container, with a network: eth0"
    summary = (ws / ".security-scan" / "SUMMARY.md").read_text()
    assert "--network=none" in summary

    api.scan(ws, runner=LocalRuntime(fake_tools), adapters=[GitleaksAdapter()])
    run = json.loads((ws / ".security-scan" / "run.json").read_text())
    assert run["network"]["boundary"] == "the Scan Container"
    assert "--network=none" not in (ws / ".security-scan" / "SUMMARY.md").read_text()



def test_a_report_names_the_workspace_as_a_scan_container_would(tmp_path):
    """A tool given the workspace's real path reports that path; the adapters read
    `/workspace/...`, as every tool writes it in a Scan Container. Run as a process,
    the engine's reports are handed back in the container's terms."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "config.py").write_text("x = 1\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    LocalRuntime().run(
        [Invocation(tool="paths", version="0", report="paths.json",
                    argv=(sys.executable, "-c",
                          "import json, sys; json.dump({'path': sys.argv[1] + '/config.py'},"
                          " open(sys.argv[2], 'w'))",
                          "/workspace", "/results/paths.json"))],
        snapshot(source, ["config.py"]), scratch)

    assert (scratch / "paths.json").read_text() == '{"path": "/workspace/config.py"}'


import pytest  # noqa: E402

KEY = "AKIA" + "QX3ZR5TW7YB2MN4P"          # assembled: push protection is on


@pytest.mark.e2e
def test_the_image_scans_a_read_only_checkout_into_a_mounted_directory(mountable_tmp):
    """R8.1 behaviour 1: `docker run` of the image on a checkout, with no network
    and no socket, writes the Results Folder to a mounted output directory. The
    checkout is mounted read-only and stays untouched; the cache is the host's."""
    import json
    import os
    import platform
    import subprocess

    from valvur import cache
    from valvur.runner import IMAGE, detect_runtime

    checkout = mountable_tmp / "checkout"
    checkout.mkdir()
    (checkout / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{KEY}"\n')
    (checkout / "requirements.txt").write_text("requests==2.19.0\n")
    out = mountable_tmp / "out"
    out.mkdir()
    user = [] if platform.system() == "Darwin" else ["--user", f"{os.getuid()}:{os.getgid()}"]

    done = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", *user,
         "-e", "VALVUR_CACHE=/cache", "-v", f"{cache.root()}:/cache/valvur",
         "-v", f"{checkout}:/src:ro", "-v", f"{out}:/out",
         IMAGE, "valvur", "scan", "/src", "--out", "/out"],
        capture_output=True, text=True, timeout=900, check=False)

    assert done.returncode == 0, done.stdout + done.stderr
    folder = out / ".security-scan"
    findings = json.loads((folder / "findings.json").read_text())["findings"]
    found = {(f["rule"], f["path"]) for f in findings}
    assert ("aws-access-token", "config.py") in found
    assert any(rule.startswith("CVE-") and path == "requirements.txt" for rule, path in found)
    sbom = json.loads((folder / "sbom.cdx.json").read_text())
    assert "requests" in {c.get("name") for c in sbom.get("components", [])}
    run = json.loads((folder / "run.json").read_text())
    assert run["network"]["boundary"] == "this job's container, with no network"
    assert run["network"]["what_left_the_machine"] == "nothing"
    assert sorted(p.name for p in checkout.iterdir()) == ["config.py", "requirements.txt"]
