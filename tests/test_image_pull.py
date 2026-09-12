"""Task 23.2.4 — the image is pulled on `valvur update`, and a scan that has to
pull it says so (10.2 claim 4).

Measured through Kiro (22.G.1): the image was pulled on the first *scan*, silently,
under the runtime's `run` — and a first tool call that shows nothing for a minute is
indistinguishable from a hang. `docker image inspect` answers in milliseconds whether
the image is local; the registry's manifest says what a pull will cost.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest
from fake_registry import FakeRegistry

from valvur import api, oci
from valvur.runner import ContainerRunner, ImagePullFailed, ScannerOutput


class _Runner:
    """A runner whose image may or may not be local, recording what was asked."""

    image = "ghcr.io/maverickhq/valvur:9.9.9"
    runtime = "/usr/local/bin/docker"

    def __init__(self, *, present: bool, pull_exit: int = 0, size: int | None = 243):
        self.present = present
        self.pull_exit = pull_exit
        self.size = size
        self.calls: list[str] = []

    def image_present(self) -> bool:
        self.calls.append("inspect")
        return self.present

    def pull_size_mb(self):
        self.calls.append("size")
        return self.size

    def pull_image(self, on_line=None):
        self.calls.append("pull")
        self.present = self.pull_exit == 0
        return ScannerOutput("pull", "", "", "denied: requested access to the resource is denied",
                             self.pull_exit)


# ------------------------------------------------------------- the scan entry


def test_a_present_image_is_not_pulled_and_no_line_is_said():
    runner = _Runner(present=True)
    said: list[str] = []

    api._ensure_image(runner, said.append)

    assert runner.calls == ["inspect"]
    assert said == []


def test_an_absent_image_is_pulled_and_the_line_names_it_and_its_size():
    runner = _Runner(present=False)
    said: list[str] = []

    api._ensure_image(runner, said.append)

    assert runner.calls == ["inspect", "size", "pull"]
    assert said[0].startswith("pulling ghcr.io/maverickhq/valvur:9.9.9 (243MB)")
    assert "first run only" in said[0]
    assert said[1].startswith("image pulled (")


def test_a_size_the_registry_cannot_state_is_left_out_rather_than_invented():
    runner = _Runner(present=False, size=None)
    said: list[str] = []

    api._ensure_image(runner, said.append)

    assert said[0].startswith("pulling ghcr.io/maverickhq/valvur:9.9.9 —")
    assert "MB" not in said[0]


def test_a_failed_pull_is_a_named_failure_with_the_runtime_words_and_the_fix():
    runner = _Runner(present=False, pull_exit=1)

    with pytest.raises(ImagePullFailed) as caught:
        api._ensure_image(runner, None)

    text = str(caught.value)
    assert "requested access to the resource is denied" in text
    assert "docker pull ghcr.io/maverickhq/valvur:9.9.9" in text


def test_a_runner_without_the_ability_is_left_alone():
    """The fake runners in the suite have no `image_present`; a scan through them
    must not need one."""
    class Bare:
        pass

    api._ensure_image(Bare(), None)


def test_the_pull_happens_before_the_compatibility_check(tmp_path, monkeypatch):
    """`compat.check` inspects the image; on a missing image it reads no label and
    passes, so it must not be the first thing to run."""
    order: list[str] = []

    class Runner(_Runner):
        def verify_compatible(self):
            order.append("compat")
            raise RuntimeError("stop here")

        def image_present(self):
            order.append("inspect")
            return False

        def pull_image(self, on_line=None):
            order.append("pull")
            return ScannerOutput("pull", "", "", "", 0)

    with pytest.raises(RuntimeError, match="stop here"):
        api._scan_locked(tmp_path, runner=Runner(present=False), adapters=[], profile="offline",
                         on_progress=None)

    assert order == ["inspect", "pull", "compat"]


# ------------------------------------------------------------- the MCP surface


def test_scan_status_says_the_image_is_being_pulled_while_it_is(tmp_path, monkeypatch):
    """Claim 4 of 10.2 on the surface an agent reads: not "starting" for a minute,
    but the image, its size, and that this is the first run only."""
    from valvur.mcp import jobs
    from valvur.operations import scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    def work(workspace, profile, progress):
        progress("pulling ghcr.io/maverickhq/valvur:0.2.0 (243MB) — the first run only; "
                 "the runtime keeps it")
        time.sleep(0.6)
        progress("image pulled (30s)")
        progress("trivy: ok")
        time.sleep(0.6)
        return "done"

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.05)
    during = scan_status({"workspace": str(tmp_path)})
    time.sleep(0.7)
    after = scan_status({"workspace": str(tmp_path)})
    jobs.reset()

    assert "RUNNING" in during
    assert "Now: pulling ghcr.io/maverickhq/valvur:0.2.0 (243MB)" in during
    assert "Completed so far: starting" in during
    assert "RUNNING" in after
    assert "Now: pulling" not in after, "the pull is over; the line goes"
    assert "image pulled (30s), trivy: ok" in after


# -------------------------------------------------------------- the runtime


def test_image_present_asks_the_runtime_and_pull_streams_its_output(monkeypatch):
    launched: list[list[str]] = []

    def run(cmd, **kwargs):
        launched.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if "inspect" in cmd else 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    runner = ContainerRunner(image="ghcr.io/acme/img:1", runtime="/usr/local/bin/docker")

    assert runner.image_present() is False
    result = runner.pull_image()

    assert launched[0] == ["/usr/local/bin/docker", "image", "inspect", "ghcr.io/acme/img:1"]
    assert launched[1] == ["/usr/local/bin/docker", "pull", "ghcr.io/acme/img:1"]
    assert result.exit_code == 0


def test_pull_lines_reach_the_terminal_when_asked(monkeypatch, tmp_path):
    """`valvur update` streams the runtime's own progress; a scan over MCP captures
    it. Same command either way."""
    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\necho \"$@\"\necho 'Status: Downloaded newer image'\nexit 0\n")
    fake.chmod(0o755)
    runner = ContainerRunner(image="ghcr.io/acme/img:1", runtime=str(fake))
    seen: list[str] = []

    result = runner.pull_image(on_line=seen.append)

    assert seen == ["pull ghcr.io/acme/img:1", "Status: Downloaded newer image"]
    assert result.exit_code == 0


# --------------------------------------------------------- `valvur update`


def test_update_pulls_the_image_first_and_streams_it(monkeypatch, capsys):
    from valvur import cli

    order: list[str] = []

    class Runner(_Runner):
        def pull_image(self, on_line=None):
            order.append("pull")
            on_line("Status: Downloaded newer image")
            return ScannerOutput("pull", "", "", "", 0)

        def update_db(self):
            order.append("db")
            return ScannerOutput("trivy-db", "", "", "", 0)

    monkeypatch.setattr(cli, "_refresh_kev", lambda: order.append("kev"))
    monkeypatch.setattr(cli, "_refresh_name_index", lambda **_: order.append("index") or True)

    assert cli.main(["update"], runner=Runner(present=False)) == 0

    assert order == ["pull", "db", "kev", "index"]
    out = capsys.readouterr().out
    assert "Pulling the image ghcr.io/maverickhq/valvur:9.9.9 (about 243MB)" in out
    assert "  Status: Downloaded newer image" in out


def test_update_does_not_pull_an_image_it_already_has(monkeypatch, capsys):
    from valvur import cli

    class Runner(_Runner):
        def update_db(self):
            return ScannerOutput("trivy-db", "", "", "", 0)

    runner = Runner(present=True)
    monkeypatch.setattr(cli, "_refresh_kev", lambda: None)
    monkeypatch.setattr(cli, "_refresh_name_index", lambda **_: True)

    assert cli.main(["update"], runner=runner) == 0
    assert "pull" not in runner.calls
    assert "Pulling" not in capsys.readouterr().out


def test_a_failed_pull_fails_the_update_before_the_database(monkeypatch, capsys):
    from valvur import cli

    class Runner(_Runner):
        def update_db(self):
            raise AssertionError("the database update ran without an image")

    assert cli.main(["update"], runner=Runner(present=False, pull_exit=1)) == 1
    out = capsys.readouterr().out
    assert "Image pull failed" in out and "docker pull ghcr.io/maverickhq/valvur:9.9.9" in out


# -------------------------------------------------------------- the size


def _push_image(registry: FakeRegistry, name: str, layers_by_arch: dict[str, list[int]]):
    """An image index with one platform manifest per architecture, the shape
    `docker buildx --platform linux/amd64,linux/arm64 --push` produces."""
    from fake_registry import _digest

    entries = []
    for arch, sizes in layers_by_arch.items():
        manifest = {
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": _digest(b"{}"), "size": 2},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": _digest(f"{arch}{i}".encode()), "size": size}
                       for i, size in enumerate(sizes)],
        }
        raw = json.dumps(manifest).encode()
        registry.manifests[f"{name}:{_digest(raw)}"] = (raw, manifest["mediaType"])
        entries.append({"mediaType": manifest["mediaType"], "digest": _digest(raw),
                        "size": len(raw), "platform": {"os": "linux", "architecture": arch}})
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": entries}
    raw = json.dumps(index).encode()
    registry.manifests[f"{name}:latest"] = (raw, index["mediaType"])


def test_the_size_is_this_architectures_layers_from_the_index(monkeypatch):
    """Measured 2026-09-12 against `ghcr.io/aquasecurity/trivy:0.65.0`, a real
    multi-platform image: 53MB for arm64 in 0.9s, anonymously. The fake reproduces
    the shape; a wrong architecture would quote the other platform's bytes."""
    import platform

    monkeypatch.setattr(platform, "machine", lambda: "arm64")
    with FakeRegistry() as registry:
        _push_image(registry, "acme/img", {"amd64": [100, 200], "arm64": [10, 20, 30]})

        assert oci.image_size(f"{registry.host}/acme/img:latest") == 60

        monkeypatch.setattr(platform, "machine", lambda: "x86_64")
        assert oci.image_size(f"{registry.host}/acme/img:latest") == 300

        monkeypatch.setattr(platform, "machine", lambda: "riscv64")
        assert oci.image_size(f"{registry.host}/acme/img:latest") is None


def test_an_unreachable_or_local_only_image_has_no_size():
    assert oci.image_size("valvur:dev") is None
    assert oci.image_size("ghcr.io/maverickhq/does-not-exist:1") is None


def test_the_shim_never_pulls_through_the_registry_client(tmp_path):
    """The client reads manifests and blobs of the *index*; the image is the
    runtime's to pull. Pinned so the ~240MB never streams through Python."""
    import inspect

    from valvur import runner

    source = inspect.getsource(runner.ContainerRunner.pull_image)
    assert '"pull"' in source and "oci." not in source
    assert Path(inspect.getsourcefile(oci)).name == "oci.py"
