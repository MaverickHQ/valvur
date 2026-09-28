"""29.1.3 — the runtime's memory, read and said (the gate's B7; N1.4). The width it
set for the thread-pool fleet ended with that fleet in R3.9.

Measured on this Mac's 3.8 GiB Docker Desktop VM, on the synthetic gate tree
with its archive excluded: `--jobs 8` wall 23.6 s, `4` 22.0 s, `2` 20.3 s — and
at two, every Scanner two to five times faster alone (Gitleaks 4.2 → 2.1 s,
Checkov 15.7 → 7.2 s, the Checks 7.3 → 1.4 s); on the gate's own tree 88 s at
eight against 83.5 s at two. Eight containers in a 4 GiB VM contend; the
default now follows the runtime's memory, and `doctor` says what it will be.
"""

from __future__ import annotations

import subprocess

from valvur import runner as _runner

GIB = 2**30


def _fake_info(monkeypatch, stdout: str, returncode: int = 0):
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode, stdout, "")
    monkeypatch.setattr(subprocess, "run", run)
    _runner.runtime_resources.cache_clear()


def test_the_runtime_answers_its_memory_and_cpus_on_both_runtimes(monkeypatch):
    _fake_info(monkeypatch, "4108828672 8\n")
    assert _runner.runtime_resources("/usr/local/bin/docker") == (4108828672, 8)
    _runner.runtime_resources.cache_clear()
    _fake_info(monkeypatch, "8589934592 4\n")
    assert _runner.runtime_resources("/opt/podman/bin/podman") == (8589934592, 4)
    _fake_info(monkeypatch, "", returncode=1)
    assert _runner.runtime_resources("/usr/local/bin/docker") == (None, None)


def test_doctor_says_the_memory_and_what_the_default_will_be(monkeypatch):
    from valvur import doctor

    monkeypatch.setattr(doctor, "_find_runtime", lambda: "/usr/local/bin/docker")
    monkeypatch.setattr(doctor, "_runtime_version", lambda runtime: "Docker 29.2.1")
    monkeypatch.setattr(doctor, "_runtime_running", lambda runtime: (True, ""))
    monkeypatch.setattr(_runner, "runtime_resources", lambda runtime: (int(3.8 * GIB), 8))

    _, check = doctor._check_runtime()

    assert check.level == "ok"
    assert "3.8 GiB, 8 CPUs" in check.detail
    # Since R3.9 one Scan Container runs every Scanner at once; the size is what
    # a person weighs before bounding it.
    assert "every Scanner runs at once" in check.detail and "`jobs`" in check.detail
