"""F1.6 — SELinux mount labelling (Phase 20).

**Measured on a real enforcing host, 2026-09-10:** Fedora CoreOS 44, native xfs on a
block device (not virtiofs), SELinux `targeted` policy in enforcing mode,
`container-selinux` installed. Both rootful and rootless Podman.

| What was mounted | Result |
|---|---|
| workspace under `$HOME`, plain `:ro` | **Permission denied** |
| valvur's scratch dir, plain `:rw` | **Permission denied** |
| the Trivy DB cache, plain `:rw` | **Permission denied** |
| any of the above with `:z` | works |
| `:Z`, then a second concurrent container | **Permission denied** |

So F1.6 was a real defect, not a theoretical one — and `:Z` is ruled out by valvur's
own architecture, because Scanners run concurrently against one mount.

Since R3.9 the source is streamed into the Scan Container and never mounted
(ADR-0022), so its label no longer matters and nothing asks to relabel it; the
unreadable-workspace probe went with the mount. valvur's own mounts are labelled.
"""

from __future__ import annotations

import pytest

from valvur import runner, selinux


@pytest.fixture
def enforcing(monkeypatch):
    monkeypatch.setattr(runner, "selinux_enforcing", lambda: True)


@pytest.fixture
def not_enforcing(monkeypatch):
    monkeypatch.setattr(runner, "selinux_enforcing", lambda: False)


def _mounts(flags: list[str]) -> dict[str, str]:
    """Map container destination -> the full -v argument."""
    out = {}
    for i, flag in enumerate(flags):
        if flag == "-v":
            spec = flags[i + 1]
            out[spec.split(":")[1]] = spec
    return out


# ------------------------------------------------------------------- detection

@pytest.mark.parametrize("contents,expected", [("1\n", True), ("0\n", False)])
def test_enforcing_is_read_from_the_kernel_not_guessed(monkeypatch, tmp_path,
                                                       contents, expected):
    """Both directions, against a real file.

    `permissive` (`0`) must read as not-enforcing: it logs the denial and allows the
    access, so relabelling would be a write to someone's tree in exchange for nothing.
    """
    enforce = tmp_path / "enforce"
    enforce.write_text(contents)
    monkeypatch.setattr(selinux, "SELINUX_ENFORCE", enforce)

    assert runner.selinux_enforcing() is expected


def test_a_host_without_selinux_is_not_enforcing():
    """macOS and most Linux distributions have no /sys/fs/selinux at all. Reading it
    must not raise — this runs on every scan."""
    import platform

    if platform.system() == "Darwin":
        assert runner.selinux_enforcing() is False


# ---------------------------------------------------------------- what gets a label

def test_valvurs_own_directories_are_relabelled_without_being_asked(enforcing, tmp_path):
    """The scratch mount and the DB cache are a temporary directory we created and a
    cache we own. Measured: without a label the container cannot write its results at
    all, so valvur would be unusable on an enforcing host for no principled gain."""
    flags = runner.ContainerRunner(image="x", runtime="podman")._base_flags(
        str(tmp_path / "scratch")
    )
    mounts = _mounts(flags)

    assert mounts["/results"].endswith(":z")
    assert mounts["/cache/trivy"].endswith(":z")


def test_nothing_is_relabelled_on_a_host_without_selinux(not_enforcing, tmp_path, monkeypatch):
    """The pair. A `:z` on a machine with no SELinux is noise in every command line
    valvur emits, and noise in a command line is how a real flag gets overlooked."""
    monkeypatch.setenv(runner.RELABEL_ENV, "1")

    flags = runner.ContainerRunner(image="x", runtime="podman")._base_flags(
        str(tmp_path / "scratch")
    )
    mounts = _mounts(flags)

    assert mounts["/results"].endswith("/results")
    assert mounts["/cache/trivy"].endswith("/cache/trivy")


# --------------------------------------------------------------------- the message


def test_the_source_is_never_mounted_so_never_relabelled_even_when_asked(
        enforcing, tmp_path, monkeypatch):
    """CLAUDE.md section 10: nothing writes to the scanned source tree. `:z` did,
    when asked, because the source was a mount; since R3.9 it is not one, on the
    database fetch or the Scan Container."""
    from valvur import cache, engine_host

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    monkeypatch.setattr(engine_host, "selinux_enforcing", lambda: True)
    monkeypatch.setenv(runner.RELABEL_ENV, "1")
    workspace = tmp_path / "ws"
    for argv in (runner.ContainerRunner(image="x", runtime="podman")._base_flags(
                     str(tmp_path / "scratch")),
                 engine_host.ContainerRuntime(image="x", runtime="podman").command(
                     tmp_path / "scratch")):
        mounts = _mounts(argv)
        assert "/workspace" not in mounts or "snapshot" in mounts["/workspace"], mounts
        assert not any(str(workspace) in m for m in mounts.values()), mounts
