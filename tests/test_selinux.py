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

The saving grace: valvur **fails loudly** rather than reporting a false clean. The
probe runs `ls -A /workspace | wc -l`, which returns 0 under denial while the host has
entries, so `WorkspaceUnreadable` is raised. Verified verbatim on the enforcing host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from valvur import runner


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
    monkeypatch.setattr(runner, "SELINUX_ENFORCE", enforce)

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
        tmp_path, str(tmp_path / "scratch")
    )
    mounts = _mounts(flags)

    assert mounts["/results"].endswith(":z")
    assert mounts["/cache/trivy"].endswith(":z")


def test_the_source_tree_is_not_relabelled_unless_asked(enforcing, tmp_path, monkeypatch):
    """CLAUDE.md section 10: any feature that writes to the scanned source tree needs
    explicit owner approval. `:z` rewrites the SELinux context of every file in the
    Workspace and the change persists after the scan."""
    monkeypatch.delenv(runner.RELABEL_ENV, raising=False)

    flags = runner.ContainerRunner(image="x", runtime="podman")._base_flags(
        tmp_path, str(tmp_path / "scratch")
    )

    assert _mounts(flags)["/workspace"].endswith(":ro")


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE"])
def test_the_source_tree_is_relabelled_when_asked(enforcing, tmp_path, monkeypatch, value):
    monkeypatch.setenv(runner.RELABEL_ENV, value)

    flags = runner.ContainerRunner(image="x", runtime="podman")._base_flags(
        tmp_path, str(tmp_path / "scratch")
    )

    # `,z` and not `:z` — the mount already carries a mode. Measured: `-v src:dst,z`
    # is parsed as a destination path literally named "dst,z".
    assert _mounts(flags)["/workspace"].endswith(":ro,z")


def test_nothing_is_relabelled_on_a_host_without_selinux(not_enforcing, tmp_path, monkeypatch):
    """The pair. A `:z` on a machine with no SELinux is noise in every command line
    valvur emits, and noise in a command line is how a real flag gets overlooked."""
    monkeypatch.setenv(runner.RELABEL_ENV, "1")

    flags = runner.ContainerRunner(image="x", runtime="podman")._base_flags(
        tmp_path, str(tmp_path / "scratch")
    )
    mounts = _mounts(flags)

    assert mounts["/workspace"].endswith(":ro")
    assert mounts["/results"].endswith("/results")
    assert mounts["/cache/trivy"].endswith("/cache/trivy")


# --------------------------------------------------------------------- the message

def test_an_enforcing_host_gets_a_diagnosis_not_a_shrug(enforcing):
    """Before this, a RHEL user met *"Check the path exists and that your container
    runtime is permitted to mount it."* — a loud failure with no way to act on it."""
    hint = runner._unreadable_hint("podman", Path("/home/dev/repo"))

    assert "SELinux is enforcing" in hint
    assert runner.RELABEL_ENV in hint
    assert "chcon -R -t container_file_t /home/dev/repo" in hint
    assert "restorecon -R -F" in hint, "a fix with no undo is not a fix"


def test_the_undo_command_is_the_one_that_actually_works():
    """`restorecon -R` alone does **nothing** here, measured on the enforcing host.
    `container_file_t` is listed in the policy's `customizable_types`, and restorecon
    skips those unless forced.

    This shipped in the first draft of the message. A remediation instruction that
    silently does nothing is worse than no instruction: the reader believes they have
    undone it.
    """
    hint = runner._selinux_hint(Path("/home/dev/repo"))

    assert "restorecon -R -F /home/dev/repo" in hint
    assert "customizable type" in hint


def test_the_message_says_why_capital_Z_is_not_offered(enforcing):
    """Measured, not assumed: after a `:Z` mount the tree carries a private MCS
    category and a second container is denied. valvur launches its Scanners
    concurrently against one mount, so `:Z` would break the fleet."""
    hint = runner._unreadable_hint("podman", Path("/home/dev/repo"))

    assert ":Z" in hint and "concurrently" in hint


def test_selinux_outranks_the_macos_podman_diagnosis(enforcing):
    """Both branches can look plausible. An enforcing host is the far more specific
    answer, and the two never co-occur — macOS has no SELinux."""
    hint = runner._unreadable_hint("podman", Path("/home/dev/repo"))

    assert "podman machine set" not in hint
