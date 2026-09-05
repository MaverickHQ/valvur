"""Phase 13 — the published artifact runs on the machines people actually have.

Measured 2026-09-05: the published image was `linux/arm64` only, so every amd64 user
— most CI runners, most Linux desktops, every cloud VM, every Intel Mac — could not
run it. The Dockerfile was already arch-aware; it had simply been published
single-arch from an Apple Silicon Mac.

**The gap mattered more than the defect.** Both workflows `docker build` locally and
neither ever pulled the published image, so CI could not catch this class at all —
not this bug, and not the next one shaped like it. These tests are pointed at the
PUBLISHED artifact for that reason.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request

import pytest

from valvur.version import IMAGE_REPOSITORY, __version__

REQUIRED_PLATFORMS = {"linux/amd64", "linux/arm64"}


def _publicly_pullable() -> bool:
    """Whether an anonymous client can obtain a pull token.

    While the package is private (task 12a.1) these tests cannot run at all. They
    skip with the reason rather than passing, because a skip that reads as a pass is
    how the single-arch image shipped in the first place.
    """
    repository = IMAGE_REPOSITORY.split("/", 1)[1]
    url = (
        f"https://ghcr.io/token?scope=repository:{repository}:pull"
        "&service=ghcr.io"
    )
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _published_platforms() -> set[str]:
    result = subprocess.run(
        ["docker", "manifest", "inspect", f"{IMAGE_REPOSITORY}:{__version__}"],
        capture_output=True, text=True, check=False, timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(
            f"cannot inspect the published manifest: {result.stderr.strip()[:300]}"
        )
    document = json.loads(result.stdout)
    manifests = document.get("manifests")
    if not manifests:
        # A single-platform push produces a bare manifest with no platform list. That
        # is the defect, not an inconclusive result.
        return set()
    return {
        f"{m['platform']['os']}/{m['platform']['architecture']}"
        for m in manifests
        if m.get("platform", {}).get("architecture") != "unknown"
    }


@pytest.mark.e2e
def test_the_published_image_supports_amd64_and_arm64():
    """The release blocker, as a test.

    It is deliberately pointed at the published tag rather than a local build. A
    local build always matches the machine that made it, which is precisely why
    nobody noticed for a week.
    """
    if not _publicly_pullable():
        pytest.skip(
            f"{IMAGE_REPOSITORY} is not publicly pullable (task 12a.1). This test "
            "cannot verify the published artifact until it is, and passing would be "
            "a lie — the single-arch image shipped because nothing looked here."
        )

    platforms = _published_platforms()

    missing = REQUIRED_PLATFORMS - platforms
    assert not missing, (
        f"published image is missing {sorted(missing)} — it advertises "
        f"{sorted(platforms) or 'a single platform with no manifest list'}. "
        "Every user on a missing architecture gets an artifact that cannot run."
    )


def test_the_dockerfile_can_build_for_both_architectures():
    """The build's half of the same claim, checkable without a registry.

    Opengrep publishes no image, so its binary is fetched per-architecture and
    selected by TARGETARCH. If that selection were wrong, a multi-arch build would
    succeed and produce an image whose scanner cannot execute — a failure that looks
    like a scanner crash rather than a build defect.
    """
    from pathlib import Path

    dockerfile = Path("Dockerfile").read_text()

    assert "ARG TARGETARCH" in dockerfile
    assert "opengrep_amd64" in dockerfile and "opengrep_arm64" in dockerfile
    selector = "/tmp/opengrep_" + "${TARGETARCH}"  # noqa: S108 - a Dockerfile path, not ours
    assert selector in dockerfile, (
        "the per-architecture binary is no longer selected by TARGETARCH"
    )


# ------------------------------------------------------- native Windows (13.3)

def test_native_windows_is_warned_about_rather_than_claimed(monkeypatch):
    """Decided in 13.3: not claimed, not blocked.

    A hard refusal would be wrong — it may genuinely work and nobody has checked.
    Silence would be worse, because silence reads as "supported". Under WSL2 valvur
    is running on Linux, so this does not fire there.
    """
    import platform as platform_module

    from valvur.runner import unsupported_platform_warning

    monkeypatch.setattr(platform_module, "system", lambda: "Windows")
    warning = unsupported_platform_warning()

    assert "never been tested on native Windows" in warning
    assert "WSL2" in warning


@pytest.mark.parametrize("system", ["Linux", "Darwin"])
def test_supported_platforms_are_not_warned_about(monkeypatch, system):
    """The warning must mean something. One that fires everywhere is one nobody
    reads — the same reason the coverage caveat is gated on a real gap."""
    import platform as platform_module

    from valvur.runner import unsupported_platform_warning

    monkeypatch.setattr(platform_module, "system", lambda: system)

    assert unsupported_platform_warning() == ""


def test_the_mcp_server_never_writes_prose_to_stdout(capsys, monkeypatch):
    """stdout is the JSON-RPC channel. A line of prose there corrupts the stream for
    every client, and the platform warning is prose."""
    import platform as platform_module

    import valvur.mcp.server as server

    monkeypatch.setattr(platform_module, "system", lambda: "Windows")
    monkeypatch.setattr(server.protocol, "serve", lambda handlers: None)

    server.main([])
    captured = capsys.readouterr()

    assert captured.out == "", f"the MCP server wrote to stdout: {captured.out[:120]!r}"
    assert "Windows" in captured.err
