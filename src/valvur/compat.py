"""Shim and image must be a compatible pair (F1.9).

ADR-0001 accepted two artifacts instead of one on the explicit condition that this
check existed. Without it, a stale image silently produces results a newer shim
cannot parse — and the failure would surface as a confusing parse error rather than
as the version mismatch it is.
"""

from __future__ import annotations

import subprocess

from .version import __version__

LABEL = "org.opencontainers.image.version"


class IncompatibleImage(RuntimeError):
    """Raised with both versions named, because 'incompatible' alone is unactionable."""


def shim_version() -> str:
    """The one version, derived in `version.py` so nothing here can disagree."""
    return __version__


def image_version(runtime: str, image: str) -> str | None:
    """Read the image's declared version. None if it does not declare one."""
    try:
        result = subprocess.run(  # noqa: S603
            [runtime, "inspect", "--format", f"{{{{index .Config.Labels \"{LABEL}\"}}}}", image],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    label = result.stdout.strip()
    return label or None


def _series(raw: str) -> tuple[int, int]:
    """The part of a version that may break compatibility.

    Semver says only major matters — but during 0.x a minor bump is allowed to break
    things, and we are in 0.x, so both count until 1.0.
    """
    numbers = []
    for part in raw.split(".")[:2]:
        digits = "".join(c for c in part if c.isdigit())
        numbers.append(int(digits) if digits else 0)
    while len(numbers) < 2:
        numbers.append(0)
    major, minor = numbers[0], numbers[1]
    return (major, minor if major == 0 else 0)


def check(runtime: str, image: str) -> None:
    """Refuse an incompatible pair, naming both versions (F1.9)."""
    declared = image_version(runtime, image)
    if declared is None:
        return                        # an image without the label predates the check
    ours = shim_version()
    if _series(ours) != _series(declared):
        raise IncompatibleImage(
            f"Shim version {ours} cannot use image version {declared}.\n"
            f"  Update both: pip install -U valvur && {runtime} pull {image}\n"
            f"  Or pin the image: VALVUR_IMAGE=valvur:{ours} valvur scan"
        )
