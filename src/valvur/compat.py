"""Shim and image must be a compatible pair (F1.9).

ADR-0001 accepted two artifacts instead of one on the explicit condition that this
check existed. Without it, a stale image silently produces results a newer shim
cannot parse — and the failure would surface as a confusing parse error rather than
as the version mismatch it is.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from . import egress
from .version import __version__

LABEL = "org.opencontainers.image.version"

#: The shim/image protocol this shim speaks (26.3.1): what it assumes of the image
#: — binaries, paths, the Checks' entry point and its JSON, the labels, the user —
#: written down in docs/PROTOCOL.md and carried by the image as one label. A change
#: that breaks anything on that page bumps this; an addition does not. The
#: Dockerfile declares the same number, and a test holds the two together.
PROTOCOL = 1
PROTOCOL_LABEL = "org.valvur.protocol"


class IncompatibleImage(RuntimeError):
    """Raised with both versions named, because 'incompatible' alone is unactionable."""


def shim_version() -> str:
    """The one version, derived in `version.py` so nothing here can disagree."""
    return __version__


def _label(runtime: str, image: str, name: str) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603
            [runtime, "inspect", "--format", f"{{{{index .Config.Labels \"{name}\"}}}}", image],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    label = result.stdout.strip()
    return label or None


def image_version(runtime: str, image: str) -> str | None:
    """Read the image's declared version. None if it does not declare one."""
    return _label(runtime, image, LABEL)


def image_protocol(runtime: str, image: str) -> int | None:
    """The protocol major the image declares. None for an image from before the
    label — `0.3.0` and earlier — which the version rule serves instead."""
    raw = _label(runtime, image, PROTOCOL_LABEL)
    return int(raw) if raw is not None and raw.isdigit() else None


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


# ---------------------------------------------------- the tree, not the version
#
# `0.1.0rc1` fell through a hole the version label cannot see: the same version on
# a shim and an image built from different code (task 23.4.4). The image records a
# digest over its inputs at build time (22.C.1); the wheel carries the same digest,
# computed by the same module over the same tree, in a generated `_build.py`. A
# scan compares the two and WARNS on a mismatch — never refuses: a mismatch is a
# diagnosis, and hiding results behind it would help nobody.

#: Where an image records the digest of the tree it was built from.
IMAGE_INPUTS_FILE = "/etc/valvur/inputs.sha256"


def shim_inputs() -> str | None:
    """The digest of the tree this shim was built beside: from the wheel's
    generated `_build.py`; for a source tree, computed live as the e2e guard does;
    None for a wheel built before the hook existed."""
    try:
        from . import _build  # type: ignore[attr-defined]

        return str(_build.INPUTS_SHA256)
    except ImportError:
        pass
    repo = _source_tree()
    if repo is None:
        return None
    from . import tree_hash

    return tree_hash.digest(tree_hash.tree_parts(repo))


def _source_tree() -> Path | None:
    """The repository this package is imported from, if it is a checkout rather
    than an installed wheel: the Dockerfile sits two levels above `src/valvur`."""
    repo = Path(__file__).resolve().parents[2]
    return repo if (repo / "Dockerfile").is_file() and (repo / "src" / "valvur").is_dir() else None


def image_inputs(runtime: str, image: str) -> str | None:
    """The digest recorded in the image, read once per image id and then from the
    host cache: `image inspect` costs milliseconds and the id changes exactly when
    the image does, while starting a container to `cat` the file costs 2-5s on
    Docker Desktop. None when the image predates the file, or nothing answers."""
    from . import cache

    try:
        inspected = subprocess.run(  # noqa: S603
            [runtime, "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    image_id = inspected.stdout.strip()
    if inspected.returncode != 0 or not image_id:
        return None
    store = cache.root() / "image-inputs"
    memo = store / image_id
    if memo.is_file():
        remembered = memo.read_text(encoding="utf-8").strip()
        return remembered or None
    try:
        probe = subprocess.run(  # noqa: S603
            [runtime, "run", "--rm", *egress.NONE.container_flags(), "--entrypoint", "cat",
             image, IMAGE_INPUTS_FILE],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    digest = probe.stdout.strip() if probe.returncode == 0 else ""
    if probe.returncode not in (0, 1):
        return None                     # the container did not start; ask again next time
    try:
        store.mkdir(parents=True, exist_ok=True)
        memo.write_text(digest + "\n", encoding="utf-8")   # empty = "has no file"
    except OSError:
        pass
    return digest or None


def verdict(ours: str, declared: str | None, theirs: int | None) -> str | None:
    """Why a shim of version `ours` cannot use an image declaring version
    `declared` and protocol `theirs`, or None when it can — the one rule `check`
    raises on and `doctor` reports (F1.9, 26.3.1).

    A labelled image is judged by its protocol major alone: the same major runs
    whatever the versions say — a different tree is a diagnosis the scan makes
    (23.4.4), never a refusal — and a different major is the one thing refused.
    An image without the label predates protocol 1, and the version-series rule
    that served it keeps serving it.
    """
    if theirs is not None:
        if theirs == PROTOCOL:
            return None
        return (f"the image speaks protocol {theirs}; this shim ({ours}) speaks protocol "
                f"{PROTOCOL} (the image says it is version {declared or 'unknown'})")
    if declared is None:
        return None                   # neither label: an image from before the check
    if _series(ours) != _series(declared):
        return f"Shim version {ours} cannot use image version {declared}"
    return None


def incompatibility(runtime: str, image: str) -> str | None:
    """`verdict`, with both labels read from the image."""
    return verdict(shim_version(), image_version(runtime, image), image_protocol(runtime, image))


def check(runtime: str, image: str) -> None:
    """Refuse an incompatible pair, naming both sides and the fix (F1.9)."""
    reason = incompatibility(runtime, image)
    if reason is None:
        return
    ours = shim_version()
    raise IncompatibleImage(
        f"{reason}.\n"
        f"  Update both: pip install -U valvur && {runtime} pull {image}\n"
        f"  Or pin the image: VALVUR_IMAGE=valvur:{ours} valvur scan"
    )
