#!/usr/bin/env python3
"""Refuse a local image that was not built from this tree (22.C.1).

    python3 scripts/check_image.py [image]      # default: $VALVUR_IMAGE or valvur:dev

Checks and rules ship inside the image (ADR-0013). Edit one, forget to rebuild, and
every real scan runs the old code while the unit suite passes — the failure looks
like the edit not working, and it cost four rebuild-and-retry cycles in three days
before this existed. The image carries a digest of what it was built from; this
compares it with the working tree and prints the rebuild command when they differ.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from valvur import tree_hash  # noqa: E402
from valvur.runner import detect_runtime  # noqa: E402


def rebuild_command(image: str) -> str:
    """The bake file is the one place the build lives (23.4.3); `IMAGE:TAG` is
    what `dev` produces, so a non-default image name is split into the two."""
    name, _, tag = image.rpartition(":")
    target = f"BAKE_IMAGE={name} BAKE_TAG={tag} " if name and image != "valvur:dev" else ""
    return (
        f"{target}VALVUR_VERSION=\"$(uv run python -c 'import valvur; "
        "print(valvur.__version__)')\" docker buildx bake"
    )


def image_digest(runtime: str, image: str) -> str | None:
    """The digest the image was built with, or None when it carries none."""
    result = subprocess.run(  # noqa: S603 — argv list, runtime resolved by valvur
        [runtime, "run", "--rm", "--entrypoint", "cat", image, tree_hash.IMAGE_DIGEST_FILE],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    image = args[0] if args else (os.environ.get("VALVUR_IMAGE") or "valvur:dev")
    runtime = detect_runtime()

    exists = subprocess.run(  # noqa: S603 — argv list, runtime resolved by valvur
        [runtime, "image", "inspect", image], capture_output=True, text=True, check=False
    )
    if exists.returncode != 0:
        print(f"[FAIL] no local image {image}. Build it:\n  {rebuild_command(image)}")
        return 1

    expected = tree_hash.digest(tree_hash.tree_parts(REPO))
    actual = image_digest(runtime, image)
    if actual is None:
        print(f"[FAIL] {image} carries no build digest — it predates the guard. Rebuild it:\n"
              f"  {rebuild_command(image)}")
        return 1
    if actual != expected:
        print(f"[FAIL] {image} was not built from this tree.\n"
              f"  image {actual[:12]}  tree {expected[:12]}\n"
              "  Something under src/valvur/, rules/ or the Dockerfile changed since it "
              "was built. Rebuild it:\n"
              f"  {rebuild_command(image)}")
        return 1
    print(f"[PASS] {image} was built from this tree ({expected[:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
