"""The image's inputs, hashed the same way on both sides of the build (22.C.1).

Checks and rules ship INSIDE the image (ADR-0013). So a change to either passes the
unit suite while a real scan runs yesterday's code, and the failure looks like the
change not working. That trap bit five times in four days; CONTRIBUTING documented
it, and documentation is not a guard.

This is the guard. The Dockerfile runs it at build time over what it copied in and
stores the digest in the image; `scripts/check_image.py` and the e2e suite run it
over the working tree and compare. One module, invoked on both sides, so the two
digests are computed by the same code and can only disagree because the inputs do.

The digest covers exactly what the Dockerfile copies from the tree — `rules/`,
`src/valvur/` (this file included) and the Dockerfile itself — keyed by a label
rather than a path, because the same file lives at `src/valvur/x.py` here and
`/usr/local/lib/python3.12/site-packages/valvur/x.py` there.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

#: Where the Dockerfile stores the build-time digest, and copies the inputs it
#: needs to recompute it. Read by the host through `docker run … cat`.
IMAGE_DIGEST_FILE = "/etc/valvur/inputs.sha256"
IMAGE_DOCKERFILE = "/etc/valvur/Dockerfile"
IMAGE_RULES = "/opt/valvur-rules"
IMAGE_CHECKOV_LOCK = "/opt/checkov-requirements.txt"
IMAGE_NOTICE = "/usr/share/doc/valvur/NOTICE"

#: Never part of the digest: byte-compiled caches differ per interpreter and are
#: stripped from the image anyway; editor droppings are not inputs; and the file
#: the wheel build generates to CARRY this digest (23.4.4) cannot also move it.
_SKIP_DIRS = {"__pycache__"}
_SKIP_SUFFIXES = (".pyc", ".pyo")
_SKIP_NAMES = {".DS_Store", "_build.py"}


def digest(parts: dict[str, Path]) -> str:
    """SHA-256 over every file under each part, in a fixed order.

    Each file contributes its label-relative path and its bytes, each NUL-terminated,
    so a rename, a move between parts and a content change are all distinct. A
    single-file part contributes just its bytes under its label.
    """
    h = hashlib.sha256()
    for label in sorted(parts):
        root = parts[label]
        for relative, path in _files(root):
            name = f"{label}/{relative}" if relative else label
            h.update(name.encode("utf-8") + b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def _files(root: Path):
    if root.is_file():
        yield "", root
        return
    if not root.is_dir():
        raise FileNotFoundError(f"image input missing: {root}")
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if _SKIP_DIRS & set(relative.parts[:-1]):
            continue
        if path.name in _SKIP_NAMES or path.suffix in _SKIP_SUFFIXES:
            continue
        yield relative.as_posix(), path


def tree_parts(repo: Path) -> dict[str, Path]:
    """The inputs as they sit in a working tree."""
    return {
        "Dockerfile": repo / "Dockerfile",
        "rules": repo / "rules",
        "valvur": repo / "src" / "valvur",
        # The Checkov lock (23.4.1): a changed hash is a changed image.
        "checkov-lock": repo / "requirements-checkov.txt",
        # The attribution file (28.3.5), copied into the image like the rest.
        "notice": repo / "NOTICE",
    }


def image_parts() -> dict[str, Path]:
    """The same inputs as the Dockerfile lays them out inside the image."""
    return {
        "Dockerfile": Path(IMAGE_DOCKERFILE),
        "rules": Path(IMAGE_RULES),
        "valvur": Path(__file__).resolve().parent,
        "checkov-lock": Path(IMAGE_CHECKOV_LOCK),
        "notice": Path(IMAGE_NOTICE),
    }


def main(argv: list[str] | None = None) -> int:
    """`python -m valvur.tree_hash --image` inside the build; `--tree <repo>` outside."""
    args = argv if argv is not None else sys.argv[1:]
    if args == ["--image"]:
        print(digest(image_parts()))
        return 0
    if len(args) == 2 and args[0] == "--tree":
        print(digest(tree_parts(Path(args[1]))))
        return 0
    print("usage: python -m valvur.tree_hash --image | --tree <repo>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
