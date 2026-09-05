"""One version, derived once.

The literal used to live in five places: `pyproject.toml`, `runner.py` twice
(`IMAGE` and `_VERSION`), `results.py` and `README.md`. F1.9 refuses to run a
mismatched shim and image by comparing two of them, so a partial bump shipped a pair
that either refused to start or — worse — agreed while being wrong.

`pyproject.toml` is now the only place a human edits. Everything else derives from
the installed package metadata, and the README is checked against it by a test rather
than by memory.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

#: Reported when valvur is imported from a source tree that was never installed. A
#: made-up release number would be worse: F1.9 would compare it against a real image
#: and reach a confident, wrong answer. This one matches nothing and fails loudly.
DEV_VERSION = "0.0.0-dev"

IMAGE_REPOSITORY = "ghcr.io/maverickhq/valvur"


def _derive() -> str:
    try:
        return _installed_version("valvur")
    except PackageNotFoundError:
        return DEV_VERSION


__version__ = _derive()


def default_image() -> str:
    """The image this shim expects.

    Derived rather than pinned: a shim that asks for whatever tag it was built
    alongside cannot drift from it. Overridden by `VALVUR_IMAGE` for local builds and
    for air-gapped mirrors.
    """
    return f"{IMAGE_REPOSITORY}:{__version__}"
