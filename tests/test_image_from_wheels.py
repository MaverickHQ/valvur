"""R44.10 (D81ab): the image's Python packages come from wheels alone, and the build
installs nothing from Alpine's repository that is not named at an exact version.

The self-healing spec's Requirement 22.2. Until this, the step that installs Checkov added
`gcc`, `musl-dev` and `libffi-dev` with no version and removed them in the same layer. A
package compiled there would carry the compiler of the day, and two builds of one tree
would differ on a day Alpine moved it. Measured on 2026-11-22 in the pinned base, at
`9af6abb`: all 97 lines of `requirements-checkov.txt` and the one of
`requirements-zizmor.txt` resolve to wheels whose hashes the locks hold, for musl on arm64
and on x86_64. So no compiler is needed, and `--only-binary=:all:` makes a later package
without a wheel fail the build instead of compiling in silence.
"""

from __future__ import annotations

import re

from test_apk_index_not_in_image import _run_steps

_ADDED = re.compile(r"\bapk add\b((?:\s+(?!&&)[^\s;]+)*)")


def test_each_hash_locked_install_takes_wheels_alone():
    installs = [step for step in _run_steps() if "--require-hashes" in step]

    assert len(installs) == 2, installs
    for step in installs:
        assert re.search(r"--only-binary[= ]:all:", step), step


def test_the_build_adds_no_alpine_package_but_the_pinned_raises():
    """`ALPINE_RAISE` holds each raise as `name=version` (`tests/test_alpine_raise.py`)."""
    named = [word
             for step in _run_steps()
             for added in _ADDED.findall(step)
             for word in added.split() if not word.startswith("-")]

    assert named == ["${ALPINE_RAISE}"], named
