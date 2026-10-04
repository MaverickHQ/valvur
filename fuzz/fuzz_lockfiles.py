"""Fuzz the lockfile readers, `valvur.ecosystems.locked.READERS` (R27.4, D63c).

A scanned project's lockfiles are untrusted text. `locked()` tolerates a reader's
`OSError` and `UnicodeError` and nothing else, so any other exception is a crash.
The first byte picks the reader; the rest is the file.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# The module behind the package's `locked` function. Importing it by name would set
# the package's `locked` to the module and break every later `ecosystems.locked()`
# in this process, so the function is resolved first, the package's way.
from valvur import ecosystems

ecosystems.locked  # noqa: B018 — resolves the function, which imports its module
locked = sys.modules["valvur.ecosystems.locked"]

ROOT = Path(tempfile.mkdtemp(prefix="valvur-fuzz-lockfiles-"))
SEEDS = [b"\x00" + b'{"packages": {"node_modules/a": {"version": "1.0.0"}}}',
         b"\x03" + b'"a@^1":\n  version "1.0.0"\n',
         b"\x04" + b"packages:\n  /a@1.0.0:\n    resolution: {}\n",
         b"\x05" + b"requests==2.31.0\nflask[async]===3.0.0 ; python_version > '3'\n",
         b"\x06" + b'[[package]]\nname = "a"\nversion = "1.0.0"\n',
         b"\x08" + b'{"default": {"a": {"version": "==1.0.0"}}}',
         b"\x0a" + b'{"packages": [{"name": "a/b", "version": "v1.0.0"}]}',
         b"\x0b" + b"GEM\n  specs:\n    rails (7.1.0)\n",
         # Each crash found, fixed with a test in tests/test_fuzz_crashes.py.
         b"\x00" + b'{"packages": [1]}', b"\x00" + b'{"dependencies": [1]}',
         b"\x02" + b'{"dependencies": [1]}', b"\x08" + b'{"default": [1]}',
         b"\x06" + b"package = 1"]


def test_one_input(data: bytes) -> None:
    if not data:
        return
    pattern, _ecosystem, read = locked.READERS[data[0] % len(locked.READERS)]
    path = ROOT / pattern.replace("*", "")
    path.write_bytes(data[1:])
    try:
        list(read(path))
    except (OSError, UnicodeError):
        pass


def main() -> None:
    """Run as a fuzzer: atheris only here, so the unit suite runs the seeds without it."""
    import atheris  # deferred: a dev dependency (the `fuzz` extra), never the shim's

    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
