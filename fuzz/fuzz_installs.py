"""Fuzz `valvur.installs.packages` (R27.4, D63c).

The plugin's hook hands it every Bash command an agent is about to run, before it
runs, so it must answer for any text: a list of packages, never an exception.
"""

from __future__ import annotations

import contextlib
import sys
import tempfile
from pathlib import Path

try:
    import atheris  # the `fuzz` extra; the unit suite runs the seeds without it
except ImportError:
    atheris = None

# Instrumented as imported: valvur, and the parsers whose branches shape its input.
# Instrumenting everything loaded took 10 s to start one input, and ClusterFuzzLite's
# 30 s reproduction dropped two real crashes (PR #196).
with (atheris.instrument_imports(include=["valvur", "tomllib", "json", "shlex"]) if atheris
      else contextlib.nullcontext()):
    from valvur import installs

#: Where the command runs: empty, so a requirements file it names is absent.
CWD = Path(tempfile.mkdtemp(prefix="valvur-fuzz-installs-"))
SEEDS = [b"pip install requests==2.31.0", b"npm i -D left-pad@1.3.0 && uv add httpx",
         b"pip install -r requirements.txt", b"cargo add serde --features derive",
         b"poetry add 'django>=4' ; gem install rails -v 7.1.0", b"",
         # A crash ClusterFuzzLite found (PR #196), fixed with a test.
         b"pip install -r requirements.tx\x00t"]


def test_one_input(data: bytes) -> None:
    installs.packages(data.decode("utf-8", errors="replace"), CWD)


def main() -> None:
    """Run as a fuzzer, with atheris; the unit suite calls `test_one_input` alone."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
