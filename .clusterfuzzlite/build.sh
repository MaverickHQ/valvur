#!/bin/bash -eu
# Builds every fuzzer under fuzz (R27.4, D63c), each with its seeds.
#
# No install: the shim is standard-library alone, so PyInstaller, and the
# subprocesses it collects data in, find the package on PYTHONPATH. Scorecard counts
# any pip install not pinned by hash, a local `--no-deps .` among them (measured).
export PYTHONPATH="$SRC/valvur/src"

for fuzzer in fuzz/fuzz_*.py; do
  name=$(basename "$fuzzer" .py)
  # Every module, since many imports are deferred, and the package's data files
  # (the bundled KEV, the configuration schema), which PyInstaller does not follow.
  compile_python_fuzzer "$fuzzer" --collect-submodules valvur --collect-data valvur
  python3 fuzz/seeds.py "$fuzzer" "$OUT/${name}_seed_corpus.zip"
done
