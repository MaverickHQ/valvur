#!/bin/bash -eu
# Builds every fuzzer under fuzz (R27.4, D63c), each with its seeds.
#
# `--no-deps .`: the shim is standard-library alone, so there is nothing to resolve,
# and a local install with no dependencies is one Scorecard reads as pinned.
pip3 install --no-deps .

for fuzzer in fuzz/fuzz_*.py; do
  name=$(basename "$fuzzer" .py)
  # Every module, since many imports are deferred, and the package's data files
  # (the bundled KEV, the configuration schema), which PyInstaller does not follow.
  compile_python_fuzzer "$fuzzer" --collect-submodules valvur --collect-data valvur
  python3 fuzz/seeds.py "$fuzzer" "$OUT/${name}_seed_corpus.zip"
done
