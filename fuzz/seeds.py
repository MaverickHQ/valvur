"""Write a fuzzer's `SEEDS` as the seed corpus ClusterFuzzLite reads (R27.4).

    python3 fuzz/seeds.py fuzz/fuzz_installs.py out/fuzz_installs_seed_corpus.zip
"""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path


def main(fuzzer: str, target: str) -> int:
    spec = importlib.util.spec_from_file_location(Path(fuzzer).stem, fuzzer)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    with zipfile.ZipFile(target, "w") as corpus:
        for n, seed in enumerate(module.SEEDS):
            corpus.writestr(f"seed-{n}", seed)
    print(f"{target}: {len(module.SEEDS)} seeds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
