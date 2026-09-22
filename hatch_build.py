"""Build hook: the wheel carries the tree hash it was built beside (task 23.4.4).

`release.yml` builds the image and the wheel from one checkout. The image records
a digest over its inputs — Dockerfile, rules, `src/valvur`, the Checkov lock — in
`/etc/valvur/inputs.sha256` (22.C.1). This hook computes the same digest, with the
same module, over the same inputs, and writes it into the wheel as
`valvur/_build.py`, so an installed shim can tell whether the image it is talking
to came from the same tree — the hole `0.1.0rc1` fell through, where the version
strings agreed and the code did not.

The file is generated here, added to the wheel, and removed again: never committed
(`.gitignore`), never copied into the image (`.dockerignore`), never an input to the
digest it holds (`tree_hash` skips it). An sdist carries the inputs, so a wheel
built from one computes the same value — and therefore needs no `_build.py` of its
own. Until task 27.2.3 the hook ran for the sdist too and `force_include` put the
file at `valvur/_build.py` in the archive, which for an sdist is not the package
path (`src/valvur/`) but a one-file directory at the root that nothing reads.
"""

from __future__ import annotations

import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

GENERATED = Path("src/valvur/_build.py")


class TreeHashHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        # The wheel's, and only the wheel's: see the module docstring. A test
        # asserts the sdist carries no `_build.py` and does carry `tree_hash.py`,
        # which is what a wheel built from it recomputes the digest with.
        if self.target_name != "wheel":
            return
        root = Path(self.root)
        sys.path.insert(0, str(root / "src"))
        try:
            from valvur import tree_hash
        finally:
            sys.path.pop(0)
        digest = tree_hash.digest(tree_hash.tree_parts(root))
        target = root / GENERATED
        target.write_text(
            '"""Generated at build time by hatch_build.py (task 23.4.4). Never committed."""\n'
            f'INPUTS_SHA256 = "{digest}"\n',
            encoding="utf-8",
        )
        build_data.setdefault("force_include", {})[str(target)] = "valvur/_build.py"

    def finalize(self, version: str, build_data: dict, artifact_path: str) -> None:
        target = Path(self.root) / GENERATED
        if target.exists():
            target.unlink()
