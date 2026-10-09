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

A second hook writes the README PyPI shows (R40, D79). PyPI renders the README as the
project's description and resolves nothing relative, so `PyPIReadme` hands it a copy
whose links point at the repository at the release's tag: every relative link to
`blob/v<version>/` (`tree/` for a folder), every image to `raw.githubusercontent.com`,
and the `<picture>` to its light `<img>`, since PyPI's page is light and its renderer
keeps no `<picture>`. A version that is not a release links `main`. The README in the
tree keeps its relative links, which GitHub needs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.metadata.plugin.interface import MetadataHookInterface

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


#: Where PyPI's copy of the README points: the repository, and its raw files for images.
REPOSITORY = "https://github.com/MaverickHQ/valvur"
RAW = "https://raw.githubusercontent.com/MaverickHQ/valvur"
IMAGES = (".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp")
_FENCE = re.compile(r"^```.*?^```", re.M | re.S)
_PICTURE = re.compile(r"<picture>\s*(?:<source[^>]*>\s*)*(<img[^>]*>)\s*</picture>")
_TARGET = re.compile(r"(\]\()([^)\s]+)(\))|(\b(?:src|srcset)=\")([^\"]+)(\")")


def _absolute(target: str, ref: str) -> str:
    if re.match(r"[a-z][a-z0-9+.-]*:|#", target):
        return target
    path, _, anchor = target.partition("#")
    if path.lower().endswith(IMAGES):
        return f"{RAW}/{ref}/{path}"
    kind = "tree" if path.endswith("/") else "blob"
    return f"{REPOSITORY}/{kind}/{ref}/{path.rstrip('/')}" + (f"#{anchor}" if anchor else "")


def pypi_readme(text: str, version: str) -> str:
    """`text`, the README, with every relative link absolute at the release's tag."""
    ref = f"v{version}" if re.fullmatch(r"\d+\.\d+\.\d+", version) else "main"
    text = _PICTURE.sub(r"\1", text)

    def rewrite(part: str) -> str:
        return _TARGET.sub(lambda m: (m[1] + _absolute(m[2], ref) + m[3]) if m[1]
                           else (m[4] + _absolute(m[5], ref) + m[6]), part)

    # Code blocks are quoted as they are: a `](` inside one is not a link.
    pieces, last = [], 0
    for block in _FENCE.finditer(text):
        pieces += [rewrite(text[last:block.start()]), block.group(0)]
        last = block.end()
    return "".join([*pieces, rewrite(text[last:])])


class PyPIReadme(MetadataHookInterface):
    PLUGIN_NAME = "custom"

    def update(self, metadata: dict) -> None:
        readme = (Path(self.root) / "README.md").read_text(encoding="utf-8")
        metadata["readme"] = {"content-type": "text/markdown",
                              "text": pypi_readme(readme, str(metadata["version"]))}
