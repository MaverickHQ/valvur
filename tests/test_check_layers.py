"""The host side in layers (D50): `scripts/check_layers.py`.

Four layers, `core`, `infra`, `app` and `surfaces`, each importing only from the
layers below it. `scripts/layers.toml` assigns every module under `src/valvur` to
one, and the check reads the AST, as `check_traceability.py` does, so an import
inside a function counts as much as one at the top of a file.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture
def layers():
    spec = importlib.util.spec_from_file_location("check_layers", SCRIPTS / "check_layers.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["check_layers"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _package(root: Path, files: dict[str, str]) -> Path:
    for name, text in {"__init__.py": "", **files}.items():
        (root / "pkg" / name).parent.mkdir(parents=True, exist_ok=True)
        (root / "pkg" / name).write_text(text)
    return root / "pkg"


def _config(root: Path, text: str) -> Path:
    path = root / "layers.toml"
    path.write_text('order = ["core", "infra", "app", "surfaces"]\n' + text)
    return path


def test_an_upward_import_is_named_with_its_file_and_line(tmp_path, layers):
    package = _package(tmp_path, {
        "model.py": "import os\n\nfrom . import service\n",
        "service.py": "from .model import X\n",
    })
    config = _config(tmp_path, '[layers]\ncore = ["pkg", "pkg.model"]\napp = ["pkg.service"]\n')

    found = layers.check(package, config)

    assert [v.where for v in found.upward] == ["pkg/model.py:3"]
    assert "pkg.model (core) imports pkg.service (app)" in found.upward[0].message


def test_a_deferred_import_counts(tmp_path, layers):
    package = _package(tmp_path, {
        "model.py": "def later():\n    from .service import run\n    return run\n",
        "service.py": "",
    })
    config = _config(tmp_path, '[layers]\ncore = ["pkg", "pkg.model"]\napp = ["pkg.service"]\n')

    found = layers.check(package, config)

    assert [(v.where, v.deferred) for v in found.upward] == [("pkg/model.py:2", True)]


def test_an_import_from_below_or_beside_passes(tmp_path, layers):
    package = _package(tmp_path, {
        "model.py": "",
        "other.py": "from . import model\n",
        "service.py": "from .model import X\nimport pkg.other\n",
    })
    config = _config(tmp_path,
                     '[layers]\ncore = ["pkg", "pkg.model", "pkg.other"]\napp = ["pkg.service"]\n')

    assert layers.check(package, config).upward == []
