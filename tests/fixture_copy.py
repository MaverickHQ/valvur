"""The tests' handle on `scripts/fixtures.py`, the one helper that copies a fixture
with its manifests' real names (R27.2, D63a)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "valvur_fixtures", Path(__file__).resolve().parent.parent / "scripts" / "fixtures.py")
_module = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_module)  # type: ignore[union-attr]

copy_fixture = _module.copy
restore = _module.restore
