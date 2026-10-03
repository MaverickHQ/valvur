"""The package loads only what is asked (D50).

`valvur/__init__.py` imported `api` to re-export `scan`, and Python runs a package's
`__init__` before any of its modules, so every import of any part of valvur loaded the
orchestrator first: `import valvur.hook`, on every install the plugin's hook checks,
loaded 52 of valvur's modules (R23.1). The public names are exported lazily now
(PEP 562), and stay importable.
"""

from __future__ import annotations

import json
import subprocess
import sys


def _loaded_by(statement: str) -> list[str]:
    """valvur's modules a fresh interpreter holds after `statement`."""
    probe = (f"import sys, json\n{statement}\n"
             "print(json.dumps(sorted(m for m in sys.modules "
             "if m == 'valvur' or m.startswith('valvur.'))))")
    done = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                          check=True)
    return json.loads(done.stdout)


def test_the_public_names_still_import():
    from valvur import Finding, ScannerFailed, ScanRun, __version__, scan
    from valvur.api import ScannerFailed as api_failed
    from valvur.api import ScanRun as api_run
    from valvur.api import scan as api_scan
    from valvur.findings import Finding as model

    assert (scan, ScanRun, ScannerFailed, Finding) == (api_scan, api_run, api_failed, model)
    assert isinstance(__version__, str) and __version__


def test_an_unknown_name_is_still_an_attribute_error():
    import pytest

    import valvur

    with pytest.raises(AttributeError):
        valvur.no_such_name  # noqa: B018


def test_the_hook_loads_neither_the_orchestrator_nor_the_pipeline():
    loaded = _loaded_by("import valvur.hook")

    assert "valvur.api" not in loaded and "valvur.pipeline" not in loaded
    # 52 before (R23.1): the parser, the index reader and what they stand on.
    assert len(loaded) <= 11, loaded


def test_importing_the_package_loads_nothing_else():
    assert _loaded_by("import valvur") == ["valvur"]
