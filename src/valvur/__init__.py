"""valvur: a local, offline security scanner for AI-generated code.

The public names are loaded when first asked for (PEP 562), not here: Python runs a
package's `__init__` before any of its modules, so an eager import of `api` made every
part of valvur, the plugin's hook included, load the orchestrator first (D50).
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .api import ScannerFailed, ScanRun, scan
    from .findings import Finding

__all__ = ["Finding", "ScanRun", "ScannerFailed", "__version__", "scan"]

#: Each public name, and the module that defines it.
_EXPORTS = {"scan": "api", "ScanRun": "api", "ScannerFailed": "api",
            "Finding": "findings", "__version__": "version"}


def __getattr__(name: str) -> Any:
    if name not in _EXPORTS:
        raise AttributeError(f"module 'valvur' has no attribute {name!r}")
    value = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
