"""A package's public names, loaded when first asked for (PEP 562).

Python runs a package's `__init__` before any of its modules, so an `__init__` that
imports its modules makes every module of the package load all the others, and
closes an import cycle with each (D50, R23.9). A package hands its names here
instead: each is imported from the module that defines it on first use, and a
name that is a module is that module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from importlib import import_module
from typing import Any


def exports(package: str, names: Mapping[str, str]) -> tuple[Callable[[str], Any],
                                                             Callable[[], list[str]]]:
    """`__getattr__` and `__dir__` for `package`: `names` maps each public name to
    the module, relative to the package, that defines it, or to `module:name` when
    the public name is another's."""
    namespace = import_module(package).__dict__

    def getattr_(name: str) -> Any:
        where = names.get(name)
        if where is None:
            raise AttributeError(f"module {package!r} has no attribute {name!r}")
        module, _, attribute = where.partition(":")
        loaded = import_module(f".{module}", package)
        value = getattr(loaded, attribute or name) if attribute or name != module else loaded
        namespace[name] = value
        return value

    def dir_() -> list[str]:
        return sorted({*namespace, *names})

    return getattr_, dir_
