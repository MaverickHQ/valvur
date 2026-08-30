"""valvur's own Checks. Registered here; invoked in-container via __main__."""

from __future__ import annotations

from .base import Check
from .licence_file import LicenceFileCheck

REGISTRY: dict[str, Check] = {c.name: c for c in (LicenceFileCheck(),)}

__all__ = ["REGISTRY", "Check", "LicenceFileCheck"]
