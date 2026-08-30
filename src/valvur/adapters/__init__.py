"""Scanner adapters. One per tool; the orchestrator knows only this list."""

from __future__ import annotations

from .base import ScannerAdapter, container_relative
from .gitleaks import GitleaksAdapter
from .trivy import TrivyAdapter

DEFAULT_ADAPTERS: tuple[ScannerAdapter, ...] = (GitleaksAdapter(), TrivyAdapter())

__all__ = [
    "DEFAULT_ADAPTERS",
    "GitleaksAdapter",
    "ScannerAdapter",
    "TrivyAdapter",
    "container_relative",
]
