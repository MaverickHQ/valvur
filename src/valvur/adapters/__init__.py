"""Scanner adapters. One per tool; the orchestrator knows only this list."""

from __future__ import annotations

from .base import ScannerAdapter, container_relative
from .gitleaks import GitleaksAdapter

DEFAULT_ADAPTERS: tuple[ScannerAdapter, ...] = (GitleaksAdapter(),)

__all__ = ["DEFAULT_ADAPTERS", "GitleaksAdapter", "ScannerAdapter", "container_relative"]
