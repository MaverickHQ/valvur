"""Scanner adapters. One per tool; the orchestrator knows only this list."""

from __future__ import annotations

from .base import ScannerAdapter, container_relative
from .check import CheckAdapter
from .checkov import CheckovAdapter
from .gitleaks import GitleaksAdapter
from .opengrep import OpengrepAdapter
from .osv import OsvAdapter
from .syft import SyftAdapter
from .trivy import TrivyAdapter

DEFAULT_ADAPTERS: tuple[ScannerAdapter, ...] = (
    GitleaksAdapter(),
    TrivyAdapter(),
    OsvAdapter(),
    OpengrepAdapter(),
    CheckovAdapter(),
    SyftAdapter(),
    CheckAdapter("licence-file"),
    CheckAdapter("ai-artifact"),
    # The only Check that needs the network, and only on standard/deep.
    CheckAdapter("dependency-reality", needs_network=True),
)

__all__ = [
    "DEFAULT_ADAPTERS",
    "CheckAdapter",
    "CheckovAdapter",
    "GitleaksAdapter",
    "OpengrepAdapter",
    "OsvAdapter",
    "ScannerAdapter",
    "SyftAdapter",
    "TrivyAdapter",
    "container_relative",
]
