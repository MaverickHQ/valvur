"""Scanner adapters. One per tool; the orchestrator knows only this list.

This IS F2.1: Trivy, Gitleaks, OSV-Scanner, Opengrep, Checkov and Syft, orchestrated
as Scanners — and valvur's own Checks beside them, on the same contract.
"""

from __future__ import annotations

from .base import ScannerAdapter, container_relative
from .check import CheckAdapter
from .checkov import CheckovAdapter
from .gitleaks import GitleaksAdapter
from .opengrep import OpengrepAdapter
from .osv import OsvAdapter
from .syft import SyftAdapter
from .trivy import TrivyAdapter
from .zizmor import ZizmorAdapter

DEFAULT_ADAPTERS: tuple[ScannerAdapter, ...] = (
    GitleaksAdapter(),
    TrivyAdapter(),
    OsvAdapter(),
    OpengrepAdapter(),
    CheckovAdapter(),
    # Workflows and action definitions (R4.2): adopted by measurement (ADR-0023).
    ZizmorAdapter(),
    SyftAdapter(),
    CheckAdapter("licence-file"),
    CheckAdapter("ai-artifact"),
    # Runs on both Profiles: existence comes from the local name index (ADR-0018).
    # With a network — `full` — it also asks the registry for first-publish age.
    CheckAdapter("dependency-reality", uses_network=True),
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
    "ZizmorAdapter",
    "container_relative",
]
