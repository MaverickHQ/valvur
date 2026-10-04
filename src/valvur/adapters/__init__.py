"""Scanner adapters. One per tool; the orchestrator knows only `DEFAULT_ADAPTERS`,
in `registry`. The names below load when first asked for (`valvur.lazy`), so a
module of this package loads only what it imports.
"""

from __future__ import annotations

from .. import lazy

__getattr__, __dir__ = lazy.exports(__name__, {
    "DEFAULT_ADAPTERS": "registry",
    "CheckAdapter": "check",
    "CheckovAdapter": "checkov",
    "GitleaksAdapter": "gitleaks",
    "OpengrepAdapter": "opengrep",
    "OsvAdapter": "osv",
    "ScannerAdapter": "base",
    "SyftAdapter": "syft",
    "TrivyAdapter": "trivy",
    "ZizmorAdapter": "zizmor",
    "container_relative": "base",
    **{module: module for module in ("base", "check", "checkov", "gitleaks", "opengrep",
                                      "osv", "registry", "syft", "trivy", "zizmor")},
})
