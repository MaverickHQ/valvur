"""valvur's own Checks. Registered here; invoked in-container via __main__."""

from __future__ import annotations

from .ai_artifact import AiArtifactCheck
from .base import Check
from .dependency_reality import DependencyRealityCheck
from .licence_file import LicenceFileCheck

REGISTRY: dict[str, Check] = {
    c.name: c for c in (LicenceFileCheck(), AiArtifactCheck(), DependencyRealityCheck())
}

__all__ = [
    "REGISTRY", "AiArtifactCheck", "Check", "DependencyRealityCheck", "LicenceFileCheck",
]
