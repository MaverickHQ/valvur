"""valvur's own Checks, by name: what the Check adapter and `python -m valvur.checks`
look a Check up in."""

from __future__ import annotations

from .ai_artifact import AiArtifactCheck
from .base import Check
from .dependency_reality import DependencyRealityCheck
from .licence_file import LicenceFileCheck

REGISTRY: dict[str, Check] = {
    c.name: c for c in (LicenceFileCheck(), AiArtifactCheck(), DependencyRealityCheck())
}
