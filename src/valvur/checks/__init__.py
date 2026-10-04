"""valvur's own Checks. Registered in `registry`; invoked in-container via __main__.
The names below load when first asked for (`valvur.lazy`)."""

from __future__ import annotations

from .. import lazy

__getattr__, __dir__ = lazy.exports(__name__, {
    "REGISTRY": "registry",
    "AiArtifactCheck": "ai_artifact",
    "Check": "base",
    "DependencyRealityCheck": "dependency_reality",
    "LicenceFileCheck": "licence_file",
    **{module: module for module in ("ai_artifact", "base", "borrowed",
                                      "dependency_reality", "licence_file", "registry")},
})
