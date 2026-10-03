"""One vocabulary for ecosystem names, shared by every adapter.

Finding identity is `(ecosystem, package, version, vuln_id)` (ADR-0003). Scanners do
not agree on the first element: OSV says "PyPI", Trivy says "pip", and for lockfiles
Trivy reports the FORMAT rather than the ecosystem — "pnpm" and "yarn" for what is
all npm. Measured on a real project: the same 24 CVEs arrived as 24 "npm" findings
from osv-scanner and 24 "pnpm" findings from Trivy, and every one was reported twice
because the fingerprints could not match.
"""

from __future__ import annotations

from .. import lazy

# Each name loads when first asked for (`valvur.lazy`): the vocabulary itself is in
# `vocabulary`, the table of ecosystems in `registry`.
__getattr__, __dir__ = lazy.exports(__name__, {
    **{name: "vocabulary" for name in ("Manifests", "MANIFESTS", "VULNERABILITY_MANIFESTS",
                                       "declared", "defined_locally", "normalise")},
    **{name: "registry" for name in ("BY_KEY", "ECOSYSTEMS", "INDEX_FILES", "Ecosystem",
                                     "get", "index_form")},
    # The function, as the package's surface has it (D26); the module is `locked`'s.
    "locked": "locked:locked",
    **{module: module for module in ("parsers", "registries", "registry", "vocabulary")},
})
