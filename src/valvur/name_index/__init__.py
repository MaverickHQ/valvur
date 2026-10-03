"""The package-name index — existence answered offline (ADR-0018).

Three modules, one job each (28.4.2): `reader` is what a scan needs — the
memory-mapped file, the on-disk contract, the environment names — and imports
nothing that fetches; `published` pulls the signed OCI artifact every
`valvur update` uses; `build` walks the registries, which only the publishing
workflow and the fallback do. `malicious` is the known-malicious list
published beside the index (D26), read, built and pulled the same ways. This
package re-exports the names callers use, each loaded when first asked for
(`valvur.lazy`); a test that patches a name patches the module that defines it.
"""

from __future__ import annotations

from .. import lazy

__getattr__, __dir__ = lazy.exports(__name__, {
    "CRATES_DUMP": "build",
    "FULL_REPULL_AFTER_DAYS": "build",
    "NPM_REPLICATE": "build",
    "PACKAGIST_LIST": "build",
    "PAGE": "build",
    "PYPI_SIMPLE": "build",
    "RUBYGEMS_NAMES": "build",
    "TIMEOUT": "build",
    "WALK_MIN_INTERVAL_HOURS": "build",
    "fetch_crates": "build",
    "fetch_mirror": "build",
    "fetch_npm_changes": "build",
    "fetch_npm_full": "build",
    "fetch_packagist": "build",
    "fetch_pypi": "build",
    "fetch_rubygems": "build",
    "refresh": "build",
    "walk": "build",
    "ARTIFACT_TYPE": "published",
    "CONFIG_TYPE": "published",
    "LAYER_TYPE": "published",
    "fetch_published": "published",
    "published_size_mb": "published",
    "repository": "published",
    "DEFAULT_INDEX_REPOSITORY": "reader",
    "FILES": "reader",
    "INDEX_INSECURE_ENV": "reader",
    "INDEX_REPOSITORY_ENV": "reader",
    "METADATA": "reader",
    "MINIMUM_NAMES": "reader",
    "MIRROR_ENV": "reader",
    "IndexUnavailable": "reader",
    "NameIndex": "reader",
    "Progress": "reader",
    "open_index": "reader",
    **{module: module for module in ("build", "malicious", "published", "reader")},
})
