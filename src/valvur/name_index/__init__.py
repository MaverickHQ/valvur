"""The package-name index — existence answered offline (ADR-0018).

Three modules, one job each (28.4.2): `reader` is what a scan needs — the
memory-mapped file, the on-disk contract, the environment names — and imports
nothing that fetches; `published` pulls the signed OCI artifact every
`valvur update` uses; `build` walks the registries, which only the publishing
workflow and the fallback do. This package re-exports the names callers use; a
test that patches a name patches the module that defines it.
"""

from __future__ import annotations

from . import build, published, reader
from .build import (  # noqa: F401
    CRATES_DUMP,
    FULL_REPULL_AFTER_DAYS,
    NPM_REPLICATE,
    PACKAGIST_LIST,
    PAGE,
    PYPI_SIMPLE,
    RUBYGEMS_NAMES,
    TIMEOUT,
    WALK_MIN_INTERVAL_HOURS,
    fetch_crates,
    fetch_mirror,
    fetch_npm_changes,
    fetch_npm_full,
    fetch_packagist,
    fetch_pypi,
    fetch_rubygems,
    refresh,
    walk,
)
from .published import (  # noqa: F401
    ARTIFACT_TYPE,
    CONFIG_TYPE,
    LAYER_TYPE,
    fetch_published,
    published_size_mb,
    repository,
)
from .reader import (  # noqa: F401
    DEFAULT_INDEX_REPOSITORY,
    FILES,
    INDEX_INSECURE_ENV,
    INDEX_REPOSITORY_ENV,
    METADATA,
    MINIMUM_NAMES,
    MIRROR_ENV,
    IndexUnavailable,
    NameIndex,
    Progress,
    open_index,
)

__all__ = ["build", "published", "reader"]
