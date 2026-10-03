"""What one scan reads of the project once, and passes to everything that asks
(D52d): the project file, parsed, its `[scan]` table, and the File Set.

R23.1 counted 76 parses of `.security-scan.toml` and 37 File Sets in one CLI scan
of a small repository: each adapter's applicability and each coverage contract
asked again for what the scan already knew. The context is built once, by the scan,
and handed to the adapters, the pipeline and coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import fileset
from .exclusions import ScanSettings, read_project, scan_settings
from .fileset import FileSet


@dataclass(frozen=True)
class ScanContext:
    workspace: Path
    #: The project file's tables, empty when there is none or it is unreadable.
    project: dict
    #: Why the project file could not be read; None when it could, or is absent.
    problem: str | None
    #: Its `[scan]` table, with the defaults.
    settings: ScanSettings
    #: The exact files the Scan Run examines (ADR-0021).
    file_set: FileSet

    @property
    def files(self) -> list[str]:
        return self.file_set.files


def build(workspace: Path) -> ScanContext:
    """Read the project once: the file, then the File Set it decides. Raises the
    File Set's `Refusal` for a tree too large to walk."""
    project, problem = read_project(workspace)
    settings = scan_settings(project)
    # Through the module, so a test that counts File Sets counts this one.
    file_set = fileset.build(workspace, settings)
    return ScanContext(workspace, project, problem, settings, file_set)

