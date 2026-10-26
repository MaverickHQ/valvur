"""TASKLIST-1.6.0 E2: the release notes say what the image does not fix (R43.4, N2.7).

`scripts/release_notes_image.py` renders `## What this image does not fix` from the
verdicts `scripts/image_gate.py --out` writes, one per architecture, in the release run's
`notes` job. 1.5.4's list was written by hand, and it missed the base image's pip.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "release_notes_image.py"

HEADING = "## What this image does not fix"
ECDSA = {"id": "CVE-2024-23342", "package": "ecdsa", "installed": "0.19.1", "fixed": "",
         "severity": "HIGH", "target": "opt/checkov"}


def _script():
    spec = importlib.util.spec_from_file_location("release_notes_image", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["release_notes_image"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _verdict(root: Path, arch: str, *, unfixed=(), accepted=()) -> Path:
    path = root / f"image-gate-{arch}" / "image-gate.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"blocking": [], "accepted": list(accepted),
                                "unfixed": list(unfixed), "refused": []}))
    return path


def _rows(out: str) -> list[list[str]]:
    return [[cell.strip() for cell in line.strip("|").split("|")]
            for line in out.splitlines() if line.startswith("| ") and "advisory" not in line]


def test_one_row_per_finding_across_architectures(tmp_path, capsys):
    paths = [_verdict(tmp_path, arch, unfixed=[ECDSA]) for arch in ("amd64", "arm64")]

    assert _script().main([str(p) for p in paths]) == 0

    out = capsys.readouterr().out
    assert HEADING in out.splitlines()
    rows = [row for row in _rows(out) if row[0] == "CVE-2024-23342"]
    assert len(rows) == 1
    assert rows[0][4] == "amd64, arm64"
    assert rows[0][5] == "no fix yet"


def test_an_accepted_finding_shows_its_expiry(tmp_path, capsys):
    pip = {"id": "GHSA-xxxx", "package": "pip", "installed": "25.0.1", "fixed": "26.2",
           "severity": "MEDIUM", "target": "usr/local", "expires": "2026-11-24"}

    assert _script().main([str(_verdict(tmp_path, "amd64", accepted=[pip]))]) == 0

    rows = [row for row in _rows(capsys.readouterr().out) if row[0] == "GHSA-xxxx"]
    assert [row[5] for row in rows] == ["accepted until 2026-11-24"]


def test_rows_are_ordered_by_severity_then_id(tmp_path, capsys):
    found = [{**ECDSA, "id": id_, "severity": severity}
             for id_, severity in [("CVE-3", "LOW"), ("CVE-2", "CRITICAL"), ("CVE-1", "HIGH"),
                                   ("CVE-0", "LOW")]]

    assert _script().main([str(_verdict(tmp_path, "arm64", unfixed=found))]) == 0

    rows = _rows(capsys.readouterr().out)
    assert [(row[0], row[3]) for row in rows] == [
        ("CVE-2", "CRITICAL"), ("CVE-1", "HIGH"), ("CVE-0", "LOW"), ("CVE-3", "LOW")]
