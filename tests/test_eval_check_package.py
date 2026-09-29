"""R12.4: the package-reality track through `check_package` as well as a scan.

Track 5 scores what a scan reports about each declared package. The same cases are
asked of `check_package`, the tool an agent calls before the install, with each case's
directory as the project whose registry configuration applies. Both scores are
reported; the Score's mean keeps the scan's, so the ratchet measures what it always
has.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "malicious-packages"


def _harness():
    spec = importlib.util.spec_from_file_location("valvur_eval", REPO / "scripts" / "eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["valvur_eval"] = module
    spec.loader.exec_module(module)
    return module


def test_the_track_is_scored_through_check_package_too(tmp_path, name_index):
    from valvur.name_index import malicious

    harness = _harness()
    real = {eco: kinds["real"] for eco, kinds in harness.twins.REALITY.items()}
    directory = name_index(**real)
    assert malicious._main(["build-malicious", str(directory), str(FIXTURE)]) == 0

    def scan(root: Path) -> None:                 # a scan that finds nothing at all
        folder = root / ".security-scan"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "findings.json").write_text(json.dumps({"findings": []}))
        (folder / "run.json").write_text(json.dumps({
            "status": "clean", "complete": True,
            "network": {"what_left_the_machine": "nothing"}}))

    result = harness.run(["package-reality"], tmp_path / "work", scan=scan,
                         image="valvur:dev", image_id=lambda image: "sha256:abc")
    track = result["tracks"]["package-reality"]

    assert track["score"] == 0.0                   # the scan flagged nothing
    assert track["check_package"] == 100.0         # the tool flagged every case right
    assert result["score"] == 0.0                  # the mean is the scan's
    assert "Package reality through `check_package`: **100.0**" in harness.scorecard(result)
