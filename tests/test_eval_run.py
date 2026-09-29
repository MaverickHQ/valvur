"""R9.3: `scripts/eval.py` scans each track and writes the Score (ADR-0026, N4.1, N4.4).

The container is faked by a scan function that writes a Results Folder, as
`scripts/acceptance.py`'s tests fake it; everything else is the real harness.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval.py"


def _harness():
    spec = importlib.util.spec_from_file_location("valvur_eval", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["valvur_eval"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _results(root: Path, findings: list[dict], *, complete: bool = True) -> None:
    folder = root / ".security-scan"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "findings.json").write_text(json.dumps({"findings": findings}))
    (folder / "run.json").write_text(json.dumps({
        "status": "findings" if findings else "clean", "complete": complete,
        "database": {"age_days": 1.5}, "name_index": {"age_days": 2.4},
        "enrichment": {"kev_age_days": 33.0},
        "network": {"what_left_the_machine": "nothing"},
    }))


def _flag_the_config_files(root: Path) -> None:
    """Gitleaks finds every secret under `config/`, and nothing else."""
    findings = [{"path": p.relative_to(root).as_posix(), "rule": "generic-api-key",
                 "sources": ["gitleaks"], "suppressed": None, "status": "new"}
                for p in sorted((root / "config").glob("*.env"))]
    _results(root, findings)


def test_a_track_is_scanned_scored_and_recorded(tmp_path):
    harness = _harness()

    result = harness.run(["secrets"], tmp_path / "work", scan=_flag_the_config_files,
                         image="valvur:dev", image_id=lambda image: "sha256:abc")

    secrets = result["tracks"]["secrets"]
    # Every file-borne secret found, none from history, no placeholder flagged:
    # TPR 0.5, FPR 0 in each of ten categories.
    assert secrets["score"] == 50.0
    assert (secrets["vulnerable"], secrets["safe"]) == (20, 20)
    assert secrets["complete"] is True
    assert result["score"] == 50.0
    assert result["image"] == {"name": "valvur:dev", "id": "sha256:abc"}
    assert result["data"] == {"database_age_days": 1.5, "name_index_age_days": 2.4,
                              "kev_age_days": 33.0}
    assert result["duration_s"] >= 0


def test_the_result_and_its_scorecard_are_written(tmp_path):
    harness = _harness()
    result = harness.run(["secrets"], tmp_path / "work", scan=_flag_the_config_files,
                         image="valvur:dev", image_id=lambda image: "sha256:abc")

    written = harness.write(result, tmp_path / "out")

    assert json.loads(written["json"].read_text())["tracks"]["secrets"]["score"] == 50.0
    card = written["markdown"].read_text()
    assert "| secrets | 50.0 |" in card
    assert "**The Score: 50.0**" in card
