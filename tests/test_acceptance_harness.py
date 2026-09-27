"""R2.2: the harness judges a scan against its repository's `expected.toml`.

Tested on fixture results folders: what a scan wrote, not how it ran.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "acceptance.py"

TASKS = """\
- [x] **R3.1** **Tracer bullet.**
- [ ] **R3.2** **The File Set**
"""


def _module():
    spec = importlib.util.spec_from_file_location("acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["acceptance"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _results(tmp_path: Path, findings: list[dict], complete: bool = True) -> Path:
    folder = tmp_path / ".security-scan"
    folder.mkdir(parents=True)
    (folder / "findings.json").write_text(json.dumps({"findings": findings}))
    (folder / "run.json").write_text(json.dumps({"complete": complete, "status": "findings"}))
    return folder


def _finding(rule: str, path: str, severity: str = "low") -> dict:
    return {"rule": rule, "path": path, "severity": severity, "suppressed": False}


EXPECTED = {"run": {"complete": True},
            "must": [{"rule": "subprocess-shell-true", "path": "src/app.py"}]}


def test_a_missing_expected_finding_fails(tmp_path):
    verdict = _module().judge(_results(tmp_path, []), EXPECTED, TASKS)
    assert verdict.ok is False
    assert verdict.missing == ["subprocess-shell-true at src/app.py"]
