"""R43.1, through the image: the acceptance set's dependency repository, scanned, carries
each advisory's publication date (F5.11)."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.mark.e2e
def test_a_scan_of_the_dependency_repository_carries_advisory_dates(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "generate", REPO / "scripts" / "acceptance" / "generate.py")
    generate = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(generate)  # type: ignore[union-attr]
    root = generate.build(tmp_path, "2")["2-lockfiles"]

    subprocess.run([sys.executable, "-c", "from valvur.cli import main; raise SystemExit(main())",
                    "scan", str(root)], check=True, capture_output=True, env={**os.environ})
    findings = json.loads((root / ".security-scan" / "findings.json").read_text())["findings"]
    vulnerable = [f for f in findings if f.get("dependency") and f["rule"].startswith(
        ("CVE-", "GHSA-", "PYSEC-"))]

    assert len(vulnerable) >= 10
    dated = [f for f in vulnerable if f["dependency"]["advisory_published"]]
    assert len(dated) == len(vulnerable)
    assert all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                            f["dependency"]["advisory_published"]) for f in dated)
