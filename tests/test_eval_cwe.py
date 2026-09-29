"""R9.4: a finding reaches a static-analysis category by its CWE (ADR-0026, D21).

From the finding's own `cwe` when it carries one (F5.10, from R13), else from its
rule's metadata under `rules/`, else from its Scanner's class: a secret Gitleaks
finds in code is a hard-coded credential. A child CWE counts toward its parent.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVAL = REPO / "scripts" / "eval"


def _cwe():
    spec = importlib.util.spec_from_file_location("cwe", EVAL / "cwe.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["cwe"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_a_finding_s_cwe_comes_from_itself_its_rule_or_its_scanner():
    cwe_of = _cwe().lookup(REPO / "rules")

    assert cwe_of({"rule": "valvur.python.string-built-sql"}) == {89}
    assert cwe_of({"rule": "valvur.python.dangerous-eval"}) == {95, 94}
    assert cwe_of({"rule": "x", "cwe": ["CWE-22: Path Traversal"]}) == {22}
    assert cwe_of({"rule": "generic-api-key", "sources": ["gitleaks"]}) == {798}
    assert cwe_of({"rule": "unknown", "sources": ["trivy"]}) == set()


def test_every_rule_of_valvur_s_own_declares_a_cwe():
    for path in sorted((REPO / "rules").glob("*.yaml")):
        blocks = re.split(r"^  - id: ", path.read_text(), flags=re.M)[1:]
        for block in blocks:
            assert re.search(r"^\s+cwe:", block, re.M), f"{path.name}: {block.split()[0]}"
