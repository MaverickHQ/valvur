"""R49.3: a vendored rule with a tier row carries its corpus counts in the manifest.

`rules/vendor/gitlab/manifest.json` gives each vendored rule's measurement when it was
admitted, on the planted tracks. A rule the tier table lists is under the bar on maintained
code, and a reader of the manifest should see that beside the number that admitted it. The
rule's own file is never edited (Requirement 4.4): the audit holds it byte for byte.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from valvur import tiers

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "rules" / "vendor" / "gitlab" / "manifest.json"
RANDOM = "python_random_rule-random"


def _audit():
    spec = importlib.util.spec_from_file_location("sast_rules",
                                                  REPO / "scripts" / "eval" / "sast_rules.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["sast_rules"] = module
    spec.loader.exec_module(module)
    return module


def test_the_manifest_carries_the_corpus_counts_of_each_vendored_rule_with_a_row():
    rows = {row.id: row for row in tiers.rows() if row.scanner == "opengrep"}
    entries = {entry["id"]: entry for entry in json.loads(MANIFEST.read_text())["rules"]}

    assert RANDOM in rows and RANDOM in entries
    for rule, entry in entries.items():
        if rule in rows:
            assert entry["corpus"] == {"true_positives": rows[rule].tp,
                                       "false_positives": rows[rule].fp}, rule
        else:
            assert "corpus" not in entry, rule


def test_vendoring_again_writes_them(tmp_path):
    checkout = tmp_path / "checkout"
    (checkout / "python" / "random").mkdir(parents=True)
    (checkout / "LICENSE").write_text("MIT\n")
    (checkout / "python" / "random" / "rule-random.yml").write_text(f"rules:\n- id: {RANDOM}\n")
    (checkout / "python" / "other.yml").write_text("rules:\n- id: python_other\n")
    entry = {"languages": ["python"], "cwe": "CWE-338", "origin": "bandit",
             "origin_licence": "Apache-2.0", "licence": "MIT", "eligible": True}
    audited = {"source": "https://example.invalid/rules", "commit": "0" * 40, "rules": [
        {**entry, "id": RANDOM, "path": "python/random/rule-random.yml"},
        {**entry, "id": "python_other", "path": "python/other.yml"}]}
    measured = {"ships": [RANDOM, "python_other"],
                "rules": {RANDOM: {"tp": 35, "fp": 3, "precision": 0.921},
                          "python_other": {"tp": 5, "fp": 0, "precision": 1.0}}}

    _audit().vendor(checkout, audited, measured, tmp_path / "vendor")

    written = {e["id"]: e for e in
               json.loads((tmp_path / "vendor" / "manifest.json").read_text())["rules"]}
    assert written[RANDOM]["corpus"] == {"true_positives": 0, "false_positives": 23}
    assert (written[RANDOM]["true_positives"], written[RANDOM]["false_positives"]) == (35, 3)
    assert "corpus" not in written["python_other"]
