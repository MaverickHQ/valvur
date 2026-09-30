"""R13.1: GitLab's `sast-rules`, audited by licence before anything is vendored (D29).

The rules are MIT, but many are translations of another project's checks, and a
translation carries its origin's terms. So each candidate rule's origin is named from
the repository's own `mappings/`, and a rule may ship only when both its file and its
origin are MIT, Apache-2.0 or BSD: flawfinder (GPL), find-sec-bugs, security-code-scan
and njsscan (LGPL), Brakeman's licence, and the trees under GitLab's EE licence, LGPL
and Commons Clause are all out. The manifest is committed so the audit can be read.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EVAL = REPO / "scripts" / "eval"
MANIFEST = REPO / "tests" / "eval" / "sast-rules.json"
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"}


def _audit():
    spec = importlib.util.spec_from_file_location("sast_rules", EVAL / "sast_rules.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["sast_rules"] = module
    spec.loader.exec_module(module)
    return module


def test_the_source_is_pinned_by_commit():
    pinned = tomllib.loads((REPO / "tests" / "eval" / "sources.toml").read_text())
    source = pinned["gitlab-sast-rules"]

    assert re.fullmatch(r"[0-9a-f]{40}", source["commit"])
    assert source["url"].startswith("https://gitlab.com/gitlab-org/security-products/")


def test_the_manifest_names_every_candidates_origin_and_licence():
    entries = json.loads(MANIFEST.read_text())["rules"]

    for entry in entries:
        assert set(entry) >= {"id", "path", "languages", "cwe", "origin", "origin_licence",
                              "licence", "eligible"}, entry
        assert entry["eligible"] == (entry["licence"] in PERMISSIVE
                                     and entry["origin_licence"] in PERMISSIVE), entry
    by_origin = {e["origin"]: e for e in entries}
    assert by_origin["bandit"]["origin_licence"] == "Apache-2.0"
    assert by_origin["gosec"]["origin_licence"] == "Apache-2.0"
    assert by_origin["find-sec-bugs"]["origin_licence"] == "LGPL-3.0"
    assert not by_origin["find-sec-bugs"]["eligible"]
    assert {e["languages"][0] for e in entries if e["eligible"]} <= {
        "python", "javascript", "typescript", "go", "java"}


def test_a_vendored_rule_whose_origin_is_not_permissive_is_refused(tmp_path):
    audit = _audit()
    vendored = tmp_path / "vendor"
    vendored.mkdir()
    (vendored / "ok.yml").write_text("rules:\n- id: python_exec_rule-exec-used\n")
    (vendored / "lgpl.yml").write_text(
        "rules:\n- id: java_inject_rule-SqlInjection\n")
    manifest = {"rules": [
        {"id": "python_exec_rule-exec-used", "origin": "bandit",
         "origin_licence": "Apache-2.0", "licence": "MIT", "eligible": True},
        {"id": "java_inject_rule-SqlInjection", "origin": "find-sec-bugs",
         "origin_licence": "LGPL-3.0", "licence": "MIT", "eligible": False}]}

    refused = audit.refuse(vendored, manifest)

    assert refused == ["java_inject_rule-SqlInjection: find-sec-bugs is LGPL-3.0"]


def test_every_vendored_rule_passes_the_audit():
    audit = _audit()

    assert audit.refuse(REPO / "rules" / "vendor" / "gitlab",
                        json.loads(MANIFEST.read_text())) == []
