"""R44.12: the image gate's verdict names each entry's kind, from Trivy's own field.

The image's heal plans from the verdict, and the three kinds are healed three ways: an
Alpine package is raised, a Go module is raised in the Scanner whose binary holds it, a
Python package is the Checkov lock's. Trivy says which, as each result's `Type`, so the
plan never guesses from a target's name.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _gate():
    spec = importlib.util.spec_from_file_location("image_gate", REPO / "scripts" / "image_gate.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["image_gate"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _vuln(vid: str, package: str, fixed: str) -> dict:
    return {"VulnerabilityID": vid, "PkgName": package, "InstalledVersion": "1.0",
            "FixedVersion": fixed, "Severity": "HIGH"}


def test_each_entry_carries_the_type_trivy_gave_its_result(tmp_path):
    report = {"Results": [
        {"Target": "img (alpine 3.24.3)", "Class": "os-pkgs", "Type": "alpine",
         "Vulnerabilities": [_vuln("CVE-1", "zlib", "1.4-r0")]},
        {"Target": "usr/local/bin/trivy", "Class": "lang-pkgs", "Type": "gobinary",
         "Vulnerabilities": [_vuln("CVE-2", "golang.org/x/crypto", "0.59.0"),
                             _vuln("CVE-3", "stdlib", "")]},
        {"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg",
         "Vulnerabilities": [_vuln("CVE-4", "soupsieve", "2.9")]},
        {"Target": "a result with no type", "Vulnerabilities": [_vuln("CVE-5", "x", "2")]},
    ]}
    scan, out = tmp_path / "scan.json", tmp_path / "verdict.json"
    scan.write_text(json.dumps(report))

    code = _gate().main([str(scan), "--today", "2026-11-22", "--out", str(out),
                         "--accepted", str(tmp_path / "none.yaml")])

    verdict = json.loads(out.read_text())
    assert code == 1
    assert {v["id"]: v["kind"] for v in verdict["blocking"]} == {
        "CVE-1": "alpine", "CVE-2": "gobinary", "CVE-4": "python-pkg", "CVE-5": ""}
    assert [(v["id"], v["kind"]) for v in verdict["unfixed"]] == [("CVE-3", "gobinary")]
