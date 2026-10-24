"""R43.4 (D81t): the image that ships is judged, not only the tree (N2.7).

Every gate read the repository's lockfiles, and none the built image: its base tag
stopped moving on 2026-04-19, and 1.5.3 shipped without six months of OpenSSL, musl, xz
and zlib fixes, and with Go Scanners built before Go's fix for CVE-2026-111943.
`scripts/image_gate.py` reads the image's own Trivy over its root filesystem. A
vulnerability with a fixed version blocks unless the owner's
`.github/image-accepted.yaml` lists it with an expiry still ahead; one with no fixed
version is reported. Recorded input: Trivy's answer for the published 1.5.3 image on
2026-10-24, trimmed to the fields the gate reads.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "image_gate.py"
RECORDED = Path(__file__).resolve().parent / "fixtures" / "image-gate" / "trivy-rootfs-1.5.3.json"
TODAY = "2026-10-24"


def _gate():
    spec = importlib.util.spec_from_file_location("image_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["image_gate"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _report(*vulns: dict) -> dict:
    return {"Results": [{"Target": "img (alpine 3.24.3)", "Class": "os-pkgs", "Type": "alpine",
                         "Vulnerabilities": list(vulns)}]}


def _vuln(vid: str, package: str, fixed: str = "") -> dict:
    return {"VulnerabilityID": vid, "PkgName": package, "InstalledVersion": "1.0",
            "FixedVersion": fixed, "Severity": "HIGH"}


def _run(tmp_path: Path, report: dict | str, accepted: str | None = None, *extra: str):
    scan = tmp_path / "scan.json"
    scan.write_text(report if isinstance(report, str) else json.dumps(report))
    argv = [str(scan), "--today", TODAY, "--out", str(tmp_path / "verdict.json"), *extra]
    file = tmp_path / "image-accepted.yaml"
    if accepted is not None:
        file.write_text(accepted)
    argv += ["--accepted", str(file)]
    code = _gate().main(argv)
    verdict = tmp_path / "verdict.json"
    return code, json.loads(verdict.read_text()) if verdict.is_file() else None


def test_a_vulnerability_with_a_fixed_version_blocks(tmp_path, capsys):
    code, verdict = _run(tmp_path, _report(_vuln("CVE-2026-85091", "zlib", "1.3.2-r1")))

    assert code == 1
    assert verdict["blocking"] == [{"id": "CVE-2026-85091", "package": "zlib",
                                    "installed": "1.0", "fixed": "1.3.2-r1",
                                    "severity": "HIGH", "target": "img (alpine 3.24.3)"}]
    assert "CVE-2026-85091 zlib 1.0, fixed in 1.3.2-r1" in capsys.readouterr().out


def test_one_the_owner_accepted_with_an_expiry_ahead_does_not_block(tmp_path):
    accepted = ("accepted:\n"
                "  - id: CVE-2024-23342\n    package: ecdsa\n    expires: 2026-12-31\n"
                "    reason: no fix exists; Checkov's dependency, accepted for the tree since"
                " 2026-09-14\n")
    code, verdict = _run(tmp_path, _report(_vuln("CVE-2024-23342", "ecdsa", "0.19.3")),
                         accepted)

    assert code == 0
    assert verdict["blocking"] == [] and [a["id"] for a in verdict["accepted"]] == [
        "CVE-2024-23342"]


def test_an_entry_without_an_expiry_or_past_it_is_refused_by_name(tmp_path, capsys):
    accepted = ("accepted:\n"
                "  - id: CVE-2024-23342\n    package: ecdsa\n    reason: forever\n"
                "  - id: CVE-2026-85091\n    package: zlib\n    expires: 2026-10-23\n")
    code, verdict = _run(tmp_path, _report(_vuln("CVE-2024-23342", "ecdsa", "0.19.3"),
                                           _vuln("CVE-2026-85091", "zlib", "1.3.2-r1")),
                         accepted)

    assert code == 1
    assert [r["id"] for r in verdict["refused"]] == ["CVE-2024-23342", "CVE-2026-85091"]
    assert {b["id"] for b in verdict["blocking"]} == {"CVE-2024-23342", "CVE-2026-85091"}
    out = capsys.readouterr().out
    assert "CVE-2024-23342 ecdsa: no expiry" in out and "CVE-2026-85091 zlib: expired" in out


def test_one_with_no_fixed_version_is_reported_and_does_not_block(tmp_path):
    code, verdict = _run(tmp_path, _report(_vuln("CVE-2025-0001", "libuuid")))

    assert code == 0
    assert [u["id"] for u in verdict["unfixed"]] == ["CVE-2025-0001"]


def test_input_it_cannot_read_exits_2(tmp_path):
    assert _run(tmp_path, "{not json")[0] == 2
    assert _run(tmp_path, json.dumps({"Results": "nope"}))[0] == 2
    assert _run(tmp_path, _report(), "accepted:\n  - this is: not an entry\n")[0] == 2


def test_the_published_1_5_3_image_is_red_on_each_of_the_five(tmp_path):
    """The positive control, behaviour 1's: OpenSSL's 25 fixed in 3.5.7 and 3.5.8,
    musl's, xz's and zlib's, and Go's CVE-2026-111943 in the Scanners' binaries."""
    code, verdict = _run(tmp_path, RECORDED.read_text())
    blocking = verdict["blocking"]

    assert code == 1
    openssl = {b["id"] for b in blocking if b["package"] == "libssl3"}
    assert len(openssl) == 25
    assert {b["fixed"] for b in blocking if b["package"] == "libssl3"} == {"3.5.7-r0", "3.5.8-r0"}
    for vid, package in (("CVE-2026-107891", "musl"), ("CVE-2026-34743", "xz-libs"),
                         ("CVE-2026-85091", "zlib")):
        assert any(b["id"] == vid and b["package"] == package for b in blocking), vid
    go = {b["target"] for b in blocking if b["id"] == "CVE-2026-111943"}
    assert go == {"usr/local/bin/gitleaks", "usr/local/bin/osv-scanner",
                  "usr/local/bin/syft", "usr/local/bin/trivy"}
    assert len(verdict["unfixed"]) == 5


def test_nothing_in_the_tree_writes_the_accepted_file():
    """The owner's alone, as a Suppression is (R43.4, Requirement 16.3)."""
    writes = re.compile(r"(>|tee |write_text|open\([^)]*['\"]w|\.write\()")
    for path in [*REPO.glob("scripts/**/*"), *REPO.glob("src/**/*"),
                 *REPO.glob(".github/**/*")]:
        if not path.is_file() or path.suffix not in {".py", ".sh", ".yml", ".yaml"}:
            continue
        for line in path.read_text(errors="ignore").splitlines():
            if "image-accepted" in line:
                assert not writes.search(line), (path, line)
