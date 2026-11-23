"""R52.2: the release's OpenVEX document, from the image gate's verdicts (D82q, Req. 14.1).

A release said what its image does not fix in its notes, as a table for a person.
`scripts/image_vex.py` says the same to a tool: one OpenVEX document whose product is the
image by digest, written from the verdicts `scripts/image_gate.py --out` leaves, one for
each architecture, and from the owner's `.github/image-accepted.yaml`.

It says only what valvur knows. A vulnerability with no fixed version is
`under_investigation`. One the owner accepted is `affected`, with the reason and the expiry,
or `not_affected` when the owner's entry gives one of OpenVEX's own justifications. valvur
claims `not_affected` for nothing by itself. Every document here is validated against
OpenVEX's schema, vendored.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "image_vex.py"
SCHEMA = REPO / "tests" / "fixtures" / "schema" / "openvex-0.2.0" / "openvex_json_schema.json"
DIGEST = "sha256:" + "ab" * 32
WHEN = "2026-11-23T05:00:00Z"
ECDSA = {"id": "CVE-2024-23342", "package": "ecdsa", "installed": "0.19.1", "fixed": "",
         "severity": "HIGH", "target": "opt/checkov", "kind": "python-pkg"}
BUSYBOX = {"id": "CVE-2026-1111", "package": "busybox", "installed": "1.37.0-r30",
           "fixed": "1.37.0-r31", "severity": "MEDIUM", "target": "valvur (alpine 3.24.1)",
           "kind": "alpine", "expires": "2027-01-31"}


def _script():
    spec = importlib.util.spec_from_file_location("image_vex", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["image_vex"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _verdict(root: Path, arch: str, *, unfixed=(), accepted=()) -> Path:
    path = root / f"image-gate-{arch}" / "image-gate.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"blocking": [], "accepted": list(accepted),
                                "unfixed": list(unfixed), "refused": []}))
    return path


def _accepted(root: Path, *entries: dict[str, str]) -> Path:
    lines = ["accepted:"]
    for entry in entries:
        first, *rest = entry.items()
        lines.append(f"  - {first[0]}: {first[1]}")
        lines += [f"    {key}: {value}" for key, value in rest]
    path = root / "image-accepted.yaml"
    path.write_text("\n".join(lines) + "\n")
    return path


def _run(root: Path, *verdicts: Path, accepted: Path | None = None) -> tuple[int, Path]:
    out = root / "valvur-1.7.0.openvex.json"
    code = _script().main([
        "--image", "ghcr.io/maverickhq/valvur", "--digest", DIGEST, "--release", "1.7.0",
        "--timestamp", WHEN, "--accepted", str(accepted or _accepted(root)),
        "--out", str(out), *map(str, verdicts)])
    return code, out


def _valid(path: Path) -> dict:
    import jsonschema

    document = json.loads(path.read_text())
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(document)
    return document


def test_an_entry_with_no_fixed_version_is_under_investigation_for_the_image_by_digest(
        tmp_path):
    code, out = _run(tmp_path, _verdict(tmp_path, "amd64", unfixed=[ECDSA]))

    assert code == 0
    document = _valid(out)
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["@id"] == ("https://github.com/MaverickHQ/valvur/releases/download/v1.7.0/"
                               "valvur-1.7.0.openvex.json")
    assert (document["timestamp"], document["version"]) == (WHEN, 1)
    [statement] = document["statements"]
    assert statement["vulnerability"] == {"name": "CVE-2024-23342"}
    assert statement["status"] == "under_investigation"
    [product] = statement["products"]
    assert product["identifiers"]["purl"] == (
        "pkg:oci/valvur@sha256%3A" + "ab" * 32 + "?repository_url=ghcr.io/maverickhq/valvur")
    assert product["subcomponents"] == [{"@id": "pkg:pypi/ecdsa@0.19.1"}]
    assert "no fixed version" in statement["status_notes"]
    assert "justification" not in statement and "impact_statement" not in statement


def test_an_accepted_entry_is_affected_with_the_acceptances_reason_and_expiry(tmp_path):
    accepted = _accepted(tmp_path, {"id": BUSYBOX["id"], "package": "busybox",
                                    "expires": "2027-01-31",
                                    "reason": "The applet is not built into the image."})

    code, out = _run(tmp_path, _verdict(tmp_path, "amd64", accepted=[BUSYBOX]),
                     accepted=accepted)

    assert code == 0
    [statement] = _valid(out)["statements"]
    assert statement["status"] == "affected"
    assert statement["action_statement"] == (
        "Accepted by the maintainer until 2027-01-31: The applet is not built into the "
        "image. busybox 1.37.0-r30 is fixed in 1.37.0-r31. Found in valvur (alpine 3.24.1).")
    assert statement["products"][0]["subcomponents"] == [
        {"@id": "pkg:apk/alpine/busybox@1.37.0-r30"}]
    assert "justification" not in statement


def test_an_acceptance_that_gives_one_of_openvexs_justifications_is_not_affected(tmp_path):
    accepted = _accepted(tmp_path, {
        "id": BUSYBOX["id"], "package": "busybox", "expires": "2027-01-31",
        "reason": "The applet is not built into the image.",
        "justification": "vulnerable_code_not_present"})

    code, out = _run(tmp_path, _verdict(tmp_path, "amd64", accepted=[BUSYBOX]),
                     accepted=accepted)

    assert code == 0
    [statement] = _valid(out)["statements"]
    assert (statement["status"], statement["justification"]) == (
        "not_affected", "vulnerable_code_not_present")
    assert statement["impact_statement"].startswith("The applet is not built into the image.")
    assert "2027-01-31" in statement["impact_statement"]
    assert "action_statement" not in statement


def test_a_justification_openvex_does_not_have_is_refused_and_nothing_is_written(tmp_path,
                                                                                capsys):
    """valvur claims `not_affected` for nothing by itself, and passes on no word of the
    owner's that OpenVEX does not define."""
    accepted = _accepted(tmp_path, {"id": BUSYBOX["id"], "package": "busybox",
                                    "expires": "2027-01-31", "reason": "Fine.",
                                    "justification": "we_think_it_is_fine"})

    code, out = _run(tmp_path, _verdict(tmp_path, "amd64", accepted=[BUSYBOX]),
                     accepted=accepted)

    assert code == 2 and not out.exists()
    assert "we_think_it_is_fine" in capsys.readouterr().err


def test_nothing_is_ever_not_affected_without_the_owners_entry_saying_so(tmp_path):
    code, out = _run(tmp_path, _verdict(tmp_path, "amd64", unfixed=[ECDSA], accepted=[BUSYBOX]))

    assert code == 0
    assert sorted(s["status"] for s in _valid(out)["statements"]) == [
        "affected", "under_investigation"]


def test_two_architectures_give_one_document_and_an_entry_on_one_alone_names_it(tmp_path):
    amd64 = _verdict(tmp_path, "amd64", unfixed=[ECDSA])
    arm64 = _verdict(tmp_path, "arm64", unfixed=[ECDSA, {**ECDSA, "id": "CVE-2026-2222",
                                                           "package": "libfoo",
                                                           "kind": "alpine"}])

    code, out = _run(tmp_path, amd64, arm64)

    assert code == 0
    both, one = _valid(out)["statements"]
    assert both["vulnerability"]["name"] == "CVE-2024-23342"
    assert [p["identifiers"]["purl"] for p in both["products"]] == [
        "pkg:oci/valvur@sha256%3A" + "ab" * 32 + "?repository_url=ghcr.io/maverickhq/valvur"]
    assert "alone" not in both["status_notes"]
    assert one["vulnerability"]["name"] == "CVE-2026-2222"
    assert [p["identifiers"]["purl"] for p in one["products"]] == [
        "pkg:oci/valvur@sha256%3A" + "ab" * 32
        + "?repository_url=ghcr.io/maverickhq/valvur&arch=arm64"]
    assert one["status_notes"].endswith("On arm64 alone.")


def test_verdicts_with_nothing_to_say_give_no_document(tmp_path, capsys):
    """Amended by R52.1: OpenVEX requires at least one statement, so there is no valid
    document with none. Nothing is written, and the run says why."""
    code, out = _run(tmp_path, _verdict(tmp_path, "amd64"), _verdict(tmp_path, "arm64"))

    assert code == 0 and not out.exists()
    assert "nothing to state" in capsys.readouterr().out


def test_the_same_verdicts_and_timestamp_give_the_same_bytes(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    made = []
    for root, order in ((first, ("amd64", "arm64")), (second, ("arm64", "amd64"))):
        root.mkdir()
        verdicts = {arch: _verdict(root, arch, unfixed=[ECDSA, {**ECDSA, "id": "CVE-1"}]
                                   if arch == "amd64" else [{**ECDSA, "id": "CVE-1"}, ECDSA])
                    for arch in ("amd64", "arm64")}
        code, out = _run(root, *(verdicts[arch] for arch in order))
        assert code == 0
        made.append(out.read_bytes())

    assert made[0] == made[1], "neither the order given nor the order found changes a byte"


def test_a_verdict_that_cannot_be_read_exits_2_and_writes_nothing(tmp_path, capsys):
    good = _verdict(tmp_path, "amd64", unfixed=[ECDSA])
    bad = tmp_path / "image-gate-arm64" / "image-gate.json"
    bad.parent.mkdir()
    bad.write_text('{"blocking": []')

    code, out = _run(tmp_path, good, bad)

    assert code == 2 and not out.exists()
    assert str(bad) in capsys.readouterr().err
    missing = tmp_path / "image-gate-s390x" / "image-gate.json"
    assert _run(tmp_path, good, missing)[0] == 2 and not out.exists()
    not_a_verdict = tmp_path / "image-gate-riscv" / "image-gate.json"
    not_a_verdict.parent.mkdir()
    not_a_verdict.write_text('{"findings": []}')
    assert _run(tmp_path, good, not_a_verdict)[0] == 2 and not out.exists()
