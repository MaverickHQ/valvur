"""R51.7: what an importing tool lost, corrected inside SARIF (Requirement 9.2).

Measured on 2026-11-23 (`docs/acceptance/r51.md`): DefectDojo 3.5.202 reads any entry in a
result's `suppressions` as *suppressed*, whatever its `status`, and files the finding as an
inactive false positive. valvur wrote a project's own ignore that it did **not** accept as a
suppression with `status: rejected`, which SARIF defines as not suppressed. So a live
Finding, one a `.trivyignore` named with no reason and no expiry, arrived hidden.

A result now carries a `suppressions` entry only when the risk was accepted. An ignore that
was not accepted is said in the result's `properties`, where it hides nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur import artifacts
from valvur.findings import Finding, IgnoredBy

IGNORE = IgnoredBy(ignore=".trivyignore", where=".trivyignore:1", text="CVE-2022-46175",
                   kind="external")
STATED = IgnoredBy(ignore="checkov:skip", where="infra/main.tf:2", kind="inSource",
                   text="checkov:skip=CKV_AWS_18:logs are elsewhere exp:2027-01-01",
                   reason="logs are elsewhere", expires="2027-01-01")


def _finding(rule: str, **given) -> Finding:
    return Finding(rule=rule, path="package-lock.json", line=0, title=f"{rule}: a flaw",
                   severity="high", fingerprint=(rule.encode().hex() * 4)[:32],
                   sources=("trivy",), **given)


def _results(findings: list[Finding]) -> dict[str, dict]:
    document = json.loads(artifacts.sarif(findings, version="1"))
    return {result["ruleId"]: result for result in document["runs"][0]["results"]}


def test_an_ignore_valvur_did_not_accept_is_no_sarif_suppression():
    result = _results([_finding("CVE-2022-46175", ignored_by=IGNORE)])["CVE-2022-46175"]

    assert "suppressions" not in result, "an importer would file a live Finding as suppressed"
    assert result["properties"]["ignoredBy"] == {
        "ignore": ".trivyignore", "where": ".trivyignore:1", "kind": "external",
        "accepted": False}


def test_a_risk_the_project_accepted_is_still_a_sarif_suppression():
    results = _results([
        _finding("CVE-1", suppressed="Accepted until the next release."),
        _finding("CVE-2", suppressed="logs are elsewhere", ignored_by=STATED)])

    assert results["CVE-1"]["suppressions"] == [
        {"kind": "external", "status": "accepted",
         "justification": "Accepted until the next release."}]
    assert results["CVE-2"]["suppressions"] == [
        {"kind": "inSource", "status": "accepted", "justification": "logs are elsewhere"}]
    assert "ignoredBy" not in results["CVE-1"]["properties"]


def test_no_result_carries_a_suppression_that_was_not_accepted():
    """The rule, over every shape at once: `status` is `accepted` wherever the key is."""
    findings = [_finding("CVE-1"), _finding("CVE-2", ignored_by=IGNORE),
                _finding("CVE-3", suppressed="a reason"),
                _finding("CVE-4", suppressed="a reason", ignored_by=STATED)]

    statuses = [s["status"] for result in _results(findings).values()
                for s in result.get("suppressions") or []]

    assert statuses == ["accepted", "accepted"]


def test_it_is_still_valid_sarif():
    import jsonschema

    schema = json.loads((Path(__file__).parent / "fixtures" / "schema"
                         / "sarif-2.1.0.json").read_text())
    document = json.loads(artifacts.sarif(
        [_finding("CVE-2", ignored_by=IGNORE), _finding("CVE-3", suppressed="a reason")],
        version="1"))

    jsonschema.validate(instance=document, schema=schema)
