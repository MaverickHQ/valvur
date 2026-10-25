"""R43.1 (D81o): an advisory's publication date on its dependency Finding (F5.11).

The nightly's healing window, and later the heal, judge an advisory's age from the
Results Folder alone. Trivy gives `PublishedDate`, OSV-Scanner `published`; the Finding
keeps the earlier, normalised to `YYYY-MM-DDTHH:MM:SSZ`, and `""` when neither gives
a date it can read. It is enrichment: it never feeds the Fingerprint.
"""

from __future__ import annotations

import json
import re

from conftest import GoldenRunner, golden

from valvur import scan
from valvur.adapters import OsvAdapter, TrivyAdapter

_STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def _scan(workspace, trivy: str | None = None, osv: str | None = None):
    runner, adapters = {}, []
    if trivy is not None:
        runner["trivy"], adapters = trivy, [*adapters, TrivyAdapter()]
    if osv is not None:
        runner["osv-scanner"], adapters = osv, [*adapters, OsvAdapter()]
    return scan(workspace, runner=GoldenRunner(**runner), adapters=adapters)


def test_trivy_s_published_date_is_carried_normalised(workspace):
    run = _scan(workspace, trivy=golden("trivy"))
    dated = [f for f in run.findings if f.dependency]

    assert dated
    raw = json.loads(golden("trivy"))
    # An advisory published hours before the capture can carry no date yet: Trivy
    # 0.76.0's golden holds two, both Pillow's from GHSA. Those are "" (F5.11).
    undated = {(v["VulnerabilityID"], v["PkgName"]) for r in raw["Results"]
               for v in r.get("Vulnerabilities") or [] if not v.get("PublishedDate")}
    for finding in dated:
        if (finding.rule, finding.dependency.package) in undated:
            assert finding.dependency.advisory_published == "", finding.rule
        else:
            assert _STAMP.fullmatch(finding.dependency.advisory_published), finding.rule
    first = next(v for r in raw["Results"] for v in r.get("Vulnerabilities") or []
                 if v.get("PublishedDate"))
    finding = next(f for f in dated if f.rule == first["VulnerabilityID"]
                   and f.dependency.package == first["PkgName"])
    assert finding.dependency.advisory_published == first["PublishedDate"][:19] + "Z"


def test_osv_scanner_s_published_date_is_carried(workspace):
    run = _scan(workspace, osv=golden("osv-scanner"))
    dated = [f for f in run.findings if f.dependency]

    assert dated
    assert all(_STAMP.fullmatch(f.dependency.advisory_published) for f in dated)


def test_where_both_scanners_report_a_finding_the_earlier_date_is_kept(workspace):
    osv = json.loads(golden("osv-scanner"))
    # Trivy's npm findings left to Trivy alone, so both kinds exist whatever the day's
    # database: OSV-Scanner 2.7.0, on 2026-10-25's data, reports everything Trivy does.
    osv["results"] = [r for r in osv["results"]
                      if not r["source"]["path"].endswith("package-lock.json")]
    for result in osv["results"]:
        for package in result.get("packages") or []:
            for vuln in package.get("vulnerabilities") or []:
                vuln["published"] = "1999-01-02T03:04:05Z"
    trivy = json.loads(golden("trivy"))
    for result in trivy["Results"]:
        for vuln in result.get("Vulnerabilities") or []:
            vuln["PublishedDate"] = "2001-01-01T00:00:00.5Z"

    run = _scan(workspace, trivy=json.dumps(trivy), osv=json.dumps(osv))
    both = [f for f in run.findings if len(f.sources) > 1]
    trivy_only = [f for f in run.findings if f.sources == ("trivy",)]

    assert both and trivy_only
    assert {f.dependency.advisory_published for f in both} == {"1999-01-02T03:04:05Z"}
    assert {f.dependency.advisory_published for f in trivy_only} == {"2001-01-01T00:00:00Z"}


def test_an_absent_or_unreadable_date_is_empty(workspace):
    trivy = json.loads(golden("trivy"))
    vulns = [v for r in trivy["Results"] for v in r.get("Vulnerabilities") or []]
    for i, vuln in enumerate(vulns):
        if i % 2:
            vuln.pop("PublishedDate", None)
        else:
            vuln["PublishedDate"] = "last Tuesday"

    run = _scan(workspace, trivy=json.dumps(trivy))

    assert {f.dependency.advisory_published for f in run.findings if f.dependency} == {""}


def test_every_fingerprint_is_the_same_with_or_without_the_dates(workspace, tmp_path):
    """ADR-0003: identity is `(ecosystem, package, version, vuln_id)`, and the date is
    not part of it. Measured before the field existed: 40 Fingerprints on Trivy
    0.75.0's golden and OSV-Scanner 2.6.0's; 75 with Trivy 0.76.0's, recaptured on
    2026-10-25's database."""
    import shutil

    other = tmp_path / "other"
    shutil.copytree(workspace, other)
    trivy, osv = golden("trivy"), golden("osv-scanner")
    undated_trivy = re.sub(r'"PublishedDate": "[^"]*",?', "", trivy)
    undated_osv = re.sub(r'"published": "[^"]*",?', "", osv)

    dated = {f.fingerprint for f in _scan(workspace, trivy=trivy, osv=osv).findings}
    undated = {f.fingerprint for f in _scan(other, trivy=undated_trivy,
                                            osv=undated_osv).findings}

    assert len(dated) == 75 and dated == undated


def test_findings_json_carries_the_field_and_stays_schema_1(workspace):
    _scan(workspace, trivy=golden("trivy"))
    document = json.loads((workspace / ".security-scan" / "findings.json").read_text())
    dependencies = [f["dependency"] for f in document["findings"] if f.get("dependency")]

    assert document["schema"] == 1
    assert dependencies and any(d["advisory_published"] for d in dependencies)
    assert all(_STAMP.fullmatch(d["advisory_published"]) or d["advisory_published"] == ""
               for d in dependencies)
