"""R38.2: every finding a project's own ignore would hide is reported (D77a), e2e.

The project `tests/project_ignores.py` builds carries each ignore D77 names, each
hiding one planted finding; R38.1 measured five of the seven hidden by `1.4.0`. A
scan with the image now reports every one, from the Scanner that found it.
"""

from __future__ import annotations

import pytest
from project_ignores import OSV_IGNORED, TRIVY_IGNORED, build

from valvur import engine_host, profiles
from valvur.api import scan

#: Each ignore, and the (path, rule) of the finding it would hide.
PLANTED = {
    "nosemgrep": ("app/ignored.py", "valvur.python.subprocess-shell-true"),
    "gitleaks:allow": ("secrets/allowed.py", "aws-access-token"),
    ".gitleaksignore": ("secrets/listed.py", "aws-access-token"),
    ".gitleaks.toml": ("vendored/secret.py", "aws-access-token"),
    "checkov:skip": ("infra/skipped.tf", "CKV_AWS_18"),
}


@pytest.mark.e2e
def test_every_finding_a_project_ignore_would_hide_is_reported(mountable_tmp):
    ws = build(mountable_tmp / "project")

    run = scan(ws, runner=engine_host.for_scan(), profile=profiles.OFFLINE)

    assert not run.failures, [s.reason for s in run.failures]
    found = {(f.path, f.rule): f for f in run.findings}
    missing = {name: where for name, where in PLANTED.items() if where not in found}
    assert missing == {}, f"still hidden: {missing}"
    by_cve = {f.rule: set(f.sources) for f in run.findings if f.rule.startswith("CVE-")}
    assert "trivy" in by_cve["CVE-2019-11324"], f".trivyignore still hid {TRIVY_IGNORED}"
    assert "osv-scanner" in by_cve["CVE-2019-11236"], f"osv-scanner.toml still hid {OSV_IGNORED}"
