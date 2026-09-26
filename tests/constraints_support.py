"""What the Phase 11 constraint files share (28.4.3): a runner whose findings reach
the enrichment path, and the one-CVE Trivy output that makes it so.
"""

from __future__ import annotations

import json

from conftest import LegacyDispatch

from valvur.runner import ScannerOutput

# Trivy output carrying a real CVE. The CVE is the point: enrichment short-circuits
# on a finding set with none, so a stub without one tests nothing.
TRIVY_ONE_CVE = json.dumps({"Results": [{
    "Target": "requirements.txt", "Type": "pip", "Class": "lang-pkgs",
    "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2023-4863", "PkgName": "pillow",
        "InstalledVersion": "10.0.0", "FixedVersion": "10.0.1",
        "Severity": "HIGH", "Title": "heap buffer overflow in libwebp",
    }],
}]})


class CveRunner(LegacyDispatch):
    """A runner whose findings reach the enrichment path."""

    def _out(self, tool, payload=""):
        return ScannerOutput(tool=tool, version="0", stdout=payload, stderr="", exit_code=0)

    def run_trivy(self, workspace): return self._out("trivy", TRIVY_ONE_CVE)
    def run_gitleaks(self, workspace): return self._out("gitleaks", "[]")
    def run_osv(self, workspace): return self._out("osv-scanner", '{"results": []}')
    def run_checkov(self, workspace):
        return self._out("checkov", '{"results": {"failed_checks": []}}')
    def run_syft(self, workspace): return self._out("syft", "")
    def run_opengrep(self, workspace): return self._out("opengrep", '{"results": []}')

    def run_check(self, name, workspace, *, network=False):
        return self._out(name, "[]")


