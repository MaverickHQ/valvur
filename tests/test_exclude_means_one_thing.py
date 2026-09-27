"""R1.3: an exclude means the same to every Scanner (F2.1; the review's N1).

`[scan] exclude = ["archive"]` meant the top-level `archive/` to Gitleaks, Trivy and
Syft, and every directory named `archive` to Opengrep, Checkov and OSV-Scanner:
measured 2026-09-27, a flow planted in `src/archive/` went unreported. Measured
inside the image the same day: Opengrep anchors on the container path
(`--exclude=/workspace/archive`), Checkov on the container path as a regular
expression, and OSV-Scanner has no anchored form, so it is given no exclude for a
configured prefix and its findings are filtered afterwards.
"""

from __future__ import annotations

import pytest

PLANTED = {
    "app.py": "import subprocess\nsubprocess.call(input(), shell=True)\n",
    "Dockerfile": "FROM python:3.9\nRUN pip install flask\n",
}
#: A different vulnerable package per directory: a dependency Finding's identity
#: carries no path (ADR-0003), so one package in three places is one Finding.
REQUIREMENTS = {"archive": "requests==2.19.0\n", "src/archive": "urllib3==1.24.1\n",
                "src/app": "jinja2==2.10\n"}


def _planted(root):
    for directory in ("archive", "src/archive", "src/app"):
        for name, text in {**PLANTED, "requirements.txt": REQUIREMENTS[directory]}.items():
            path = root / directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    (root / ".security-scan.toml").write_text('[scan]\nexclude = ["archive"]\n')
    return root


@pytest.mark.e2e
def test_every_scanner_reads_a_nested_directory_that_shares_an_excluded_name(mountable_tmp):
    from valvur import api
    from valvur.runner import ContainerRunner

    workspace = _planted(mountable_tmp / "ws")
    run = api.scan(workspace, runner=ContainerRunner(), profile="full")

    by_source: dict[str, set[str]] = {}
    for finding in run.findings:
        for source in finding.sources:
            by_source.setdefault(source, set()).add(finding.path)
    assert not run.failures, run.failures
    for scanner, planted in (("opengrep", "src/archive/app.py"),
                             ("checkov", "src/archive/Dockerfile"),
                             ("trivy", "src/archive/requirements.txt"),
                             ("osv-scanner", "src/archive/requirements.txt")):
        assert planted in by_source.get(scanner, set()), (scanner, by_source.get(scanner))
    assert not any(p.startswith("archive/") for paths in by_source.values() for p in paths)
