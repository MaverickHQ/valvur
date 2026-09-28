"""R4.2: zizmor audits GitHub Actions workflows (F3.11; D8, ADR-0023).

R4.1 measured it against what valvur reported before: every unpinned action (85 of 85)
and every write permission Checkov found (18 of 18), with `--persona pedantic
--min-severity medium`, offline. The golden fixture is its report on a planted
workflow with one of each of the three classes the task names.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import golden

from valvur.findings import Severity
from valvur.invocation import ScannerOutput

FIXTURE = Path(__file__).parent / "fixtures" / "workflows-repo"


def _adapter():
    from valvur.adapters import ZizmorAdapter

    return ZizmorAdapter()


def test_zizmor_runs_offline_at_the_measured_persona_with_no_exit_codes():
    invocation = _adapter().command(FIXTURE)
    assert invocation.argv == (
        "zizmor", "--offline", "--persona", "pedantic", "--min-severity", "medium",
        "--format", "json", "--no-progress", "--no-exit-codes", "/workspace")
    assert invocation.network is False and invocation.report is None


def test_each_planted_class_is_one_finding_at_its_line():
    output = ScannerOutput("zizmor", "1.30.1", golden("zizmor"), "", 0)
    found = {f.rule: f for f in _adapter().parse(output)}
    assert sorted(found) == ["excessive-permissions", "template-injection", "unpinned-uses"]
    assert {r: f.line for r, f in found.items()} == {
        "excessive-permissions": 7, "unpinned-uses": 12, "template-injection": 15}
    for finding in found.values():
        assert finding.path == ".github/workflows/planted.yml"
        assert finding.severity is Severity.HIGH
        assert finding.sources == ("zizmor",)
    assert found["excessive-permissions"].evidence == "permissions: write-all"
    assert "write-all" in found["excessive-permissions"].title
    assert len({f.fingerprint for f in found.values()}) == 3


def test_the_fingerprint_survives_the_line_moving():
    """Per-class identity (ADR-0003): a workflow finding is SAST-shaped, keyed on the
    offending text, never on its line."""
    text = golden("zizmor").replace('"row": 6', '"row": 40')
    before = _adapter().parse(ScannerOutput("zizmor", "1.30.1", golden("zizmor"), "", 0))
    after = _adapter().parse(ScannerOutput("zizmor", "1.30.1", text, "", 0))
    assert {f.fingerprint for f in before} == {f.fingerprint for f in after}


def test_zizmor_runs_on_every_profile_where_there_is_a_workflow(tmp_path):
    from valvur import profiles
    from valvur.adapters import DEFAULT_ADAPTERS

    for profile in (profiles.OFFLINE, profiles.FULL):
        assert "zizmor" in [a.name for a in profiles.select(DEFAULT_ADAPTERS, profile)]
    assert _adapter().applies_to(FIXTURE)[0] is True
    skipped, why = _adapter().applies_to(tmp_path)
    assert skipped is False and "workflow" in why


def test_the_image_installs_the_adapters_zizmor_by_hash_for_both_architectures():
    """Pinned by hash like Checkov (23.4.1): the musl wheels for x86_64 and
    aarch64, from a lock the tree hash covers, installed with `--require-hashes`."""
    import re

    from valvur.adapters.zizmor import VERSION

    root = Path(__file__).parent.parent
    lock = (root / "requirements-zizmor.txt").read_text()
    assert f"zizmor=={VERSION}" in lock
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", lock)) == 2
    dockerfile = (root / "Dockerfile").read_text()
    assert "requirements-zizmor.txt" in dockerfile and "--require-hashes" in dockerfile
    assert "ln -s /opt/zizmor/bin/zizmor /usr/local/bin/zizmor" in dockerfile


def test_the_tree_hash_covers_the_zizmor_lock(tmp_path):
    from valvur import tree_hash

    repo = Path(__file__).parent.parent
    assert "zizmor-lock" in tree_hash.tree_parts(repo)


@pytest.mark.e2e
def test_a_real_scan_reports_each_planted_problem_once_and_ranked(mountable_tmp):
    import shutil

    from valvur import api, engine_host
    from valvur.adapters import ZizmorAdapter

    ws = mountable_tmp / "workflows"
    shutil.copytree(FIXTURE, ws)
    run = api.scan(ws, runner=engine_host.for_scan(), adapters=[ZizmorAdapter()])

    assert all(s.ok for s in run.scanners), run.scanners
    assert sorted(f.rule for f in run.findings) == [
        "excessive-permissions", "template-injection", "unpinned-uses"]
    assert all(f.rank > 0 for f in run.findings)
