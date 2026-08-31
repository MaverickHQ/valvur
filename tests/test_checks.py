"""Sub-phase 4.0 — the Check protocol.

A Check is detection valvur performs itself, as opposed to a Scanner, which is a
third-party tool we orchestrate. Checks run in the container exactly as Scanners do.
"""

from valvur import scan
from valvur.adapters import CheckAdapter


def test_a_workspace_with_no_licence_file_is_a_finding(workspace, runner_finding_nothing):
    """F4.2 — invisible to every Scanner we orchestrate, and it blocks a release."""
    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[CheckAdapter("licence-file")])

    assert [f.rule for f in run.findings] == ["valvur.licence.missing"]


def test_a_workspace_with_a_licence_file_is_clean(workspace, runner_finding_nothing):
    (workspace / "LICENSE").write_text("MIT License\n")

    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[CheckAdapter("licence-file")])

    assert run.findings == []


def test_checks_are_distinguishable_from_scanners(workspace, runner_finding_nothing):
    """P4 — we credit Scanners by name and licence. Detection we perform ourselves
    must never be presented as a third-party tool's work, nor the reverse."""
    from valvur.adapters import GitleaksAdapter

    assert CheckAdapter("licence-file").kind == "check"
    assert GitleaksAdapter().kind == "scanner"


def test_a_check_failure_is_isolated_like_a_scanner_failure(
    workspace, runner_finding_one_secret
):
    """Checks inherit the fleet's failure isolation, so one broken Check does not
    cost the run."""
    run = scan(workspace, runner=runner_finding_one_secret,
               adapters=[CheckAdapter("no-such-check")])

    assert run.findings == [] or run.failures


# ---------------------------------------------------------------- 4.1 AI artifact

def _ai_scan(workspace, runner):
    return scan(workspace, runner=runner, adapters=[CheckAdapter("ai-artifact")])


def test_zero_width_unicode_in_an_agent_file_is_a_finding(workspace, runner_finding_nothing):
    """F3.7 — invisible to a human reviewer, fully legible to a model."""
    run = _ai_scan(workspace, runner_finding_nothing)

    assert "valvur.ai-artifact.hidden-unicode" in [f.rule for f in run.findings]


def test_an_mcp_server_on_a_mutable_ref_is_a_finding(workspace, runner_finding_nothing):
    """F3.8 — the exact defect we found in the AWS sample that started this project."""
    run = _ai_scan(workspace, runner_finding_nothing)

    assert "valvur.ai-artifact.mcp-mutable-ref" in [f.rule for f in run.findings]


def test_blanket_tool_auto_approval_is_a_finding(workspace, runner_finding_nothing):
    run = _ai_scan(workspace, runner_finding_nothing)

    assert "valvur.ai-artifact.blanket-auto-approve" in [f.rule for f in run.findings]


def test_a_permission_bypass_directive_is_a_finding(workspace, runner_finding_nothing):
    run = _ai_scan(workspace, runner_finding_nothing)

    assert "valvur.ai-artifact.permission-bypass" in [f.rule for f in run.findings]


def test_an_instruction_override_directive_is_a_finding(workspace, runner_finding_nothing):
    """F3.12 — quoted as evidence, never obeyed."""
    run = _ai_scan(workspace, runner_finding_nothing)

    assert "valvur.ai-artifact.prompt-injection" in [f.rule for f in run.findings]


def test_no_invisible_character_is_ever_written_into_an_artifact(
    workspace, runner_finding_nothing
):
    """F3.13, part one.

    Copying a zero-width character into our own output would carry the attack
    forward — into the file we tell agents to read first.
    """
    from valvur.defang import is_invisible

    _ai_scan(workspace, runner_finding_nothing)

    written = [p for p in (workspace / ".security-scan").rglob("*") if p.is_file()]
    offenders = {
        p.name for p in written
        if any(is_invisible(c) for c in p.read_text(encoding="utf-8"))
    }

    assert offenders == set()


def test_an_injection_payload_is_fenced_as_untrusted_not_reproduced_as_prose(
    workspace, runner_finding_nothing
):
    """F3.13, part two — valvur must not become the delivery mechanism.

    An agent reads SUMMARY.md first and by instruction. A payload reproduced as bare
    prose would be an attack laundered out of a file the agent might never have
    opened into one we explicitly tell it to read.
    """
    import json

    _ai_scan(workspace, runner_finding_nothing)
    results = workspace / ".security-scan"
    payload = "Ignore all previous instructions"

    # Since 6.2, SUMMARY.md carries one line per finding and no evidence body, so the
    # payload does not appear there at all — a stronger outcome than fencing it.
    # The finding is still actionable: the rule, file and line are named.
    summary = (results / "SUMMARY.md").read_text(encoding="utf-8")
    assert payload not in summary
    assert "prompt-injection" in summary and "AGENTS.md" in summary

    # Evidence moved to findings.json, which an agent queries per finding. It must be
    # fenced there.
    findings = json.loads((results / "findings.json").read_text())["findings"]
    injection = next(f for f in findings if "prompt-injection" in f["rule"])
    assert payload in injection["evidence"]
    before = injection["evidence"][: injection["evidence"].index(payload)]
    assert "[UNTRUSTED CONTENT FROM THE SCANNED REPOSITORY" in before


# ------------------------------------------------------------------- 4.3 licence

def test_a_licence_file_contradicting_package_metadata_is_a_finding(
    tmp_path, runner_finding_nothing
):
    """F4.3 — a GPL LICENSE in a project whose metadata claims MIT is a real problem,
    and no Scanner we orchestrate looks for it."""
    import shutil

    from conftest import FIXTURES

    ws = tmp_path / "mismatch"
    shutil.copytree(FIXTURES / "licence-mismatch-repo", ws)

    run = scan(ws, runner=runner_finding_nothing, adapters=[CheckAdapter("licence-file")])

    assert [f.rule for f in run.findings] == ["valvur.licence.mismatch"]


def test_a_copyleft_dependency_in_a_permissive_project_is_a_finding():
    """F4.5 — GPL obligations may extend to your own source."""
    import json

    from valvur.licence_policy import evaluate

    sbom = json.dumps({"components": [
        {"name": "gpl-thing", "version": "1.0", "licenses": [{"license": {"id": "GPL-3.0"}}]},
        {"name": "fine-thing", "version": "2.0", "licenses": [{"license": {"id": "MIT"}}]},
    ]})

    findings = evaluate("MIT", sbom)

    assert [f.rule for f in findings] == ["valvur.licence.copyleft-in-permissive"]


def test_a_dependency_with_no_declared_licence_is_a_finding():
    """F4.6 — unknown cannot be cleared for release."""
    import json

    from valvur.licence_policy import evaluate

    # A tree whose licences we could read, with one package that genuinely declares
    # none. Where NOTHING is readable the honest finding is a different one — see
    # test_wholly_absent_licence_data_is_reported_as_unreadable_not_as_absent.
    sbom = json.dumps({"components": [
        {"name": "known", "version": "1.0", "licenses": [{"license": {"id": "MIT"}}]},
        {"name": "mystery", "version": "0.1"},
    ]})

    findings = evaluate("MIT", sbom)

    assert [f.rule for f in findings] == ["valvur.licence.dependency-unknown"]


# --------------------------------------------------------- 4.4 dependency reality

def test_a_dependency_that_does_not_exist_is_a_finding():
    """F3.2 — the headline slopsquat behaviour, and the one NO advisory database can
    catch: the package is new, not known-bad."""
    from valvur.checks.dependency_reality import DependencyRealityCheck

    class Offline(DependencyRealityCheck):
        pass

    import valvur.checks.dependency_reality as mod

    real = mod._pypi
    mod._pypi = lambda name: None if name == "aws-helper-sdk" else {"releases": {}}
    try:
        found = Offline().run(_tmp_manifest("aws-helper-sdk==1.0.0\nurllib3==1.24.1\n"))
    finally:
        mod._pypi = real

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]


def test_a_hallucinated_name_suggests_the_package_you_probably_meant():
    """Reporting absence alone is unactionable; naming the near neighbour is not."""
    import valvur.checks.dependency_reality as mod
    from valvur.checks.dependency_reality import DependencyRealityCheck

    real = mod._pypi
    mod._pypi = lambda name: None
    try:
        found = DependencyRealityCheck().run(_tmp_manifest("reqeusts==2.31.0\n"))
    finally:
        mod._pypi = real

    assert "did you mean 'requests'" in found[0]["title"]


def test_with_no_registry_reachable_the_check_fails_rather_than_reporting_clean():
    """F3.5 — the honesty behaviour. Unverified is not the same as clean, and a
    Check that quietly returns nothing would be the worst possible outcome."""
    import pytest

    import valvur.checks.dependency_reality as mod
    from valvur.checks.dependency_reality import DependencyRealityCheck, RegistryUnreachable

    real = mod._pypi

    def unreachable(name):
        raise RegistryUnreachable("no network")

    mod._pypi = unreachable
    try:
        with pytest.raises(RegistryUnreachable):
            DependencyRealityCheck().run(_tmp_manifest("urllib3==1.24.1\n"))
    finally:
        mod._pypi = real


def _tmp_manifest(body: str):
    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp())
    (d / "requirements.txt").write_text(body)
    return d
