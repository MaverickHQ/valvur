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
    _ai_scan(workspace, runner_finding_nothing)

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text(encoding="utf-8")
    payload = "Ignore all previous instructions"

    assert payload in summary, "the finding should still be actionable"
    before = summary[: summary.index(payload)]
    assert "[UNTRUSTED CONTENT FROM THE SCANNED REPOSITORY" in before
