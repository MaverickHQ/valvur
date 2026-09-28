"""The owner's decision, 2026-09-28: a correct report names each finding by its rule
ID and its path, as the acceptance set's scorer demands.

Every agent answer that missed since R6 was right in substance and described a
finding without one of the two: a CVE without `requirements.txt`, two Checkov rules
without their IDs, a malicious package "in the lockfile". The rule reaches the agent
twice, in the same words: in the handshake's instructions and at the end of
`SUMMARY.md`.
"""

from __future__ import annotations

from valvur.api import ScanRun


def test_the_agent_is_told_to_name_the_rule_and_the_path_on_both_surfaces():
    from valvur import summary
    from valvur.mcp.tools import instructions

    rule = summary.REPORT_RULE
    assert "rule ID" in rule and "path" in rule

    assert " ".join(rule.split()) in " ".join(instructions().split())
    block = summary.render(ScanRun()).rsplit("## For AI agents", 1)[1]
    assert " ".join(rule.split()) in " ".join(block.replace("> ", " ").split())
