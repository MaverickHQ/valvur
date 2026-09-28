"""R6.5: one `findings` tool (D12; F9.1, F9.3, F9.8).

`list_findings` and `explain_finding` were two tools an agent had to chain; the
review counted the turns. One tool filters by fingerprint, group, rule and path,
and with a fingerprint answers in full; it says when it clamped the limit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from valvur import artifacts, pipeline
from valvur.adapters import DEFAULT_ADAPTERS
from valvur.findings import Finding
from valvur.operations import MAX_LIMIT, findings_reply


@pytest.fixture
def scanned(tmp_path) -> Path:
    def f(rule, path, fp, severity="high", line=3):
        return Finding(rule=rule, path=path, line=line, title=f"{rule} in {path}",
                       fingerprint=fp, severity=severity, sources=("opengrep",),
                       evidence="subprocess.run(cmd, shell=True)")
    found = [f("valvur.python.subprocess-shell-true", "src/app/run.py", "fp-shell"),
             f("aws-access-token", "config.py", "fp-key", "critical"),
             *[f("unpinned-uses", f".github/workflows/w{i}.yml", f"fp-pin-{i}", "low")
               for i in range(3)]]
    ctx = pipeline.Context(workspace=tmp_path, profile="offline", network=False,
                           declaring=[a.for_profile(network=False) for a in DEFAULT_ADAPTERS])
    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "findings.json").write_text(artifacts.findings_json(
        pipeline.run(found, ctx).findings, status="findings", complete=True))
    return tmp_path


def _ask(workspace: Path, **filters) -> tuple[str, dict]:
    return findings_reply({"workspace": str(workspace), **filters})


def test_it_filters_by_rule_group_and_path(scanned):
    _, by_rule = _ask(scanned, rule="aws-access-token")
    _, by_group = _ask(scanned, group="unpinned-uses in .github/")
    _, by_path = _ask(scanned, path="src/")

    assert [f["fingerprint"] for f in by_rule["findings"]] == ["fp-key"]
    assert sorted(f["fingerprint"] for f in by_group["findings"]) == [
        "fp-pin-0", "fp-pin-1", "fp-pin-2"]
    assert [f["fingerprint"] for f in by_path["findings"]] == ["fp-shell"]
    assert by_path["filters"] == {"path": "src/"}


def test_a_fingerprint_answers_in_full(scanned):
    text, fields = _ask(scanned, fingerprint="fp-shell")

    [finding] = fields["findings"]
    assert finding["fingerprint"] == "fp-shell"
    assert fields["detail"]["sources"] == ["opengrep"]
    assert "reported by: opengrep" in text and "Evidence:" in text


def test_it_says_when_it_clamped_the_limit(scanned):
    text, fields = _ask(scanned, limit=MAX_LIMIT + 50)

    assert fields["clamped"] is True and fields["limit"] == MAX_LIMIT
    assert f"clamped to {MAX_LIMIT}" in text
    _, unclamped = _ask(scanned, limit=2)
    assert unclamped["clamped"] is False and unclamped["omitted"] == 3


def test_the_mcp_tool_is_findings(scanned):
    from valvur.mcp.tools import registry

    tools = {tool.name: tool for tool in registry()}

    assert tools["findings"].handler is findings_reply
    assert set(tools["findings"].schema["properties"]) >= {
        "workspace", "fingerprint", "group", "rule", "path", "status", "limit"}
