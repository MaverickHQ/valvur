"""R5.2: `SUMMARY.md` leads with what matters (F7.4 to F7.7, N1.3).

The review's lab report opened with 30 lines of instructions to agents before any
finding, listed one rule eight times with titles cut mid-word, and never said
what was scanned. The order is now: the verdict, the scope manifest, what did not
run, the top groups, Hygiene, and a shortened agent block at the end, since the
MCP handshake carries the full rules before any call (28.2.2).
"""

from __future__ import annotations

from pathlib import Path

from valvur import pipeline
from valvur.adapters import DEFAULT_ADAPTERS
from valvur.api import ScanRun
from valvur.findings import Finding
from valvur.provenance import ScannerRun
from valvur.summary import render


def _run(tmp_path: Path) -> ScanRun:
    pins = [Finding(rule="unpinned-uses", path=f".github/workflows/w{i}.yml", line=9,
                    title="unpinned action reference", fingerprint=f"fp-pin-{i}",
                    severity="low", sources=("zizmor",)) for i in range(8)]
    shell = Finding(rule="valvur.python.subprocess-shell-true", path="src/app.py", line=4,
                    title="subprocess call with shell=True", fingerprint="fp-shell",
                    severity="high", sources=("opengrep",))
    ctx = pipeline.Context(workspace=tmp_path, profile="offline", network=False,
                           declaring=[a.for_profile(network=False) for a in DEFAULT_ADAPTERS])
    findings = pipeline.run([*pins, shell], ctx).findings
    return ScanRun(
        findings=findings, profile="offline",
        scanners=[ScannerRun("opengrep", True, "1.29.0", duration_s=2.1),
                  ScannerRun("zizmor", True, "1.30.1", duration_s=0.3),
                  ScannerRun("checkov", True, skipped=True,
                             reason="no infrastructure other than workflows")],
        scope={"scope": "git", "files": 304, "bytes": 4895},
        not_read=((".venv/", "ignored by git"),),
        history={"commits": 12},
    )


def test_the_order_is_verdict_scope_what_did_not_run_groups_then_the_agent_block(tmp_path):
    text = render(_run(tmp_path))

    marks = ["active finding", "## Scope", "## What did not run", "## Most urgent",
             "## For AI agents"]
    at = [text.index(m) for m in marks]
    assert at == sorted(at), dict(zip(marks, at, strict=True))
    assert text.rstrip().rsplit("\n## ", 1)[1].startswith("For AI agents"), \
        "something follows the agent block"


def test_the_eight_pin_lines_are_one_entry_with_a_count(tmp_path):
    text = render(_run(tmp_path))
    top = text.split("## Most urgent", 1)[1].split("\n## ", 1)[0]

    assert top.count("unpinned-uses") == 1
    assert "**8 ×**" in top   # noqa: RUF001 — the multiplication sign


def test_the_shortened_block_still_says_what_f7_6_requires(tmp_path):
    """F7.6 as amended: the folder, the three Status values, the ranking basis and
    the constraints of F9.5 to F9.7, at the end, in fewer lines."""
    block = render(_run(tmp_path)).rsplit("## For AI agents", 1)[1]

    for said in ("Never commit it", "Never add a suppression without asking the human",
                 "not proof it was fixed", "`findings`", "`clean`", "`inconclusive`",
                 "KEV", "EPSS", "[UNTRUSTED CONTENT", "`findings.json`"):
        assert said in block, said
    assert len(block.strip().splitlines()) <= 14
