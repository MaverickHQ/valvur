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


# ------------------------------------------- behaviour 2: never cut mid-word

#: A title whose one long word straddles every limit a surface cuts at: 100
#: (`REMEDIATION.md`, the suppression snippet), 110 (`SUMMARY.md`) and 120 (SARIF).
WORD = "Straddlingwordthatcrossesthelimit"
LONG = ("An advisory whose title runs long enough to be cut on every bounded surface, "
        "and then last, " + WORD + " follows, and more words after it.")


def _long(i: int = 0, path: str = "src/app.py") -> Finding:
    return Finding(rule="valvur.test.long", path=path, line=3 + i, title=LONG,
                   fingerprint=f"fp-long-{i}", severity="high", sources=("opengrep",))


def _whole_or_absent(text: str) -> bool:
    return WORD in text or WORD[:7] not in text


def test_no_title_is_cut_mid_word_on_any_surface(tmp_path, capsys):
    import argparse
    import json

    from valvur import artifacts, cli, remediation

    # Every limit falls at least seven letters into the word.
    assert LONG.index(WORD) + 7 <= 100 and LONG.index(WORD) + len(WORD) > 120
    ctx = pipeline.Context(workspace=tmp_path, profile="offline", network=False,
                           declaring=[a.for_profile(network=False) for a in DEFAULT_ADAPTERS])
    single = pipeline.run([_long()], ctx).findings
    grouped = pipeline.run([_long(i) for i in range(3)], ctx).findings

    surfaces = {
        "SUMMARY.md, one": render(ScanRun(findings=single)),
        "SUMMARY.md, a group": render(ScanRun(findings=grouped)),
        "REMEDIATION.md": remediation.render(single),
        "results.sarif": json.loads(artifacts.sarif(single, version="0"))
                         ["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"],
    }
    results = tmp_path / ".security-scan"
    results.mkdir()
    (results / "findings.json").write_text(artifacts.findings_json(
        single, status="findings", complete=True))
    cli._print_suppression(argparse.Namespace(path=str(tmp_path), days=30, reason="r",
                                              fingerprint=single[0].fingerprint))
    surfaces["the suppression snippet"] = capsys.readouterr().out

    halved = [name for name, text in surfaces.items() if not _whole_or_absent(text)]
    assert halved == [], f"a title was cut mid-word in: {halved}"


def test_a_flood_ranked_below_the_top_entries_is_still_named(tmp_path):
    """Ranked last, a flood never reaches the top fifteen, and the reader would
    learn of thousands of findings only as "further findings omitted"."""
    distinct = [Finding(rule=f"valvur.test.r{i:02}", path="src/app.py", line=i + 1,
                        title=f"distinct {i}", fingerprint=f"fp-d{i}", severity="high",
                        sources=("opengrep",)) for i in range(20)]
    flood = [Finding(rule="generic-api-key", path=f"data/b/{i:05}.json", line=1,
                     title="Detected a Generic API Key", fingerprint=f"fp-f{i}",
                     severity="high", sources=("gitleaks",)) for i in range(300)]
    ctx = pipeline.Context(workspace=tmp_path, profile="offline", network=False,
                           declaring=[a.for_profile(network=False) for a in DEFAULT_ADAPTERS])
    text = render(ScanRun(findings=pipeline.run([*distinct, *flood], ctx).findings))
    top = text.split("## Most urgent", 1)[1].split("\n## ", 1)[0]

    assert "**300 ×** generic-api-key in `data/`" in top   # noqa: RUF001 — the multiplication sign
    assert "possibly machine-written data" in top
