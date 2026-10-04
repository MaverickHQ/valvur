"""R21.4: a lookup the human can run, where valvur holds no answer offline (D59c).

Pinning an action to a commit needs the commit its tag points at today, which only
the network knows. So `REMEDIATION.md` gives each `unpinned-uses` finding the exact
command that asks, and the `uses:` line to write with its answer, the tag kept as a
comment. valvur runs neither: the human does, and decides.
"""

from __future__ import annotations

from pathlib import Path

from valvur import remediation
from valvur.findings import Finding, Severity


def _pin(evidence: str, n: int = 0) -> Finding:
    return Finding(rule="unpinned-uses", path=".github/workflows/ci.yml", line=10 + n,
                   title="unpinned action reference", fingerprint=f"fp-pin-{n}",
                   severity=Severity.LOW, evidence=evidence, sources=("zizmor",), rank=1 + n)


def test_each_unpinned_action_gets_its_lookup_and_the_line_to_write():
    text = remediation.render([_pin("      - uses: actions/checkout@v4"),
                               _pin("      - uses: github/codeql-action/init@v3", 1)])

    assert "`gh api repos/actions/checkout/commits/v4 --jq .sha`" in text
    assert "`uses: actions/checkout@<sha> # v4`" in text
    assert "`gh api repos/github/codeql-action/commits/v3 --jq .sha`" in text
    assert "`uses: github/codeql-action/init@<sha> # v3`" in text


def test_evidence_without_an_action_reference_gets_no_invented_command():
    text = remediation.render([_pin("[UNTRUSTED CONTENT] something else")])

    assert "gh api" not in text


def test_valvur_runs_none_of_them():
    source = Path(remediation.__file__).read_text()

    assert "subprocess" not in source and "urllib" not in source
