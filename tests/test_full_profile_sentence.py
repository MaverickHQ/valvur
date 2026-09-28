"""R7.1: what `full` adds, said once (P6).

Since R4.6 OSV-Scanner runs on `offline` from its offline database, and the
dependency-reality Check has run on both Profiles since ADR-0018; the CLI's help and
the `scan` tool still said `full` adds them. What `full` adds is questions, not
Scanners: one sentence in `profiles`, which both surfaces give.
"""

from __future__ import annotations

from valvur import profiles


def test_full_adds_no_scanner_and_is_described_by_one_sentence(capsys):
    import pytest

    from valvur import cli
    from valvur.mcp.tools import registry

    assert set(profiles.SCANNERS[profiles.FULL]) == set(profiles.SCANNERS[profiles.OFFLINE])
    for name in profiles.SCANNERS[profiles.OFFLINE]:
        assert name not in profiles.FULL_ADDS, name

    scan = next(t for t in registry() if t.name == "scan")
    assert profiles.FULL_ADDS in scan.schema["properties"]["profile"]["description"]
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    assert " ".join(profiles.FULL_ADDS.split()) in " ".join(capsys.readouterr().out.split())
