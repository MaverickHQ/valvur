"""R6.5: seven CLI commands (D12; F9.3).

Nine commands became seven: `findings` absorbs `explain`, and `doctor` and
`update --prune`/`--clear` absorb `cache`. The old names work for one release and
say what replaced them, on stderr, so a script that pipes stdout still reads what
it did.
"""

from __future__ import annotations

import pytest
from test_findings_tool import scanned  # noqa: F401 — the fixture, shared

from valvur import cli

SEVEN = ["scan", "update", "findings", "status", "doctor", "gate", "suppress"]


def test_findings_takes_the_filters_and_a_fingerprint(scanned, capsys):  # noqa: F811
    assert cli.main(["findings", str(scanned), "--fingerprint", "fp-shell"]) == 0
    detail = capsys.readouterr().out
    assert cli.main(["findings", str(scanned), "--rule", "aws-access-token"]) == 0
    by_rule = capsys.readouterr().out
    assert cli.main(["findings", str(scanned), "--group", "unpinned-uses in .github/"]) == 0
    by_group = capsys.readouterr().out
    assert cli.main(["findings", str(scanned), "--path", "src"]) == 0
    by_path = capsys.readouterr().out

    assert "reported by: opengrep" in detail and "Evidence:" in detail
    assert "1 finding(s)" in by_rule and "config.py" in by_rule
    assert "3 finding(s)" in by_group
    assert "1 finding(s)" in by_path and "src/app/run.py" in by_path


def test_explain_still_works_and_says_what_replaced_it(scanned, capsys):  # noqa: F811
    assert cli.main(["explain", "fp-shell", str(scanned)]) == 0
    said = capsys.readouterr()

    assert "reported by: opengrep" in said.out
    assert "`valvur findings --fingerprint fp-shell`" in said.err


def test_cache_still_works_and_says_what_replaced_it(tmp_path, monkeypatch, capsys):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    assert cli.main(["cache"]) == 0
    said = capsys.readouterr()

    assert "cache:" in said.out
    assert "`valvur doctor`" in said.err and "`valvur update --prune`" in said.err


@pytest.mark.parametrize("flag", ["--clear", "--prune"])
def test_update_prunes_and_clears_without_fetching(tmp_path, monkeypatch, capsys, flag):
    from valvur import cache

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    cleared, pruned = [], []
    monkeypatch.setattr(cache, "clear", lambda: cleared.append(1) or [])
    monkeypatch.setattr(cli, "_prune_cache", lambda c: pruned.append(1))
    monkeypatch.setattr(cli, "_ensure_image_for_update",
                        lambda runner: pytest.fail("update fetched instead of tidying"))

    assert cli.main(["update", flag]) == 0

    assert (cleared, pruned) == (([1], []) if flag == "--clear" else ([], [1]))


def test_doctor_shows_the_caches_sizes(tmp_path, monkeypatch):
    from valvur import cache, doctor

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    (tmp_path / "cache").mkdir()

    [line] = [c for c in doctor.run(tmp_path) if c.name == "cache"]

    assert str(tmp_path / "cache") in line.detail and "total" in line.detail
    assert "valvur update --prune" in line.detail


def test_the_help_offers_seven_commands_and_init(capsys):
    """D12's seven, and D10's `init` (R6.8), which prints and never writes."""
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    usage = capsys.readouterr().out

    assert "{" + ",".join([*SEVEN, "init"]) + "}" in usage
