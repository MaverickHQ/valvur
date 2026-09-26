"""`valvur --help`, and every subcommand's, byte for byte across the move of
`cli.main` into a command table (28.4.2, A3) — 27.3.3's method.

`main()` was 292 lines: nine parsers built inline, then a chain of `if
args.command == …` branches. The text argparse prints is the CLI's contract with
a person at a terminal, and these goldens were generated from `main([cmd,
"--help"])` before the move and are committed; the same calls must print the same
bytes after it.

    UPDATE_CLI_HELP_GOLDEN=1 uv run pytest tests/test_cli_help_golden.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

GOLDEN = Path(__file__).parent / "fixtures" / "cli-help"
UPDATE = "UPDATE_CLI_HELP_GOLDEN"
COMMANDS = ("", "scan", "update", "findings", "explain", "status", "doctor", "gate", "cache",
            "suppress")


def _help(command: str, capsys) -> str:
    from valvur.cli import main

    with pytest.raises(SystemExit) as stopped:
        main([*([command] if command else []), "--help"])
    assert stopped.value.code == 0
    out = capsys.readouterr().out
    # argparse wraps to the terminal's width; the goldens are what a 100-column
    # terminal sees (conftest pins COLUMNS), and the version line is normalised.
    from valvur.version import __version__

    return out.replace(__version__, "<version>")


@pytest.mark.parametrize("command", COMMANDS)
def test_the_help_text_is_what_it_was_before_the_move(command, capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "100")
    path = GOLDEN / f"{command or 'valvur'}.txt"
    rendered = _help(command, capsys)

    if os.environ.get(UPDATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        pytest.skip(f"regenerated {path.name}")

    assert path.is_file(), f"no golden for {command!r}; generate with {UPDATE}=1"
    assert rendered == path.read_text(encoding="utf-8"), (
        f"`valvur {command} --help` changed. If that is intended, regenerate with "
        f"{UPDATE}=1; if it is not, the move changed more than structure."
    )
