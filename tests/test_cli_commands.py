"""`cli.main` is a table (28.4.2, A3): one command, one function.

`main()` was 292 lines — nine parsers built inline, then an `if args.command ==`
chain — and the only way to find `doctor`'s behaviour was to read past
`update`'s. `build_parser` builds the parsers (`tests/test_cli_help_golden.py`
holds their text byte for byte), `COMMANDS` names a function per command, and
`main` is the two lines between them. This holds the table to the parser.
"""

from __future__ import annotations

import inspect

from valvur import cli


def _subcommands() -> set[str]:
    parser = cli.build_parser()
    [action] = [a for a in parser._actions if hasattr(a, "choices") and a.choices
                and not isinstance(a.choices, list | tuple)]
    return set(action.choices)


def test_every_subcommand_has_exactly_one_function_and_no_function_lacks_a_command():
    assert set(cli.COMMANDS) == _subcommands()
    for name, handler in cli.COMMANDS.items():
        assert callable(handler) and handler.__name__.startswith("_cmd_"), name


def test_main_only_parses_and_dispatches():
    source = inspect.getsource(cli.main)
    body = [line for line in source.splitlines()[1:]
            if line.strip() and not line.strip().startswith("#")]
    assert len(body) == 2, source
    assert "build_parser()" in body[0] and "COMMANDS[args.command]" in body[1]
