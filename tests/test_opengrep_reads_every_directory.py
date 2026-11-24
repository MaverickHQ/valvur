"""R53.3: Opengrep reads every directory of the File Set, through the Scan Container.

Left to itself Opengrep skips `tests/`, `test/`, `build/`, `dist/` and `vendor/`.
valvur turns that list off with an ignore file that ignores nothing, since the File Set
decides what a scan reads (ADR-0021). 1.31.0 read that file from where it started and
2.0.0 reads it from the root it scans: measured on 2026-11-24, with the file in the first
place alone, a flaw in each of those directories went unreported and the Score rose. This
is the test that would have said so in one line.
"""

from __future__ import annotations

import pytest

FLAW = "def run(expression):\n    return eval(expression)\n"
#: `node_modules/` is not here: the File Set's own walk leaves it out (`fileset.py`), so
#: it never reaches Opengrep, which is valvur's decision and not the Scanner's.
DIRECTORIES = ("app", "tests", "test", "build", "dist", "vendor")


@pytest.mark.e2e
def test_a_flaw_in_each_directory_opengrep_would_skip_is_reported(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    for directory in DIRECTORIES:
        (ws / directory).mkdir(parents=True)
        (ws / directory / "flaw.py").write_text(FLAW)
    # The project's own ignore file asks for less to be read. It is not asked.
    (ws / ".semgrepignore").write_text("app/\n")

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    reported = sorted(f.path for f in run.findings if f.rule == "valvur.python.dangerous-eval")
    assert reported == sorted(f"{directory}/flaw.py" for directory in DIRECTORIES)
    assert (ws / ".semgrepignore").read_text() == "app/\n", "the project's file is as it was"
