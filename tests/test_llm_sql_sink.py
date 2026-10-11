"""R41.4 (D80c): the SQL rule reports a query the model wrote, not a value it chose.

Track 9 showed `valvur.llm.output-to-sql` flagging all eight of its fixes, each binding
the model's text as a parameter: `cur.execute("... WHERE title = ?", (text,))`. That is
the safe form, and the rule's sink matched any argument of `execute`. The sink is now
the query alone.
"""

from __future__ import annotations

import pytest

HEAD = """import sqlite3

from openai import OpenAI

client = OpenAI()


def run(prompt):
    cur = sqlite3.connect("notes.db").cursor()
    reply = client.chat.completions.create(model="m", messages=[{"role": "user", "content": prompt}])
    text = reply.choices[0].message.content
"""
CASES = {
    "query.py": (True, "    return cur.execute(text).fetchall()\n"),
    "script.py": (True, "    cur.executescript(text)\n"),
    "formatted.py": (True, '    return cur.execute(f"SELECT * FROM notes WHERE {text}").fetchall()\n'),
    "bound.py": (False, '    return cur.execute("SELECT id FROM notes WHERE title = ?", (text,)).fetchall()\n'),
    "bound_many.py": (False, '    cur.executemany("INSERT INTO notes (title) VALUES (?)", [(text,)])\n'),
}


@pytest.mark.e2e
def test_the_model_writing_the_query_is_reported_and_a_bound_value_is_not(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    ws.mkdir()
    for name, (_, line) in CASES.items():
        (ws / name).write_text(HEAD + line)

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    reported = {f.path for f in run.findings if f.rule == "valvur.llm.output-to-sql"}
    assert reported == {name for name, (vulnerable, _) in CASES.items() if vulnerable}
