"""R20.5: non-security hashing draws no `weak-hash` (D47c).

`weak-hash` was 4 of the corpus's 26 false alarms (R20.1), and Python 3.9 gave the
code a way to say so: `usedforsecurity=False`, written at the call, is the project
stating the hash is a cache key or a content id. That call is not reported; the
same call without it still is.
"""

from __future__ import annotations

import pytest


@pytest.mark.e2e
def test_usedforsecurity_false_draws_no_weak_hash_and_a_plain_call_still_does(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    ws.mkdir()
    (ws / "cache_key.py").write_text(
        "import hashlib\n\n"
        "def key(data):\n"
        "    return hashlib.md5(data, usedforsecurity=False).hexdigest()\n\n"
        "def digest(data):\n"
        "    return hashlib.sha1(data, usedforsecurity=False).hexdigest()\n")
    (ws / "password.py").write_text(
        "import hashlib\n\n"
        "def stored(password):\n"
        "    return hashlib.md5(password).hexdigest()\n")

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    assert [f.path for f in run.findings if f.rule == "valvur.python.weak-hash"] == [
        "password.py"]
