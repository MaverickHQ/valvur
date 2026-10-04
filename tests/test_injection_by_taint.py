"""R25.2: command and code injection tell safe from unsafe (D60).

The pattern rule flagged every `subprocess(..., shell=True)` in the OWASP Benchmark,
the 7 safe cases with the 13 unsafe, so its category scored below zero; the `eval`
and `exec` sinks flagged all 33 safe code-injection cases (R25.1). Taint rules report
the flow instead: request data reaching a shell, `eval` or `exec` fires, and a
constant, or a value quoted for the shell or checked to be one string literal on
the way, draws nothing. The sinks themselves stay in the inventory.
"""

from __future__ import annotations

import pytest

APP = '''\
import shlex
import subprocess
from flask import request

def unsafe_shell():
    name = request.args.get("name")
    subprocess.run(f"echo {name}", shell=True)

def unsafe_list():
    name = request.form.get("name")
    args = ["sh", "-c"]
    args.append(f"echo {name}")
    subprocess.run(args)

def unsafe_eval():
    expression = request.args.get("expression")
    return eval(expression)

def unsafe_exec():
    code = request.cookies.get("code")
    exec(code)

def safe_constant():
    name = request.args.get("name")
    name = "world"
    subprocess.run(f"echo {name}", shell=True)

def safe_quoted():
    name = shlex.quote(request.args.get("name"))
    subprocess.run(f"echo {name}", shell=True)

def safe_literal():
    code = request.args.get("code")
    if not code.startswith("'") or not code.endswith("'"):
        return "not a literal"
    exec(code)
'''


@pytest.mark.e2e
def test_a_flow_from_the_request_fires_and_a_constant_or_sanitised_value_does_not(
        mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    ws.mkdir()
    (ws / "app.py").write_text(APP)
    lines = APP.splitlines()

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    def where(rule: str) -> list[str]:
        """The function each finding of `rule` sits in."""
        found = []
        for f in run.findings:
            if f.rule == rule:
                found.append(next(line.split("(")[0][4:] for line in reversed(lines[:f.line])
                                  if line.startswith("def ")))
        return sorted(found)

    assert where("valvur.python.command-injection") == ["unsafe_list", "unsafe_shell"]
    assert where("valvur.python.code-injection") == ["unsafe_eval", "unsafe_exec"]
    shell = [f for f in run.findings if f.rule == "valvur.python.subprocess-shell-true"]
    assert shell and all(f.inventory for f in shell)
