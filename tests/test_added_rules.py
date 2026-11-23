"""R49.6: two rules the tracks lacked, each held to its generated cases (D82i).

Certificate verification turned off (CWE-295) in Python, and a cookie set without `secure`
in JavaScript (CWE-614). Each rule must report every vulnerable case the Score's generators
write for its weakness, and no safe one, through Opengrep in the image.

A third was written and is not shipped: `valvur.javascript.tls-verification-off` caught its
two cases and was 0 true of 307 on maintained code, under ADR-0029's bar (D82i's fallback).
Its cases stay on the JavaScript track, uncaught, so the Score shows the gap.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

TWINS = Path(__file__).resolve().parent.parent / "scripts" / "eval" / "twins.py"
#: Verification an operator must ask to turn off, chosen by a conditional expression: an
#: option, not a weakness. valvur's own client for an internal mirror reads so, and the
#: rule reported it in the acceptance set's scan of valvur itself.
OPT_IN = '''\
import ssl

def context(insecure=False):
    return ssl._create_unverified_context() if insecure else None
'''


def _twins():
    sys.path.insert(0, str(TWINS.parent))
    spec = importlib.util.spec_from_file_location("valvur_twins_added", TWINS)
    module = importlib.util.module_from_spec(spec)
    sys.modules["valvur_twins_added"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def reported(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    twins = _twins()
    ws = mountable_tmp / "ws"
    cases = [("js/" + c.path, c) for c in twins.build("sast-js", ws / "js", seed=7)]
    (ws / "py").mkdir()
    cases += [("py/" + c.path, c) for c in twins.python_generated(ws / "py")]
    (ws / "py" / "app" / "optin.py").write_text(OPT_IN)
    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    def of(rule: str, cwe: int, prefix: str) -> tuple[list[str], list[str]]:
        vulnerable = sorted(path for path, c in cases
                            if path.startswith(prefix) and c.cwes == (cwe,) and c.vulnerable)
        return sorted({f.path for f in run.findings if f.rule == rule}), vulnerable

    return of


@pytest.mark.e2e
@pytest.mark.parametrize("rule, cwe, prefix, count", [
    ("valvur.javascript.insecure-cookie", 614, "js/", 2),
    ("valvur.python.tls-verification-off", 295, "py/", 3),
])
def test_each_added_rule_reports_its_vulnerable_cases_and_no_safe_one(reported, rule, cwe,
                                                                      prefix, count):
    found, vulnerable = reported(rule, cwe, prefix)

    assert len(vulnerable) == count
    assert found == vulnerable


def test_the_javascript_tls_rule_is_not_shipped():
    """Held, so that it comes back only with a measurement that says it may."""
    rules = (TWINS.parents[2] / "rules" / "javascript-security.yaml").read_text()

    assert "- id: valvur.javascript.tls-verification-off" not in rules
    assert "- id: valvur.javascript.insecure-cookie" in rules


@pytest.mark.e2e
def test_verification_turned_off_only_when_asked_is_not_reported(reported):
    found, _vulnerable = reported("valvur.python.tls-verification-off", 295, "py/")

    assert "py/app/optin.py" not in found
