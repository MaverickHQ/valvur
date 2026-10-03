"""R25.3: Python's path traversal, secure cookies, open redirects and XXE (D60).

None of the four found anything on the OWASP Benchmark (R25.1), and no rule in
GitLab's audited set met D29's bar for them, so they are valvur's own. Each has a
vulnerable twin it must report and a safe twin it must not: the safe one refuses a
path that climbs, sets `secure=True`, checks a URL's host once parsed, or leaves
external entities off.
"""

from __future__ import annotations

import pytest

TWINS = {
    "valvur.python.path-traversal": ('''\
from flask import request

def read():
    name = request.args.get("name")
    return open(f"/srv/files/{name}").read()
''', '''\
from flask import request

def read():
    name = request.args.get("name")
    if "../" in name:
        return "no"
    return open(f"/srv/files/{name}").read()
'''),
    "valvur.python.insecure-cookie": ('''\
def remember(response, value):
    response.set_cookie("session", value, secure=False, httponly=True)
''', '''\
def remember(response, value):
    response.set_cookie("session", value, secure=True, httponly=True)
'''),
    "valvur.python.open-redirect": ('''\
from flask import redirect, request

def go():
    return redirect(request.args.get("next"))
''', '''\
import urllib.parse
from flask import redirect, request

def go():
    target = request.args.get("next")
    url = urllib.parse.urlparse(target)
    if url.netloc not in ["example.com"]:
        return "no"
    return redirect(target)
'''),
    "valvur.python.xml-external-entities": ('''\
import xml.dom.minidom
import xml.sax
import xml.sax.handler

def parse(data):
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    return xml.dom.minidom.parseString(data, parser)
''', '''\
import xml.dom.minidom
import xml.sax
import xml.sax.handler

def parse(data):
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    return xml.dom.minidom.parseString(data, parser)
'''),
}


@pytest.mark.e2e
def test_each_rule_reports_its_vulnerable_twin_and_not_its_safe_one(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    ws.mkdir()
    for index, (vulnerable, safe) in enumerate(TWINS.values()):
        (ws / f"vulnerable_{index}.py").write_text(vulnerable)
        (ws / f"safe_{index}.py").write_text(safe)

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    for index, rule in enumerate(TWINS):
        paths = sorted(f.path for f in run.findings if f.rule == rule)
        assert paths == [f"vulnerable_{index}.py"], (rule, paths)
        assert all(f.cwe for f in run.findings if f.rule == rule), rule
