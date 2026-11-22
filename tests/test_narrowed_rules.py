"""R49.5: the rules that can be narrowed, narrowed on what maintained code showed (D82e).

Three of valvur's own rules were under the bar on the corpus (R49.1), and a fourth had two
false Findings there. Each false Finding is cut down here to the lines that made it, and
must not be reported; beside it stands a case that is a vulnerability and must still be.
`tests/test_python_web_rules.py` holds each rule's planted twins, unchanged.

- **open-redirect:** a redirect to a URL the application's own router builds.
- **path-traversal:** a path's name, suffix or absoluteness taken and nothing opened, and
  pytest's `request.param`, which is no web request.
- **ssrf:** a *response's* headers are not request data.
- **insecure-cookie** cannot be narrowed: its false Findings are the vulnerable form itself,
  in tests. It is listed in test material by the tier table, and active everywhere else.
"""

from __future__ import annotations

import pytest

FILES = {
    # ------------------------------------------------------------ open-redirect
    "app/shorty.py": '''\
from flask import redirect, request, url_for

def new():
    uid = store(request.form["url"])
    return redirect(url_for("display", uid=uid))
''',
    "app/sanic_pages.py": '''\
from sanic.response import redirect

async def page(request, language, path):
    return redirect(request.app.url_for("page", language=language, path=path))
''',
    "app/still_open.py": '''\
from flask import redirect, request

def go():
    return redirect(request.args.get("next"))
''',
    # ----------------------------------------------------------- path-traversal
    "app/names.py": '''\
from pathlib import Path

def extension(request):
    return Path(request.url).suffix

def stored_as(request):
    return str(Path("subdir") / Path(request.url).name)

def refuse_absolute(request):
    filename = request.match_info["filename"]
    if Path(filename).is_absolute():
        raise ValueError(filename)
''',
    "app/fixture_params.py": '''\
import shutil
from pathlib import Path

def copy_test_files(root_dir, request):
    en_file_path = Path(request.param[0])
    shutil.copy(str(en_file_path), str(root_dir / "doc.md"))
''',
    "app/still_read.py": '''\
from pathlib import Path
from flask import request

def read():
    return Path(request.args.get("name")).read_text()

def read_again():
    return open(f"/srv/files/{request.args.get('name')}").read()
''',
    # ---------------------------------------------------------- insecure-cookie
    "tests/test_cookies.py": '''\
def test_a_cookie_without_secure(resp):
    resp.set_cookie("foo", "bar", secure=False)
''',
    "app/session.py": '''\
def remember(response, value):
    response.set_cookie("session", value, secure=False)
''',
    # --------------------------------------------------------------------- ssrf
    "lib/follow.js": '''\
async function follow(response, requestOptions) {
  const locationURL = new URL(response.headers.get('Location'), requestOptions.url);
  return fetch(new Request(locationURL, requestOptions));
}
module.exports = { follow };
''',
    "lib/still_forged.js": '''\
const express = require('express');
const app = express();
app.get('/proxy', async (req, res) => {
  const upstream = await fetch(req.query.url);
  res.send(await upstream.text());
});
''',
}


@pytest.fixture
def findings(mountable_tmp):
    from valvur import api
    from valvur.adapters import OpengrepAdapter
    from valvur.engine_host import ContainerRuntime

    ws = mountable_tmp / "ws"
    for name, text in FILES.items():
        (ws / name).parent.mkdir(parents=True, exist_ok=True)
        (ws / name).write_text(text)
    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")
    return run.findings


def _where(findings, rule: str) -> list[tuple[str, bool]]:
    return sorted({(f.path, f.inventory) for f in findings if f.rule == rule})


@pytest.mark.e2e
def test_a_redirect_to_a_url_the_router_builds_is_not_reported(findings):
    assert _where(findings, "valvur.python.open-redirect") == [("app/still_open.py", False)]


@pytest.mark.e2e
def test_a_paths_name_and_pytests_param_are_not_reported(findings):
    assert _where(findings, "valvur.python.path-traversal") == [("app/still_read.py", False)]
    lines = sorted(f.line for f in findings if f.rule == "valvur.python.path-traversal")
    assert lines == [5, 8], "both reads in still_read.py, and nothing else"


@pytest.mark.e2e
def test_an_insecure_cookie_is_listed_in_a_test_and_active_in_the_application(findings):
    assert _where(findings, "valvur.python.insecure-cookie") == [
        ("app/session.py", False), ("tests/test_cookies.py", True)]


@pytest.mark.e2e
def test_a_responses_headers_are_not_request_data(findings):
    assert _where(findings, "valvur.javascript.ssrf") == [("lib/still_forged.js", False)]
