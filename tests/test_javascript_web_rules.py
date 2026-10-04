"""R25.4: JavaScript's SQL injection, command injection, path traversal and SSRF (D60).

Track 2 found none of the four (R25.1), and GitLab's audited set has nothing for
three of them and one rule for the fourth that fires on everything, so they are
valvur's own. The twins here are not track 2's: an Express handler written another
way, so a rule fitted to the Score's cases alone fails here. The safe twin binds a
parameter, passes an argument list, reduces a name to its base or confines it to a
root, or checks a host against a list.
"""

from __future__ import annotations

import pytest

TWINS = {
    "valvur.javascript.sql-injection": ('''\
const pool = require('./pool');
module.exports = (app) => app.get('/books', async (req, res) => {
  const author = req.query.author;
  const { rows } = await pool.query("SELECT title FROM books WHERE author = '" + author + "'");
  res.json(rows);
});
''', '''\
const pool = require('./pool');
module.exports = (app) => app.get('/books', async (req, res) => {
  const author = req.query.author;
  const { rows } = await pool.query('SELECT title FROM books WHERE author = $1', [author]);
  res.json(rows);
});
'''),
    "valvur.javascript.command-injection": ('''\
const cp = require('child_process');
module.exports = (app) => app.post('/archive', (req, res) => {
  const dir = req.body.dir;
  cp.exec(`tar czf /tmp/out.tgz ${dir}`, () => res.sendStatus(204));
});
''', '''\
const cp = require('child_process');
module.exports = (app) => app.post('/archive', (req, res) => {
  const dir = req.body.dir;
  cp.execFile('tar', ['czf', '/tmp/out.tgz', '--', dir], () => res.sendStatus(204));
});
'''),
    "valvur.javascript.path-traversal": ('''\
const fs = require('fs');
module.exports = (app) => app.get('/avatar', (req, res) => {
  const file = '/srv/avatars/' + req.query.user + '.png';
  res.type('png').send(fs.readFileSync(file));
});
''', '''\
const path = require('path');
module.exports = (app) => app.get('/avatar', (req, res) => {
  res.sendFile(req.query.user + '.png', { root: '/srv/avatars' });
});
'''),
    "valvur.javascript.ssrf": ('''\
const https = require('https');
module.exports = (app) => app.get('/proxy', (req, res) => {
  https.get(req.query.target, (upstream) => upstream.pipe(res));
});
''', '''\
const https = require('https');
const HOSTS = ['cdn.example.com'];
module.exports = (app) => app.get('/proxy', (req, res) => {
  const target = new URL(req.query.target);
  if (!HOSTS.includes(target.hostname)) return res.sendStatus(400);
  https.get(target, (upstream) => upstream.pipe(res));
});
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
        (ws / f"vulnerable_{index}.js").write_text(vulnerable)
        (ws / f"safe_{index}.js").write_text(safe)

    run = api.scan(ws, runner=ContainerRuntime(), adapters=[OpengrepAdapter()],
                   profile="offline")

    for index, rule in enumerate(TWINS):
        paths = sorted(f.path for f in run.findings if f.rule == rule)
        assert paths == [f"vulnerable_{index}.js"], (rule, paths)
        assert all(f.cwe for f in run.findings if f.rule == rule), rule
