"""GitHub's REST API on loopback, for the watchdog's tests (R42.5).

Real HTTP, as `fake_registry.py` serves an OCI registry: the scheduled runs of each
workflow, and the repository's issues, which the client reads, opens, comments on and
closes. Every write is recorded, so a test can say what was filed, and that a dry run
filed nothing.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class FakeGitHub:
    def __init__(self, repo: str = "MaverickHQ/valvur"):
        self.repo = repo
        #: workflow file → runs, newest first, as the Actions API lists them.
        self.runs: dict[str, list[dict]] = {}
        self.issues: list[dict] = []
        self.writes: list[tuple[str, str, dict]] = []
        self.reads: list[str] = []
        self.authorizations: list[str | None] = []

    def __enter__(self) -> FakeGitHub:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self))
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, args=(0.02,),
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def issue(self, title: str, *, state: str = "open") -> dict:
        issue = {"number": len(self.issues) + 1, "title": title, "state": state,
                 "comments": []}
        self.issues.append(issue)
        return issue


def _handler(github: FakeGitHub):
    prefix = f"/repos/{github.repo}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):  # quiet
            pass

        def _send(self, status: int, body: object) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self):
            github.authorizations.append(self.headers.get("Authorization"))
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            github.reads.append(self.path)
            if url.path.startswith(f"{prefix}/actions/workflows/") and url.path.endswith("/runs"):
                name = url.path.split("/")[-2]
                runs = [r for r in github.runs.get(name, [])
                        if r.get("event") == query.get("event", [r.get("event")])[0]
                        and r.get("head_branch") == query.get("branch", [r.get("head_branch")])[0]]
                return self._send(200, {"total_count": len(runs), "workflow_runs": runs})
            if url.path == f"{prefix}/issues":
                state = query.get("state", ["open"])[0]
                return self._send(200, [i for i in github.issues
                                        if state == "all" or i["state"] == state])
            return self._send(404, {"message": "Not Found"})

        def do_POST(self):
            body = self._body()
            path = urlsplit(self.path).path
            github.writes.append(("POST", path, body))
            if path == f"{prefix}/issues":
                issue = github.issue(body["title"])
                issue["body"] = body.get("body", "")
                return self._send(201, issue)
            if path.startswith(f"{prefix}/issues/") and path.endswith("/comments"):
                number = int(path.split("/")[-2])
                github.issues[number - 1]["comments"].append(body.get("body", ""))
                return self._send(201, {"id": number})
            return self._send(404, {"message": "Not Found"})

        def do_PATCH(self):
            body = self._body()
            path = urlsplit(self.path).path
            github.writes.append(("PATCH", path, body))
            number = int(path.split("/")[-1])
            github.issues[number - 1].update(body)
            return self._send(200, github.issues[number - 1])

    return Handler
