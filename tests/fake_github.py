"""GitHub's REST API on loopback, for the watchdog's tests (R42.5).

Real HTTP, as `fake_registry.py` serves an OCI registry: the scheduled runs of each
workflow, and the repository's issues, which the client reads, opens, comments on and
closes. Every write is recorded, so a test can say what was filed, and that a dry run
filed nothing. It also serves each Scanner's releases upstream, at the same API's
`/repos/<owner>/<name>/releases`, and go.dev's list of supported Go releases at `/go`,
for the watchdog's Scanner checks.
"""

from __future__ import annotations

import io
import json
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class FakeGitHub:
    def __init__(self, repo: str = "MaverickHQ/valvur"):
        self.repo = repo
        #: workflow file → runs, newest first, as the Actions API lists them.
        self.runs: dict[str, list[dict]] = {}
        self.issues: list[dict] = []
        #: The repository's pull requests, as the Pulls API lists them (R46.3).
        self.pulls: list[dict] = []
        #: commit → its message, as the Commits API gives one (R46.1).
        self.commits: dict[str, str] = {}
        self.writes: list[tuple[str, str, dict]] = []
        self.reads: list[str] = []
        self.authorizations: list[str | None] = []
        #: upstream repository → releases, newest first, as the Releases API lists them.
        self.releases: dict[str, list[dict]] = {}
        #: The repository's artifacts, as the Actions API lists them (R52.5). Each one's
        #: files are served as a zip from another path, which the API redirects to, as
        #: GitHub redirects a download to its storage.
        self.artifacts: list[dict] = []
        self.files: dict[int, dict[str, bytes]] = {}
        #: What the storage was sent as authorization: a token must not follow there.
        self.storage_authorizations: list[str | None] = []
        #: Artifact names whose listing fails, as an API that is down does.
        self.broken: set[str] = set()
        #: go.dev's `/dl/?mode=json`: the supported releases.
        self.go: list[dict] = [{"version": "go1.27.3", "stable": True},
                               {"version": "go1.26.10", "stable": True}]

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

    def issue(self, title: str, *, state: str = "open", **more) -> dict:
        issue = {"number": len(self.issues) + 1, "title": title, "state": state,
                 "comments": [], **more}
        self.issues.append(issue)
        return issue

    def artifact(self, name: str, files: dict[str, object], *, created: str,
                 branch: str = "main", expired: bool = False) -> dict:
        """An artifact of a run on `branch`, holding `files` (JSON-encoded unless bytes)."""
        made = {"id": 1000 + len(self.artifacts), "name": name, "created_at": created,
                "expired": expired, "workflow_run": {"head_branch": branch}}
        self.files[made["id"]] = {
            path: body if isinstance(body, bytes) else json.dumps(body).encode()
            for path, body in files.items()}
        self.artifacts.insert(0, made)
        return made


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
            if url.path == f"{prefix}/actions/artifacts":
                name = query.get("name", [None])[0]
                if name in github.broken:
                    return self._send(503, {"message": "Service Unavailable"})
                found = sorted((a for a in github.artifacts if name in (None, a["name"])),
                               key=lambda a: a["created_at"], reverse=True)
                return self._send(200, {"total_count": len(found), "artifacts": found})
            if url.path.startswith(f"{prefix}/actions/artifacts/") and url.path.endswith("/zip"):
                self.send_response(302)
                self.send_header("Location", f"{github.url}/storage/{url.path.split('/')[-2]}")
                self.send_header("Content-Length", "0")
                return self.end_headers()
            if url.path.startswith("/storage/"):
                github.authorizations.pop()
                github.storage_authorizations.append(self.headers.get("Authorization"))
                if self.headers.get("Authorization"):
                    return self._send(403, {"message": "the storage refuses a token"})
                packed = io.BytesIO()
                with zipfile.ZipFile(packed, "w") as archive:
                    for path, body in github.files[int(url.path.split("/")[-1])].items():
                        archive.writestr(path, body)
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(packed.getvalue())))
                self.end_headers()
                return self.wfile.write(packed.getvalue())
            if url.path.startswith(f"{prefix}/actions/workflows/") and url.path.endswith("/runs"):
                name = url.path.split("/")[-2]
                if name not in github.runs:
                    return self._send(404, {"message": "Not Found"})
                runs = [r for r in github.runs.get(name, [])
                        if r.get("event") == query.get("event", [r.get("event")])[0]
                        and r.get("head_branch") == query.get("branch", [r.get("head_branch")])[0]]
                return self._send(200, {"total_count": len(runs), "workflow_runs": runs})
            if url.path.endswith("/releases") and url.path.count("/") == 4:
                upstream = url.path.removeprefix("/repos/").removesuffix("/releases")
                if upstream not in github.releases:
                    return self._send(404, {"message": "Not Found"})
                return self._send(200, github.releases[upstream])
            if url.path == "/go":
                return self._send(200, github.go)
            if url.path.startswith(f"{prefix}/issues/"):
                parts = url.path.removeprefix(f"{prefix}/issues/").split("/")
                issue = github.issues[int(parts[0]) - 1]
                if parts[1:] == ["comments"]:
                    return self._send(200, [c if isinstance(c, dict) else {"body": c}
                                            for c in issue["comments"]])
                return self._send(200, issue)
            if url.path.startswith(f"{prefix}/commits/"):
                sha = url.path.rsplit("/", 1)[1]
                if sha not in github.commits:
                    return self._send(404, {"message": "Not Found"})
                return self._send(200, {"sha": sha, "commit": {"message": github.commits[sha]}})
            if url.path == f"{prefix}/pulls":
                return self._send(200, github.pulls)
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
                # A workflow's own token opens an issue as this account.
                issue = github.issue(body["title"], user={"login": "github-actions[bot]"})
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
