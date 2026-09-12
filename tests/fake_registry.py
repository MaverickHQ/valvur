"""An OCI registry on loopback, for the published-index tests (23.2.1).

Real HTTP rather than a monkeypatched `urlopen`, because the two things that made
the client more than three GETs are HTTP behaviour measured against GHCR on
2026-09-12: an anonymous pull is answered **401 with a bearer challenge** naming a
token endpoint, and a blob request is answered **307 to a CDN host** whose signed
URL refuses a request that also carries our bearer token. Both are optional here so
a test can say which it is exercising. A plain `registry:2` does neither.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from valvur.name_index import ARTIFACT_TYPE, CONFIG_TYPE, FILES, LAYER_TYPE, METADATA

MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeRegistry:
    def __init__(self, *, challenge: bool = False, redirect_blobs: bool = False):
        self.challenge = challenge
        self.redirect_blobs = redirect_blobs
        self.manifests: dict[str, tuple[bytes, str]] = {}   # "name:ref" → (raw, media type)
        self.blobs: dict[str, bytes] = {}
        #: Serve these bytes for a digest instead of the real ones — a registry, or
        #: the wire, that lies.
        self.tamper: dict[str, bytes] = {}
        #: Name every manifest by a digest its bytes do not hash to.
        self.lie_about_digests = False
        self.requests: list[str] = []
        #: Every Authorization header that arrived, None for none — what the client
        #: SENT, which is the half of the anonymous promise a request log shows.
        self.authorizations: list[str | None] = []
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------- lifecycle

    def __enter__(self) -> FakeRegistry:
        registry = self
        cdn = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self, cdn=True))
        main = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self, cdn=False))
        self._servers = [main, cdn]
        registry.host = f"127.0.0.1:{main.server_address[1]}"
        registry.cdn_host = f"127.0.0.1:{cdn.server_address[1]}"
        for server in self._servers:
            thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __exit__(self, *_: object) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()

    # --------------------------------------------------------------- pushing

    def push_index(self, name: str, tag: str, directory: Path, *,
                   artifact_type: str = ARTIFACT_TYPE) -> str:
        """What `oras push` does in the workflow: the directory's `metadata.json` as
        the config blob, each ecosystem file gzip-compressed as a layer titled
        `<file>.gz`. Returns the manifest digest."""
        config = (directory / METADATA).read_bytes()
        self.blobs[_digest(config)] = config
        layers = []
        for filename in FILES.values():
            path = directory / filename
            if not path.is_file():
                continue
            data = gzip.compress(path.read_bytes(), mtime=0)
            self.blobs[_digest(data)] = data
            layers.append({
                "mediaType": LAYER_TYPE, "digest": _digest(data), "size": len(data),
                "annotations": {"org.opencontainers.image.title": filename + ".gz"},
            })
        manifest = {
            "schemaVersion": 2, "mediaType": MANIFEST_TYPE, "artifactType": artifact_type,
            "config": {"mediaType": CONFIG_TYPE, "digest": _digest(config), "size": len(config)},
            "layers": layers,
        }
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        digest = _digest(raw)
        self.manifests[f"{name}:{tag}"] = (raw, MANIFEST_TYPE)
        self.manifests[f"{name}:{digest}"] = (raw, MANIFEST_TYPE)
        return digest

    def reference(self, name: str, tag: str = "latest") -> str:
        return f"{self.host}/{name}:{tag}"


def _handler(registry: FakeRegistry, *, cdn: bool):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):  # quiet
            pass

        def do_GET(self):
            registry.requests.append(("cdn " if cdn else "") + self.path)
            registry.authorizations.append(self.headers.get("Authorization"))
            path = urlsplit(self.path).path
            if cdn:
                return self._cdn(path)
            if path == "/token":
                return self._json(200, {"token": "anonymous-pull-token"})
            parts = path.split("/")
            if len(parts) < 5 or parts[1] != "v2":
                return self._status(404)
            kind, ref = parts[-2], parts[-1]
            name = "/".join(parts[2:-2])
            granted = self.headers.get("Authorization") == "Bearer anonymous-pull-token"
            if registry.challenge and not granted:
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    f'Bearer realm="http://{registry.host}/token",service="fake",'
                    f'scope="repository:{name}:pull"',
                )
                self.end_headers()
                return None
            if kind == "manifests":
                entry = registry.manifests.get(f"{name}:{ref}")
                if entry is None:
                    return self._status(404)
                raw, media_type = entry
                self.send_response(200)
                self.send_header("Content-Type", media_type)
                stated = "sha256:" + "0" * 64 if registry.lie_about_digests else _digest(raw)
                self.send_header("Docker-Content-Digest", stated)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return None
            if kind == "blobs":
                if ref not in registry.blobs:
                    return self._status(404)
                if registry.redirect_blobs:
                    self.send_response(307)
                    self.send_header("Location", f"http://{registry.cdn_host}/cdn/{ref}")
                    self.end_headers()
                    return None
                return self._blob(ref)
            return self._status(404)

        def _cdn(self, path: str):
            if self.headers.get("Authorization"):
                # A signed CDN URL plus a bearer token: "only one auth mechanism".
                return self._status(400)
            digest = path.rsplit("/", 1)[-1]
            if digest not in registry.blobs:
                return self._status(404)
            return self._blob(digest)

        def _blob(self, digest: str):
            data = registry.tamper.get(digest, registry.blobs[digest])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self, status: int, body: dict):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _status(self, status: int):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler
