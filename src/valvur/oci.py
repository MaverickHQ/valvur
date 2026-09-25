"""A read-only OCI registry client, for the published package-name index (23.2.1).

The shim has zero dependencies (ADR-0015) and no container runtime is needed to read
a registry: the distribution API is three requests. Resolve a tag to a manifest, read
the manifest, stream each blob by digest. Every byte that arrives is checked against
the digest that named it — the manifest against the digest the registry resolved the
tag to, each blob against the digest in the manifest — so what is written is what
the manifest describes, whatever the wire did. Authenticity is the signature's job
(`verify_signature` below); integrity is the digest's, and it costs nothing.

Anonymous only. The published index is public and a mirror is on the operator's own
registry; a credential store is a surface this product declines to read.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote, urlencode

TIMEOUT = 120
_UA = {"User-Agent": "valvur (+https://github.com/MaverickHQ/valvur)"}

MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))

#: A blob larger than this is not an index and is not read. The whole index is
#: about 100MB uncompressed (six million names); a registry answering with something
#: else must not be streamed to disk indefinitely.
MAX_BLOB = 512 * 1024 * 1024


class RegistryError(RuntimeError):
    """The registry could not be read. Nothing was written."""


class DigestMismatch(RegistryError):
    """Bytes arrived that do not hash to the digest that named them."""


class SignatureInvalid(RuntimeError):
    """cosign ran and REFUSED the artifact. Never softened into a fallback: a bad
    signature on a supply-chain artifact is the one failure that must stop."""


#: The distribution spec's grammar for a repository path.
_REPOSITORY_NAME = r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"


@dataclass(frozen=True)
class Reference:
    """`host/name[:tag]` — the part of an image reference a pull needs."""

    host: str
    name: str
    tag: str = "latest"

    @classmethod
    def parse(cls, text: str) -> Reference:
        text = text.strip()
        if "://" in text or not text:
            raise RegistryError(f"not an OCI reference (host/name[:tag]): {text!r}")
        host, _, rest = text.partition("/")
        if not rest or ("." not in host and ":" not in host and host != "localhost"):
            # `maverickhq/valvur-index` with no registry host would mean Docker Hub
            # by Docker's convention; nothing of ours lives there, so it is a typo.
            raise RegistryError(f"an OCI reference needs a registry host: {text!r}")
        if "@" in rest:
            raise RegistryError(f"a digest reference cannot name a moving index: {text!r}")
        name, _, tag = rest.partition(":")
        if not re.fullmatch(_REPOSITORY_NAME, name):
            raise RegistryError(f"not a valid repository name: {name!r}")
        return cls(host, name, tag or "latest")

    @property
    def repository(self) -> str:
        return f"{self.host}/{self.name}"

    def __str__(self) -> str:
        return f"{self.repository}:{self.tag}"


@dataclass(frozen=True)
class Manifest:
    digest: str
    media_type: str
    body: dict
    raw: bytes


class _KeepAuthOnSameHost(urllib.request.HTTPRedirectHandler):
    """GHCR answers a blob request with a redirect to a CDN URL that is already
    signed; forwarding our bearer token there makes the CDN refuse the request as
    doubly authenticated. Docker drops credentials on a cross-host redirect, and so
    does this."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            before = urllib.parse.urlsplit(req.full_url).netloc
            if urllib.parse.urlsplit(newurl).netloc != before:
                new.remove_header("Authorization")
        return new


class Registry:
    """One repository on one registry, read anonymously.

    `insecure` is what Trivy's `--insecure` is (`VALVUR_DB_INSECURE`): TLS without
    certificate verification, and plain HTTP when the host does not speak TLS at all.
    For an operator's internal mirror; never the default.
    """

    def __init__(self, reference: Reference, *, insecure: bool = False, timeout: int = TIMEOUT):
        self.reference = reference
        self.insecure = insecure
        self.timeout = timeout
        self._scheme: str | None = None
        self._token: str | None = None
        context = ssl._create_unverified_context() if insecure else None  # noqa: S323 — opt-in
        handlers: list = [_KeepAuthOnSameHost()]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    # ------------------------------------------------------------ the three calls

    def manifest(self, tag: str | None = None) -> Manifest:
        """The manifest a tag resolves to, with the digest the registry states for
        it — recomputed here from the bytes, because that digest is what gets signed
        and what the caller reports."""
        url = self._url(f"manifests/{quote(tag or self.reference.tag, safe=':')}")
        with self._open(url, accept=MANIFEST_ACCEPT) as response:
            raw = response.read(MAX_BLOB)
            stated = response.headers.get("Docker-Content-Digest")
            media_type = response.headers.get("Content-Type", "").split(";")[0].strip()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if stated and stated != digest:
            raise DigestMismatch(f"{self.reference}: the registry named the manifest {stated} "
                                 f"and served bytes hashing to {digest}")
        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise RegistryError(f"{self.reference}: the manifest is not JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise RegistryError(f"{self.reference}: the manifest is not an object")
        return Manifest(digest, body.get("mediaType") or media_type, body, raw)

    def blob(self, digest: str, sink: Callable[[bytes], None], *, size: int | None = None) -> int:
        """Stream one blob into `sink`, verifying its digest as it goes. The sink
        sees every chunk BEFORE verification completes, so it must write somewhere
        that can be discarded — the caller renames into place only on return."""
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise RegistryError(f"not a sha256 digest: {digest!r}")
        if size is not None and size > MAX_BLOB:
            raise RegistryError(f"{self.reference}: blob {digest} is {size:,} bytes, larger "
                                f"than any index ({MAX_BLOB:,})")
        hasher = hashlib.sha256()
        total = 0
        url = self._url(f"blobs/{digest}")
        with self._open(url, accept="application/octet-stream") as response:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BLOB:
                    raise RegistryError(f"{self.reference}: blob {digest} exceeds "
                                        f"{MAX_BLOB:,} bytes")
                hasher.update(chunk)
                sink(chunk)
        actual = "sha256:" + hasher.hexdigest()
        if actual != digest:
            raise DigestMismatch(f"{self.reference}: blob named {digest} hashed to {actual}")
        if size is not None and total != size:
            raise DigestMismatch(f"{self.reference}: blob {digest} is {total:,} bytes, the "
                                 f"manifest says {size:,}")
        return total

    def blob_bytes(self, digest: str, *, size: int | None = None) -> bytes:
        chunks: list[bytes] = []
        self.blob(digest, chunks.append, size=size)
        return b"".join(chunks)

    # ------------------------------------------------------------------ plumbing

    def _url(self, path: str) -> str:
        return f"{self._scheme or 'https'}://{self.reference.host}/v2/{self.reference.name}/{path}"

    def _open(self, url: str, *, accept: str):
        """One request, with the bearer-token dance the distribution spec
        prescribes: an anonymous request is answered 401 with a challenge naming a
        token endpoint; the token endpoint hands out a pull token for the scope;
        the request is repeated with it. GHCR and Docker Hub both do exactly this
        for public repositories; a plain `registry:2` never challenges."""
        try:
            return self._send(url, accept)
        except urllib.error.HTTPError as exc:
            if exc.code != 401 or self._token is not None:
                raise RegistryError(f"{url}: {exc}") from exc
            challenge = exc.headers.get("WWW-Authenticate", "")
            self._token = self._token_for(challenge)
            if self._token is None:
                raise RegistryError(f"{url}: the registry demands credentials and valvur pulls "
                                    "anonymously (is the package public?)") from exc
        try:
            return self._send(url, accept)
        except urllib.error.HTTPError as exc:
            raise RegistryError(f"{url}: {exc}") from exc

    def _send(self, url: str, accept: str):
        headers = {**_UA, "Accept": accept}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if self._scheme is None and self.insecure:
            # Trivy's `--insecure`: TLS without verification, then plain HTTP. Decided
            # once, on the first request, and remembered for the session.
            try:
                response = self._opener.open(_request(url, headers), timeout=self.timeout)
                self._scheme = "https"
                return response
            except urllib.error.HTTPError:
                self._scheme = "https"
                raise
            except (urllib.error.URLError, OSError, ssl.SSLError):
                self._scheme = "http"
        # The caller built the URL before the scheme was known (a retry after a 401
        # carries the original URL), so it is restated here from the decision above.
        url = f"{self._scheme or 'https'}://{url.split('://', 1)[1]}"
        try:
            return self._opener.open(_request(url, headers), timeout=self.timeout)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise RegistryError(f"{url}: {exc}") from exc

    def _token_for(self, challenge: str) -> str | None:
        if not challenge.lower().startswith("bearer "):
            return None
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.get("realm")
        if not realm or not realm.startswith(("https://", "http://")):
            return None
        query = {k: v for k, v in fields.items() if k in ("service", "scope")}
        try:
            with self._opener.open(_request(f"{realm}?{urlencode(query)}", dict(_UA)),
                                   timeout=self.timeout) as response:
                data = json.loads(response.read(1 << 20))
        except (urllib.error.URLError, OSError, ValueError):
            return None
        token = data.get("token") or data.get("access_token") if isinstance(data, dict) else None
        return token if isinstance(token, str) and token else None


def _request(url: str, headers: dict) -> urllib.request.Request:
    if not url.startswith(("https://", "http://")):
        raise RegistryError(f"refusing a non-http(s) registry URL: {url!r}")
    return urllib.request.Request(url, headers=headers)  # noqa: S310 — asserted above


# ---------------------------------------------------------------- image size

#: `platform.machine()` spellings → the OCI architecture an image index uses.
_ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def image_size(reference: str, *, insecure: bool = False) -> int | None:
    """Compressed bytes the runtime will pull for `reference` on this machine's
    architecture, or None when the registry cannot say — no answer is better than
    a made-up one on the line that tells an agent why nothing is happening yet
    (10.2 claim 4). Two anonymous requests; a private image answers None. Works
    for a plain artifact too — the database, the index (24.1) — whose manifest has
    layers and no platforms. `insecure` is the operator's mirror setting."""
    import platform

    try:
        parsed = Reference.parse(reference)
        # Docker's own convention: loopback registries are allowed plain HTTP.
        local = parsed.host.split(":")[0] in ("localhost", "127.0.0.1")
        registry = Registry(parsed, insecure=local or insecure, timeout=20)
        manifest = registry.manifest()
        if "manifests" in manifest.body:            # a multi-platform index
            wanted = _ARCHITECTURES.get(platform.machine().lower(), platform.machine().lower())
            chosen = next((m for m in manifest.body["manifests"]
                           if (m.get("platform") or {}).get("architecture") == wanted
                           and (m.get("platform") or {}).get("os", "linux") == "linux"), None)
            if chosen is None:
                return None
            manifest = registry.manifest(chosen["digest"])
        layers = manifest.body.get("layers") or []
        return sum(int(layer.get("size") or 0) for layer in layers)
    except (RegistryError, ValueError, TypeError, KeyError):
        return None


# ------------------------------------------------------------------ signatures

#: The identity every valvur artifact is signed under: a workflow in this repository,
#: through GitHub's OIDC issuer. The same two values the README's own verification
#: command uses for the image.
#: The identity a signature on the INDEX must carry (28.0.2): the index workflow,
#: run on main — one file, one ref. Until 28.0.2 this was the repository alone,
#: which every workflow on every branch satisfies, so a branch's or a probe's
#: signature verified as the daily index's. Anchored at both ends: the ref is the
#: last thing in the SAN and `main` must be all of it.
SIGNING_IDENTITY = r"^https://github\.com/MaverickHQ/valvur/\.github/workflows/index\.yml@refs/heads/main$"
SIGNING_ISSUER = "https://token.actions.githubusercontent.com"

Verification = str


def verify_signature(reference_at_digest: str, *, identity: str = SIGNING_IDENTITY,
                     issuer: str = SIGNING_ISSUER, insecure: bool = False) -> Verification:
    """Verify the keyless cosign signature on an artifact, with cosign.

    Returns what a run report can print: `"verified"`, or `"not verified: …"` naming
    why it could not be — cosign is not installed, most often. A verifier that RAN
    and refused raises `SignatureInvalid`, which nothing catches on the way up: the
    artifact is not used and the failure is the whole answer.

    cosign, not a reimplementation. Keyless verification is a certificate chain to
    Fulcio, a transparency-log inclusion proof and the OIDC identity in the
    certificate's SAN; a shim with no dependencies does not carry that, and a
    home-made ECDSA verifier in a security tool is the wrong trade. The vulnerability
    database this sits beside is pulled by Trivy with no signature at all.
    """
    cosign = shutil.which("cosign")
    if cosign is None:
        return ("not verified: cosign is not installed (brew install cosign, or see "
                "docs/AIR-GAPPED.md)")
    command = [cosign, "verify", reference_at_digest,
               "--certificate-identity-regexp", identity,
               "--certificate-oidc-issuer", issuer]
    if insecure:
        command.append("--allow-insecure-registry")
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"not verified: cosign could not run ({exc})"
    if proc.returncode == 0:
        return "verified"
    detail = (proc.stderr.strip() or proc.stdout.strip()).splitlines()
    raise SignatureInvalid(
        f"cosign REFUSED the signature on {reference_at_digest}:\n  "
        + "\n  ".join(detail[-6:])
        + "\nThe artifact was not used. If this is a mirror, copy the signature with it "
        "(`cosign copy` or `oras cp --recursive`); otherwise treat it as tampering."
    )
