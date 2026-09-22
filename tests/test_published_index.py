"""The published package-name index (23.2.1) and the three ecosystems it added
(23.2.2 Ruby and PHP, 23.2.3 Rust).

Measured 2026-09-12 before any of this was written: `rubygems.org/names` is 196,829
names in 2.8MB, one request, under a `---` line; `packagist.org/packages/list.json`
is 461,638 names, 3.6MB gzip-encoded; and crates.io's 1.86GB database dump has
`data/crates.csv` as its third member, so a streaming read stops after **381MB and
17.5 seconds** in 91MB of memory — the phase note that called it "impossible per
user" was written before measuring it. Against GHCR, anonymously: a manifest request
is answered 401 with a bearer challenge; a blob request 307s to
`pkg-containers.githubusercontent.com`, which refuses a request that still carries
the token. `trivy-db:2` has no `.sig` tag — Trivy pulls its database unsigned.
"""

from __future__ import annotations

import gzip
import io
import json
import stat
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from conftest import write_name_index
from fake_registry import FakeRegistry

from valvur import name_index, oci

# ------------------------------------------------------------------ fixtures


@pytest.fixture
def tiny(monkeypatch):
    """Every floor at one name, so a five-line fixture is a valid index."""
    monkeypatch.setattr(name_index, "MINIMUM_NAMES", dict.fromkeys(name_index.FILES, 1))


@pytest.fixture
def no_cosign(monkeypatch):
    monkeypatch.setattr(oci.shutil, "which", lambda _: None)


@pytest.fixture
def cosign(tmp_path, monkeypatch):
    """A `cosign` on PATH whose verdict the test chooses, and which records the
    arguments it was given."""
    log = tmp_path / "cosign.log"

    def install(exit_code: int) -> Path:
        binary = tmp_path / "bin" / "cosign"
        binary.parent.mkdir(exist_ok=True)
        binary.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}\n"
            f"echo 'Error: no matching signatures' >&2\nexit {exit_code}\n"
        )
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setattr(oci.shutil, "which", lambda _: str(binary))
        return log

    return install


@pytest.fixture
def source(tmp_path):
    """An index as the workflow builds it, ready to push."""
    return write_name_index(
        tmp_path / "source", pip=["requests", "flask"], npm=["react"], gem=["rack"],
        composer=["monolog/monolog"], cargo=["serde", "serde-json"],
        built_at="2026-09-12T02:00:00Z",
    )


@pytest.fixture
def registry(monkeypatch):
    with FakeRegistry() as fake:
        monkeypatch.setenv(name_index.INDEX_INSECURE_ENV, "1")   # loopback is plain http
        yield fake


# ------------------------------------------------------- the OCI client itself


def test_a_reference_is_host_name_and_tag():
    ref = oci.Reference.parse("ghcr.io/maverickhq/valvur-index")
    assert (ref.host, ref.name, ref.tag) == ("ghcr.io", "maverickhq/valvur-index", "latest")
    assert str(oci.Reference.parse("registry.internal:5000/mirror/idx:2026-09-12")) == \
        "registry.internal:5000/mirror/idx:2026-09-12"


@pytest.mark.parametrize("bad", [
    "", "maverickhq/valvur-index", "https://ghcr.io/x/y", "ghcr.io/x/y@sha256:abc",
    "ghcr.io/Upper/Case", "ghcr.io/",
])
def test_a_reference_that_is_not_one_is_refused(bad):
    with pytest.raises(oci.RegistryError):
        oci.Reference.parse(bad)


def test_the_bearer_challenge_is_answered_and_the_token_reused(registry, source, monkeypatch):
    """GHCR's anonymous flow, measured: 401 + challenge → token endpoint → retry.
    One token for the session, not one per request."""
    registry.challenge = True
    registry.push_index("acme/idx", "latest", source)
    client = oci.Registry(oci.Reference.parse(registry.reference("acme/idx")), insecure=True)

    manifest = client.manifest()
    client.blob_bytes(manifest.body["config"]["digest"])

    assert manifest.body["artifactType"] == name_index.ARTIFACT_TYPE
    assert sum(r.startswith("/token?") for r in registry.requests) == 1
    unauthorised = [r for r in registry.requests if r.startswith("/v2/")]
    assert len(unauthorised) == 3    # manifest (401), manifest again, blob


def test_a_redirect_to_the_cdn_drops_the_token(registry, source):
    """The CDN refuses a doubly-authenticated request (400). Docker strips
    credentials on a cross-host redirect, and so must we — with the challenge on,
    so there IS a token to drop."""
    registry.challenge = True
    registry.redirect_blobs = True
    registry.push_index("acme/idx", "latest", source)
    client = oci.Registry(oci.Reference.parse(registry.reference("acme/idx")), insecure=True)

    manifest = client.manifest()
    body = client.blob_bytes(manifest.body["config"]["digest"])

    assert json.loads(body)["schema"] == 1
    assert any(r.startswith("cdn /cdn/sha256:") for r in registry.requests)


def test_a_blob_that_does_not_hash_to_its_digest_is_refused(registry, source):
    registry.push_index("acme/idx", "latest", source)
    client = oci.Registry(oci.Reference.parse(registry.reference("acme/idx")), insecure=True)
    manifest = client.manifest()
    layer = manifest.body["layers"][0]
    original = registry.blobs[layer["digest"]]
    # Same length, one bit different: the size check cannot catch it; only the
    # digest can. (A mutation that dropped the digest comparison survived a
    # shorter tamper, caught by the size check instead.)
    registry.tamper[layer["digest"]] = original[:-1] + bytes([original[-1] ^ 1])

    with pytest.raises(oci.DigestMismatch, match="hashed to"):
        client.blob_bytes(layer["digest"], size=layer["size"])


def test_a_manifest_whose_stated_digest_disagrees_with_its_bytes_is_refused(registry, source):
    """The digest the registry states is what gets signed and reported; the bytes
    are what gets parsed. They have to be the same thing."""
    registry.push_index("acme/idx", "latest", source)
    registry.lie_about_digests = True

    with pytest.raises(oci.DigestMismatch):
        oci.Registry(oci.Reference.parse(registry.reference("acme/idx")), insecure=True).manifest()


def test_a_private_or_missing_repository_reads_as_such(registry, no_cosign):
    registry.challenge = True   # 401 for everything; the token does not help a 404
    client = oci.Registry(oci.Reference.parse(registry.reference("acme/absent")), insecure=True)

    with pytest.raises(oci.RegistryError, match="404"):
        client.manifest()


def test_the_client_never_reads_a_credential_store(registry, source):
    """Anonymous only: no `~/.docker/config.json`, no token from the environment.
    Pinned because the natural next feature — private mirrors — would add it, and
    §10 rules out a dependency on a token."""
    import inspect

    text = inspect.getsource(oci)
    assert "config.json" not in text
    assert "GITHUB_TOKEN" not in text and "environ" not in text


# ------------------------------------------------------------ fetch_published


def test_the_published_index_is_pulled_gunzipped_and_written_in_place(
    registry, source, tmp_path, tiny, no_cosign
):
    digest = registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"

    metadata = name_index.fetch_published(registry.reference("acme/idx"), cache)

    for filename in name_index.FILES.values():
        assert (cache / filename).read_bytes() == (source / filename).read_bytes()
    entry = metadata["ecosystems"]["cargo"]
    assert entry["built_at"] == "2026-09-12T02:00:00Z", "the workflow's build time, not now"
    assert entry["published"]["digest"] == digest
    assert entry["published"]["repository"] == f"{registry.host}/acme/idx"
    assert entry["published"]["signature"].startswith("not verified: cosign is not installed")
    with name_index.NameIndex(cache / "crates.txt") as crates:
        assert crates.contains("serde_json") and not crates.contains("serde-json")


def test_a_layer_larger_than_one_chunk_round_trips_byte_for_byte(
    registry, tmp_path, tiny, no_cosign
):
    """Found by `cmp` on the first real pull (34MB, 2026-09-12): every fragment of
    a name that straddled a 1MB chunk boundary was written twice, and the unit
    fixtures — five names, one chunk — could not see it. Two hundred thousand
    names compress to several chunks and every boundary lands mid-line."""
    import hashlib

    names = [f"pkg-{hashlib.sha256(str(i).encode()).hexdigest()[:20]}" for i in range(300_000)]
    source = write_name_index(tmp_path / "big", pip=names, built_at="2026-09-12T02:00:00Z")
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    raw, _ = registry.manifests["acme/idx:latest"]
    pypi = next(layer for layer in json.loads(raw)["layers"]
                if layer["annotations"]["org.opencontainers.image.title"] == "pypi.txt.gz")
    assert pypi["size"] > 2 * (1 << 20), "the fixture must span several chunks"

    name_index.fetch_published(registry.reference("acme/idx"), cache, ecosystems=("pip",))

    assert (cache / "pypi.txt").read_bytes() == (source / "pypi.txt").read_bytes()


def test_an_index_already_at_the_published_build_fetches_no_layer(
    registry, source, tmp_path, tiny, no_cosign
):
    """Two small requests decide it; the 40MB never moves. This is what makes a
    daily `valvur update` cost nothing on a current machine."""
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    name_index.fetch_published(registry.reference("acme/idx"), cache)
    registry.requests.clear()
    said: list[str] = []

    name_index.fetch_published(registry.reference("acme/idx"), cache, progress=said.append)

    blobs = [r for r in registry.requests if "/blobs/" in r]
    assert len(blobs) == 1, "only the config blob"
    assert any("nothing to fetch" in line for line in said)


def test_a_newer_published_build_replaces_only_what_changed(
    registry, source, tmp_path, tiny, no_cosign
):
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    name_index.fetch_published(registry.reference("acme/idx"), cache)
    # The workflow rebuilds PyPI only (say); the other files keep their stamp.
    meta = json.loads((source / "metadata.json").read_text())
    meta["ecosystems"]["pip"]["built_at"] = "2026-09-13T02:00:00Z"
    (source / "metadata.json").write_text(json.dumps(meta))
    (source / "pypi.txt").write_text("django\nflask\nrequests\n")
    registry.push_index("acme/idx", "latest", source)
    registry.requests.clear()

    name_index.fetch_published(registry.reference("acme/idx"), cache)

    assert (cache / "pypi.txt").read_text() == "django\nflask\nrequests\n"
    layers = [r for r in registry.requests if "/blobs/" in r]
    assert len(layers) == 2, "the config and the one changed layer"


def test_something_that_is_not_an_index_is_refused_by_type(registry, source, tmp_path, tiny):
    registry.push_index("acme/idx", "latest", source, artifact_type="application/vnd.other")

    with pytest.raises(name_index.IndexUnavailable, match="not a valvur name index"):
        name_index.fetch_published(registry.reference("acme/idx"), tmp_path / "cache")
    assert not (tmp_path / "cache" / "pypi.txt").exists()


def test_an_unsorted_published_file_is_refused_before_it_can_mislead_the_reader(
    registry, source, tmp_path, tiny, no_cosign
):
    """The reader bisects. A file out of order would answer "absent" for names it
    holds — every one a false hallucination — so order is checked as it streams."""
    (source / "pypi.txt").write_text("requests\nflask\n")
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"

    with pytest.raises(name_index.IndexUnavailable, match="not a sorted list"):
        name_index.fetch_published(registry.reference("acme/idx"), cache, ecosystems=("pip",))
    assert not (cache / "pypi.txt").exists() and not (cache / "pypi.txt.tmp").exists()


def test_a_published_file_below_the_floor_is_refused(registry, source, tmp_path, no_cosign):
    """A registry serving five names under a valid signature is still not PyPI."""
    registry.push_index("acme/idx", "latest", source)

    with pytest.raises(name_index.IndexUnavailable, match="far fewer"):
        name_index.fetch_published(registry.reference("acme/idx"), tmp_path / "cache",
                                   ecosystems=("pip",))


def test_a_tampered_layer_is_refused_and_nothing_is_written(
    registry, source, tmp_path, tiny, no_cosign
):
    registry.push_index("acme/idx", "latest", source)
    raw, _ = registry.manifests["acme/idx:latest"]
    pypi = next(layer for layer in json.loads(raw)["layers"]
                if layer["annotations"]["org.opencontainers.image.title"] == "pypi.txt.gz")
    registry.tamper[pypi["digest"]] = gzip.compress(b"a\nb\n")
    cache = tmp_path / "cache"

    with pytest.raises(name_index.IndexUnavailable, match="hashed to"):
        name_index.fetch_published(registry.reference("acme/idx"), cache, ecosystems=("pip",))
    assert not (cache / "pypi.txt").exists()


# ---------------------------------------------------------------- signatures


def test_with_cosign_installed_the_signature_is_verified_against_the_workflow_identity(
    registry, source, tmp_path, tiny, cosign
):
    log = cosign(exit_code=0)
    digest = registry.push_index("acme/idx", "latest", source)

    metadata = name_index.fetch_published(registry.reference("acme/idx"), tmp_path / "cache")

    args = log.read_text().split("\n")
    assert args[0] == "verify"
    assert args[1] == f"{registry.host}/acme/idx@{digest}", "the digest, never the tag"
    assert "--certificate-identity-regexp" in args
    assert args[args.index("--certificate-identity-regexp") + 1] == oci.SIGNING_IDENTITY
    assert args[args.index("--certificate-oidc-issuer") + 1] == oci.SIGNING_ISSUER
    assert "--allow-insecure-registry" in args, "the loopback registry is plain http"
    assert metadata["ecosystems"]["pip"]["published"]["signature"] == "verified"


def test_an_index_cached_without_cosign_is_verified_once_cosign_appears(
    registry, source, tmp_path, tiny, no_cosign, cosign
):
    """27.1.3, ADR-0018. The current-cache shortcut returned before the signature
    was ever checked, so an index pulled on a machine without cosign kept
    `"not verified: cosign is not installed"` for as long as that build stayed
    published — a trust state that could not improve by installing the tool it
    named. Now the same `update` that finds nothing to fetch verifies what is
    already on disk, by its recorded digest, with no layer moved."""
    digest = registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    first = name_index.fetch_published(registry.reference("acme/idx"), cache)
    assert first["ecosystems"]["pip"]["published"]["signature"].startswith("not verified")

    log = cosign(exit_code=0)                      # the user installs cosign
    registry.requests.clear()
    said: list[str] = []

    metadata = name_index.fetch_published(registry.reference("acme/idx"), cache,
                                          progress=said.append)

    for ecosystem in metadata["ecosystems"].values():
        assert ecosystem["published"]["signature"] == "verified"
    assert json.loads((cache / "metadata.json").read_text()) == metadata, \
        "the verdict has to survive the process that learned it"
    args = log.read_text().split("\n")
    assert args[1] == f"{registry.host}/acme/idx@{digest}", "the digest it recorded"
    assert [r for r in registry.requests if "/blobs/" in r] == \
        [r for r in registry.requests if "/blobs/" in r][:1], "only the config blob"
    assert not any("names, built" in line for line in said), "a layer was fetched"
    assert any("signature: verified" in line for line in said), said


def test_a_current_index_is_not_re_verified_when_cosign_is_still_absent(
    registry, source, tmp_path, tiny, no_cosign
):
    """The common case stays two requests and no work: nothing to fetch, nothing
    to re-check, and the metadata is not rewritten to say the same thing."""
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    name_index.fetch_published(registry.reference("acme/idx"), cache)
    stamp = (cache / "metadata.json").stat().st_mtime_ns
    said: list[str] = []

    name_index.fetch_published(registry.reference("acme/idx"), cache, progress=said.append)

    assert (cache / "metadata.json").stat().st_mtime_ns == stamp, "the metadata was rewritten"
    assert any("nothing to fetch" in line for line in said), said


def test_a_current_index_already_verified_is_not_verified_again(
    registry, source, tmp_path, tiny, cosign
):
    """cosign costs a Rekor round trip; a verdict already recorded for this digest
    stands until the digest changes."""
    log = cosign(exit_code=0)
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    name_index.fetch_published(registry.reference("acme/idx"), cache)
    log.unlink()

    name_index.fetch_published(registry.reference("acme/idx"), cache)

    assert not log.exists(), "cosign ran again for a signature already verified"


def test_a_cached_index_whose_signature_cosign_refuses_is_not_used(
    registry, source, tmp_path, tiny, no_cosign, cosign
):
    """The re-check is a real verification, so its refusal is the real refusal
    (`SignatureInvalid`, never softened) — and the files it refuses stay on disk
    untouched rather than being half-removed by a path that fetched nothing."""
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"
    name_index.fetch_published(registry.reference("acme/idx"), cache)
    before = (cache / "pypi.txt").read_bytes()
    cosign(exit_code=1)

    with pytest.raises(oci.SignatureInvalid, match="REFUSED"):
        name_index.fetch_published(registry.reference("acme/idx"), cache)
    assert (cache / "pypi.txt").read_bytes() == before


def test_a_refused_signature_stops_everything_and_writes_nothing(
    registry, source, tmp_path, tiny, cosign
):
    """The one failure that is never softened: not into the fallback walk, not
    into "not verified". cosign ran and said no."""
    cosign(exit_code=1)
    registry.push_index("acme/idx", "latest", source)
    cache = tmp_path / "cache"

    with pytest.raises(oci.SignatureInvalid, match="REFUSED"):
        name_index.fetch_published(registry.reference("acme/idx"), cache)
    assert not any(cache.glob("*.txt"))
    layers = [r for r in registry.requests if "/blobs/" in r]
    assert len(layers) == 1, "verified before a single layer was fetched"


def test_a_refused_signature_is_not_caught_by_refresh(registry, source, tmp_path, tiny,
                                                       cosign, monkeypatch):
    cosign(exit_code=1)
    registry.push_index("acme/idx", "latest", source)
    monkeypatch.setenv(name_index.INDEX_REPOSITORY_ENV, registry.reference("acme/idx"))
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)

    with pytest.raises(oci.SignatureInvalid):
        name_index.refresh(tmp_path / "cache")


def test_the_update_command_refuses_loudly_and_names_the_way_round(
    registry, source, tmp_path, tiny, cosign, monkeypatch, capsys
):
    from valvur import cache as _cache
    from valvur import cli

    cosign(exit_code=1)
    registry.push_index("acme/idx", "latest", source)
    monkeypatch.setenv(name_index.INDEX_REPOSITORY_ENV, registry.reference("acme/idx"))
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)
    monkeypatch.setattr(_cache, "root", lambda: tmp_path)
    monkeypatch.setattr(_cache, "name_index", lambda: tmp_path / "names")

    assert cli._refresh_name_index() is False
    out = capsys.readouterr().out
    assert "REFUSED" in out and "--build-index" in out


# ----------------------------------------------------------- the source order


def _recording_walk(walked: list):
    def walk(directory, *, ecosystems, progress, force):
        walked.append(ecosystems)
        return {}

    return walk



def test_the_published_index_is_tried_before_any_registry(
    registry, source, tmp_path, tiny, no_cosign, monkeypatch
):
    registry.push_index("acme/idx", "latest", source)
    monkeypatch.setenv(name_index.INDEX_REPOSITORY_ENV, registry.reference("acme/idx"))
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)
    monkeypatch.setattr(name_index, "walk", lambda *a, **k: pytest.fail("walked the registries"))

    name_index.refresh(tmp_path / "cache")

    assert (tmp_path / "cache" / "npm.txt").read_text() == "react\n"


def test_an_unreachable_default_repository_falls_back_to_the_walk(tmp_path, monkeypatch):
    """The published index is a shortcut, not a dependency: until the package is
    public — and on any day GHCR is down — the registries still answer."""
    monkeypatch.delenv(name_index.INDEX_REPOSITORY_ENV, raising=False)
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)
    walked: list[tuple] = []
    monkeypatch.setattr(name_index, "walk", _recording_walk(walked))
    said: list[str] = []

    name_index.refresh(tmp_path / "cache", progress=said.append)

    assert walked == [tuple(name_index.FILES)]
    assert any("unavailable" in line and "registries directly" in line for line in said)


def test_an_operator_named_mirror_that_fails_does_not_fall_back(tmp_path, monkeypatch):
    """Someone who set `VALVUR_INDEX_REPOSITORY` wants to hear that their mirror is
    broken, not watch valvur try the internet from inside their air gap."""
    monkeypatch.setenv(name_index.INDEX_REPOSITORY_ENV, "registry.internal/mirror/idx")
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)
    monkeypatch.setattr(name_index, "walk", lambda *a, **k: pytest.fail("walked the registries"))

    with pytest.raises(name_index.IndexUnavailable):
        name_index.refresh(tmp_path / "cache")


def test_build_index_walks_and_never_looks_at_the_registry(tmp_path, monkeypatch):
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)
    monkeypatch.setattr(name_index, "fetch_published",
                        lambda *a, **k: pytest.fail("pulled the published index"))
    walked: list[tuple] = []
    monkeypatch.setattr(name_index, "walk", _recording_walk(walked))

    name_index.refresh(tmp_path / "cache", published=False)

    assert walked == [tuple(name_index.FILES)]


def test_the_static_mirror_still_wins_over_everything(tmp_path, monkeypatch):
    monkeypatch.setenv(name_index.MIRROR_ENV, "http://mirror.internal/idx")
    monkeypatch.setenv(name_index.INDEX_REPOSITORY_ENV, "registry.internal/mirror/idx")
    seen: list[str] = []
    monkeypatch.setattr(name_index, "fetch_mirror",
                        lambda base, directory, **k: seen.append(base) or {})

    name_index.refresh(tmp_path / "cache")

    assert seen == ["http://mirror.internal/idx"]


def test_the_module_entry_point_builds_and_pulls(tmp_path, monkeypatch, registry, source,
                                                  tiny, no_cosign):
    """What the workflow runs: `build` walks, `pull` fetches with the same code
    every user's `valvur update` runs, so the round trip is proven before the tag
    moves."""
    registry.push_index("acme/idx", "latest", source)
    monkeypatch.setenv(name_index.INDEX_REPOSITORY_ENV, registry.reference("acme/idx"))

    assert name_index._main(["pull", str(tmp_path / "pulled")]) == 0
    assert (tmp_path / "pulled" / "rubygems.txt").read_text() == "rack\n"

    walked: list[tuple] = []
    monkeypatch.setattr(name_index, "walk", _recording_walk(walked))
    assert name_index._main(["build", str(tmp_path / "built"), "gem", "composer"]) == 0
    assert walked == [("gem", "composer")]
    assert name_index._main(["nonsense"]) == 2


# ------------------------------------------------ the three new registries (23.2.2, 23.2.3)


class _Canned:
    """`urlopen` serving one body per URL prefix, gzip-encoded on request."""

    def __init__(self, routes):
        self.routes = routes

    def __call__(self, request, timeout=None):
        url = request.full_url
        for prefix, body in self.routes.items():
            if url.startswith(prefix):
                return _Response(body if isinstance(body, bytes) else json.dumps(body).encode())
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)


class _Response(io.BytesIO):
    def __init__(self, body):
        super().__init__(body)
        self.headers = {}
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def test_rubygems_names_are_kept_exactly_as_spelled(monkeypatch):
    """`---` is YAML's document marker, not a gem. Case is identity on RubyGems."""
    monkeypatch.setattr(urllib.request, "urlopen", _Canned({
        name_index.RUBYGEMS_NAMES: b"---\n_\nRails\nrails\nrack\n",
    }))

    assert name_index.fetch_rubygems() == {"_", "Rails", "rails", "rack"}


def test_packagist_names_are_lowercase_vendor_slash_name(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _Canned({
        name_index.PACKAGIST_LIST: {"packageNames": ["Monolog/Monolog", "symfony/console", "php"]},
    }))

    assert name_index.fetch_packagist() == {"monolog/monolog", "symfony/console"}


def _crates_dump(names, *, readme_bytes=200_000) -> bytes:
    """A db-dump in the measured shape: README and SQL first, then `data/crates.csv`
    with a `name` column and a README field far past the csv module's default
    field limit, then megabytes of members that must never be read. Random text,
    because a compressible one would fit the whole archive in the first read."""
    import csv
    import secrets

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        def add(path, data: bytes):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        add("2026-09-12-020008/README.md", b"# dump\n")
        add("2026-09-12-020008/data/categories.csv", b"id,name\n1,x\n")
        rows = io.StringIO()
        writer = csv.writer(rows)
        writer.writerow(["created_at", "description", "id", "name", "readme", "updated_at"])
        for i, name in enumerate(names):
            readme = secrets.token_hex(readme_bytes // 2)
            writer.writerow(["2026-01-01", "d", str(i), name, readme, "2026-01-02"])
        add("2026-09-12-020008/data/crates.csv", rows.getvalue().encode())
        add("2026-09-12-020008/data/versions.csv", secrets.token_hex(2_000_000).encode())
    return buffer.getvalue()


def test_crates_are_streamed_out_of_the_dump_and_folded_to_canonical_form(monkeypatch):
    """Only the `name` column, only as far as `crates.csv`; a README field of
    200KB does not stop the reader. `serde-json` and `Serde` fold to what
    crates.io itself answers with."""
    read: list[int] = []

    class Counting(_Response):
        def read(self, n=-1):
            data = super().read(n)
            read.append(len(data))
            return data

    dump = _crates_dump(["serde", "serde-json", "Serde_Yaml", "tokio"])
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda request, timeout=None: Counting(dump))

    names = name_index.fetch_crates()

    assert names == {"serde", "serde_json", "serde_yaml", "tokio"}
    assert sum(read) < len(dump), "stopped before the members after crates.csv"


def test_a_dump_without_the_crate_list_is_named_as_such(monkeypatch):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("x/README.md")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"# "))
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda request, timeout=None: _Response(buffer.getvalue()))

    with pytest.raises(name_index.IndexUnavailable, match=r"crates\.csv"):
        name_index.fetch_crates()


def test_the_walk_covers_every_ecosystem_the_check_reads(monkeypatch, tmp_path, tiny):
    """`FILES` is the contract: an ecosystem listed there has a fetcher, or the walk
    would raise on the day someone adds the file name and forgets the source."""
    monkeypatch.setattr(name_index, "fetch_pypi", lambda progress=None: {"requests"})
    monkeypatch.setattr(name_index, "fetch_npm_full", lambda progress=None: ({"react"}, 1))
    monkeypatch.setattr(name_index, "fetch_rubygems", lambda progress=None: {"rack"})
    monkeypatch.setattr(name_index, "fetch_packagist", lambda progress=None: {"a/b"})
    monkeypatch.setattr(name_index, "fetch_crates", lambda progress=None: {"serde"})

    metadata = name_index.walk(tmp_path)

    assert set(metadata["ecosystems"]) == set(name_index.FILES)
    for ecosystem, filename in name_index.FILES.items():
        assert (tmp_path / filename).read_text().endswith("\n")
        assert metadata["ecosystems"][ecosystem]["source"].startswith("https://")


def test_a_registry_walked_today_is_not_walked_again_unless_forced(monkeypatch, tmp_path, tiny):
    """The fallback walk is 400MB. A CI job restoring yesterday's cache, or a user
    running `update` twice while GHCR is down, pays it once; `--build-index`
    (`force`) and the publishing workflow always walk."""
    from conftest import write_name_index

    calls: list[str] = []
    monkeypatch.setattr(name_index, "fetch_pypi",
                        lambda progress=None: calls.append("pip") or {"a"})
    monkeypatch.setattr(name_index, "fetch_rubygems",
                        lambda progress=None: calls.append("gem") or {"b"})
    write_name_index(tmp_path, pip=["x"], gem=["y"])       # built just now

    name_index.walk(tmp_path, ecosystems=("pip", "gem"))
    assert calls == []
    assert (tmp_path / "pypi.txt").read_text() == "x\n"

    name_index.walk(tmp_path, ecosystems=("pip", "gem"), force=True)
    assert calls == ["pip", "gem"]

    meta = json.loads((tmp_path / "metadata.json").read_text())
    meta["ecosystems"]["pip"]["built_at"] = "2026-01-01T00:00:00Z"
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    calls.clear()
    name_index.walk(tmp_path, ecosystems=("pip", "gem"))
    assert calls == ["pip"], "old enough is walked; fresh is not"


def test_build_index_forces_the_walk_and_the_fallback_does_not(tmp_path, monkeypatch):
    monkeypatch.delenv(name_index.MIRROR_ENV, raising=False)
    monkeypatch.delenv(name_index.INDEX_REPOSITORY_ENV, raising=False)
    seen: list[bool] = []
    monkeypatch.setattr(name_index, "walk",
                        lambda directory, *, ecosystems, progress, force: seen.append(force) or {})

    name_index.refresh(tmp_path, published=False)
    name_index.refresh(tmp_path)          # the default repository is unreachable here

    assert seen == [True, False]


def test_every_indexed_ecosystem_has_a_floor_and_a_registry_name():
    from valvur.checks.dependency_reality import _REGISTRY_NAME

    assert set(name_index.MINIMUM_NAMES) == set(name_index.FILES)
    assert set(name_index.FILES) <= set(_REGISTRY_NAME)


def test_the_index_directory_is_what_the_runner_mounts(monkeypatch):
    """`FILES` names are what land under `/cache/names`; the Check opens them by
    ecosystem. No other table maps one to the other."""
    from valvur.checks import dependency_reality as check

    monkeypatch.setenv(check.INDEX_ENV, "/somewhere")
    assert check._index_dir() == Path("/somewhere")
    assert name_index.open_index(Path("/nonexistent"), "gem") is None
    assert name_index.open_index(Path("/nonexistent"), "nuget") is None


def test_no_environment_token_reaches_the_registry(registry, source, tmp_path, tiny,
                                                    no_cosign, monkeypatch):
    """A `GITHUB_TOKEN` in the environment — every CI job has one — must not be
    sent anywhere by a tool whose promise is that nothing leaves the machine
    unasked. The only Authorization the registry ever sees is the anonymous pull
    token it handed out itself."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    registry.challenge = True
    registry.push_index("acme/idx", "latest", source)

    name_index.fetch_published(registry.reference("acme/idx"), tmp_path / "cache")

    assert set(registry.authorizations) == {None, "Bearer anonymous-pull-token"}
