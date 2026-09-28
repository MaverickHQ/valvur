"""R8.3: a mirror in the customer's own registry (ECR, stood in for by `registry:2`).

The image, the vulnerability database and the name index are copied into a registry
of the customer's; KEV and OSV's databases are files on a server of theirs. The
machine that scans sits on a network with no route out, pulls the image from the
mirror, fetches from the mirrors alone, and its record says nothing left.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
import urllib.request
import uuid

import pytest

#: `registry:2`, by digest.
REGISTRY_IMAGE = "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
DB_SOURCE = "mirror.gcr.io/aquasec/trivy-db:2"
INDEX_SOURCE = "ghcr.io/maverickhq/valvur-index:latest"


def _upload(host: str, name: str, digest: str, data, size: int | None = None) -> None:
    """One blob, by the registry API's monolithic upload; `data` bytes or a file."""
    start = urllib.request.Request(f"http://{host}/v2/{name}/blobs/uploads/", data=b"",
                                   method="POST")
    with urllib.request.urlopen(start, timeout=60) as response:  # noqa: S310 — local registry
        location = response.headers["Location"]
    if location.startswith("/"):
        location = f"http://{host}{location}"
    joiner = "&" if "?" in location else "?"
    headers = {"Content-Type": "application/octet-stream"}
    if size is not None:
        headers["Content-Length"] = str(size)
    put = urllib.request.Request(  # noqa: S310 — the local registry's upload URL
        f"{location}{joiner}digest={digest}", data=data, method="PUT", headers=headers)
    urllib.request.urlopen(put, timeout=900).close()  # noqa: S310


def _push_saved(archive, host: str, name: str, tag: str) -> str:
    """An image `docker save` wrote as an OCI layout, pushed blob by blob, streamed;
    the daemon is not asked, since Docker Desktop's cannot reach the host's
    loopback. Returns the manifest's digest."""
    import tarfile

    with tarfile.open(archive) as layout:
        def member(digest: str):
            return layout.getmember(f"blobs/sha256/{digest.split(':', 1)[1]}")

        def read(digest: str) -> bytes:
            return layout.extractfile(member(digest)).read()

        names = set(layout.getnames())
        described = json.loads(layout.extractfile("index.json").read())["manifests"][0]
        body = json.loads(read(described["digest"]))
        while "manifests" in body:
            # An index: the one platform whose manifest was saved.
            described = next(m for m in body["manifests"]
                             if f"blobs/sha256/{m['digest'].split(':', 1)[1]}" in names
                             and m.get("platform", {}).get("os") != "unknown")
            body = json.loads(read(described["digest"]))
        for blob in [body["config"], *body["layers"]]:
            found = member(blob["digest"])
            _upload(host, name, blob["digest"], layout.extractfile(found), found.size)
        raw = read(described["digest"])
    put = urllib.request.Request(f"http://{host}/v2/{name}/manifests/{tag}", data=raw,
                                 method="PUT", headers={"Content-Type": described["mediaType"]})
    urllib.request.urlopen(put, timeout=60).close()  # noqa: S310
    return described["digest"]


def _copy(source: str, host: str, name: str, tag: str) -> None:
    """An OCI artifact, pulled anonymously as valvur pulls, pushed to `host`."""
    from valvur import oci

    registry = oci.Registry(oci.Reference.parse(source))
    manifest = registry.manifest()
    assert "manifests" not in manifest.body, f"{source} is an index, not one artifact"
    for described in [manifest.body["config"], *manifest.body.get("layers", [])]:
        data = registry.blob_bytes(described["digest"], size=described.get("size"))
        _upload(host, name, described["digest"], data)
    put = urllib.request.Request(f"http://{host}/v2/{name}/manifests/{tag}", data=manifest.raw,
                                 method="PUT", headers={"Content-Type": manifest.media_type})
    urllib.request.urlopen(put, timeout=60).close()  # noqa: S310


@pytest.fixture
def network(monkeypatch):
    """The copy reaches the public registries, as an operator's mirror job does; the
    unit suite's refusal (conftest) is lifted for this test alone."""
    import conftest

    monkeypatch.setattr(urllib.request, "urlopen", conftest.REAL_URLOPEN)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", conftest.REAL_OPENER_OPEN)


def _fetch(url: str, dest) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=600) as response, open(dest, "wb") as out:  # noqa: S310
        shutil.copyfileobj(response, out)


@pytest.mark.e2e
def test_a_mirror_in_the_customers_registry_serves_a_scan_that_sends_nothing(mountable_tmp,
                                                                              network):
    from valvur import osv_offline
    from valvur.enrichment import KEV_URL
    from valvur.runner import IMAGE, detect_runtime
    from valvur.version import __version__

    runtime = detect_runtime()
    tag = uuid.uuid4().hex[:8]
    outside, inside = f"valvur-push-{tag}", f"valvur-vpc-{tag}"
    registry, files = f"valvur-registry-{tag}", f"valvur-files-{tag}"

    def docker(*argv: str, check: bool = True, timeout: int = 900):
        done = subprocess.run([runtime, *argv], capture_output=True, text=True,
                              timeout=timeout, check=False)
        assert done.returncode == 0 or not check, f"{argv}: {done.stdout}{done.stderr}"
        return done

    checkout = mountable_tmp / "checkout"
    checkout.mkdir()
    (checkout / "app.py").write_text("print('hello')\n")
    (checkout / "requirements.txt").write_text("six==1.16.0\n")
    (checkout / "LICENSE").write_text("MIT License\n\nPermission is hereby granted, free of "
                                      "charge, to any person obtaining a copy.\n")
    served, cache_dir, out = mountable_tmp / "files", mountable_tmp / "cache", mountable_tmp / "out"
    cache_dir.mkdir()
    out.mkdir()
    user = [] if platform.system() == "Darwin" else ["--user", f"{os.getuid()}:{os.getgid()}"]
    mirrored = None
    try:
        docker("network", "create", outside)
        docker("network", "create", "--internal", inside)
        docker("run", "-d", "--name", registry, "--network", outside,
               "-p", "127.0.0.1::5000", REGISTRY_IMAGE)
        docker("network", "connect", inside, registry)
        published = docker("port", registry, "5000/tcp").stdout.split()[0]
        host = "127.0.0.1:" + published.rsplit(":", 1)[1]
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://{host}/v2/", timeout=2).close()
                break
            except OSError:
                time.sleep(0.2)

        # Into the customer's registry: the image, the database and the index.
        from valvur import oci

        saved = mountable_tmp / "image.tar"
        docker("save", IMAGE, "-o", str(saved))
        pushed = _push_saved(saved, host, "valvur", __version__)
        saved.unlink()
        served_manifest = oci.Registry(oci.Reference.parse(f"{host}/valvur:{__version__}"),
                                       insecure=True).manifest()
        assert served_manifest.digest == pushed
        _copy(DB_SOURCE, host, "trivy-db", "2")
        _copy(INDEX_SOURCE, host, "valvur-index", "latest")
        # And onto a file server of theirs: KEV, and OSV's database for PyPI.
        _fetch(KEV_URL, served / "kev.json")
        held = osv_offline.path("PyPI")
        if held.is_file():
            (served / "osv" / "PyPI").mkdir(parents=True)
            shutil.copy(held, served / "osv" / "PyPI" / "all.zip")
        else:
            _fetch(f"{osv_offline.DEFAULT_URL}/PyPI/all.zip", served / "osv" / "PyPI" / "all.zip")
        docker("run", "-d", "--name", files, "--network", inside, "-v", f"{served}:/srv:ro",
               "--entrypoint", "python3", IMAGE, "-m", "http.server", "8000", "--directory", "/srv")

        # The machine that scans: the image from the mirror where the daemon can
        # reach it (Linux; Docker Desktop's daemon cannot reach the host's loopback,
        # and there the copy is the one verified by digest above), and no route out.
        image = IMAGE
        if platform.system() != "Darwin":
            mirrored = f"{host}/valvur:{__version__}"
            docker("pull", mirrored)
            image = mirrored
        settings = ["-e", f"VALVUR_DB_REPOSITORY={registry}:5000/trivy-db:2",
                    "-e", "VALVUR_DB_INSECURE=1",
                    "-e", f"VALVUR_INDEX_REPOSITORY={registry}:5000/valvur-index:latest",
                    "-e", "VALVUR_INDEX_INSECURE=1",
                    "-e", f"VALVUR_KEV_URL=http://{files}:8000/kev.json",
                    "-e", f"VALVUR_OSV_URL=http://{files}:8000/osv",
                    "-e", "VALVUR_CACHE=/cache", "-v", f"{cache_dir}:/cache/valvur",
                    "-v", f"{checkout}:/src:ro"]
        update = docker("run", "--rm", "--network", inside, *user, *settings, image,
                        "valvur", "update", "/src", check=False)
        assert update.returncode == 0, update.stdout + update.stderr
        scan = docker("run", "--rm", "--network", inside, *user, *settings,
                      "-v", f"{out}:/out", image, "valvur", "scan", "/src", "--out", "/out",
                      check=False)
        assert scan.returncode == 0, scan.stdout + scan.stderr
    finally:
        docker("rm", "-f", registry, files, check=False)
        docker("network", "rm", inside, outside, check=False)
        if mirrored:
            docker("rmi", mirrored, check=False)

    run = json.loads((out / ".security-scan" / "run.json").read_text())
    assert run["network"]["what_left_the_machine"] == "nothing"
    assert run["network"]["fetched"] == []
    assert run["complete"] is True, run.get("status_reason")
    assert run["status"] == "clean", run.get("status_reason")
    listed = docker("ps", "-a", "--filter", f"name={tag}", "--format", "{{.Names}}").stdout
    assert listed.strip() == "", listed
