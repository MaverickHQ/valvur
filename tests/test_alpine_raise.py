"""Alpine packages raised past the base (the owner, 2026-11-21).

On 2026-11-19 the image gate blocked on 22 advisories, the same on both architectures
(run 44475786283): 21 in krb5-libs 1.22.2-r1, fixed in 1.22.3-r0, and CVE-2026-4738 in zlib
1.3.2-r1, fixed in 1.4-r0. Alpine 3.24's repository held both fixed versions, and no
`python:3.12-alpine3.24` digest carried them: the tag last moved on 2026-11-12. So the final
stage's `ALPINE_RAISE` raises a package of the base to an advisory's fixed version, each at
an exact version, as `<SCANNER>_RAISE` raises a Go module (D81w). The build refuses a raise
the base already carries, so a moved base drops it, and one for a package the base lacks.

On 2026-11-21 the gate on that raise's own pull request (run 44893108886) blocked on ten
more: five advisories in OpenSSL 3.5.9-r0, each in libcrypto3 and libssl3, fixed in 3.5.9-r1,
which Alpine built on 2026-11-19. They are raised the same way.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INSTALLED = "/lib/apk/db/installed"
CACHE = "/var/cache/apk"
EXACT_RAISE = re.compile(r"[a-z0-9][a-z0-9+._-]*=\d[0-9a-z._]*-r\d+")

#: The image gate's 22 on #294's branch, run 44475786283 (2026-11-19), on both architectures.
KRB5 = {"CVE-2026-107364", "CVE-2026-107708", "CVE-2026-107778", "CVE-2026-107884",
        "CVE-2026-111423", "CVE-2026-112314", "CVE-2026-112315", "CVE-2026-112316",
        "CVE-2026-112317", "CVE-2026-112318", "CVE-2026-112319", "CVE-2026-112320",
        "CVE-2026-112321", "CVE-2026-112322", "CVE-2026-112323", "CVE-2026-118380",
        "CVE-2026-119079", "CVE-2026-40355", "CVE-2026-40356", "CVE-2026-71199",
        "CVE-2026-71200"}
ZLIB = {"CVE-2026-4738"}
#: Its ten on the raise's own pull request, run 44893108886 (2026-11-21): each of the five in
#: both of OpenSSL's packages.
OPENSSL = {"CVE-2026-88822", "CVE-2026-88823", "CVE-2026-95691", "CVE-2026-95692",
           "CVE-2026-107496"}


def _final_stage() -> str:
    text = (REPO / "Dockerfile").read_text()
    return text[text.rindex("\nFROM "):]


def _raises() -> list[str]:
    match = re.search(r'^ARG ALPINE_RAISE="([^"\n]*)"$', _final_stage(), re.M)
    assert match, "no ARG ALPINE_RAISE in the final stage"
    return match.group(1).split()


def _step() -> str:
    """The `RUN` after `ARG ALPINE_RAISE`, as the shell receives it."""
    stage = _final_stage()
    rest = stage[stage.index("ARG ALPINE_RAISE="):]
    run = rest[rest.index("\nRUN ") + len("\nRUN "):]
    lines = []
    for line in run.splitlines():
        lines.append(line.removesuffix("\\"))
        if not line.endswith("\\"):
            break
    return "".join(lines)


def test_each_raise_is_one_package_at_one_exact_version():
    raises = _raises()

    for raise_ in raises:
        assert EXACT_RAISE.fullmatch(raise_), raise_
    assert len({r.split("=")[0] for r in raises}) == len(raises), "a package raised twice"
    assert not EXACT_RAISE.fullmatch("zlib")
    assert not EXACT_RAISE.fullmatch("zlib>=1.4-r0")
    assert not EXACT_RAISE.fullmatch("zlib=~1.4")


def test_the_raise_is_one_transaction_before_any_other_package_is_installed():
    code = "\n".join(line for line in _final_stage().splitlines()
                     if not line.lstrip().startswith("#"))

    raised = code.index("apk add --no-logfile --no-cache ${ALPINE_RAISE}")
    assert code.count("${ALPINE_RAISE}") == 2, "the loop that checks, and the one transaction"
    assert raised < code.index("apk add --no-logfile --no-cache --virtual .build")
    assert raised < code.index("COPY --from=")


def _build(tmp_path: Path, installed: dict[str, str], compares: str,
           raises: str = "krb5-libs=1.22.3-r0 zlib=1.4-r0") -> subprocess.CompletedProcess[str]:
    """The Dockerfile's own step, run against a stand-in for the base: its package
    database, its cache, and an `apk` that answers `version -t` with `compares`, and
    records any other call and leaves an index in the cache, as apk-tools 3 does."""
    cache = tmp_path / "cache"
    cache.mkdir()
    database = tmp_path / "installed"
    database.write_text("".join(f"C:Q1x\nP:{name}\nV:{version}\nA:aarch64\n\n"
                                for name, version in installed.items()))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    apk = bin_ / "apk"
    apk.write_text('#!/bin/sh\n'
                   'if [ "$1" = version ]; then echo "$COMPARES"; exit 0; fi\n'
                   f'echo "$@" >> "{tmp_path}/apk.calls"\n'
                   f'touch "{cache}/APKINDEX.5773bea6.tar.gz"\n')
    apk.chmod(0o755)
    step = _step()
    assert INSTALLED in step
    return subprocess.run(
        ["sh", "-c", step.replace(INSTALLED, str(database)).replace(CACHE, str(cache))],
        capture_output=True, text=True,
        env={"PATH": f"{bin_}:{os.environ['PATH']}", "ALPINE_RAISE": raises,
             "COMPARES": compares})


def test_a_package_the_base_holds_below_its_fixed_version_is_raised_to_it(tmp_path):
    built = _build(tmp_path, {"musl": "1.2.5-r21", "krb5-libs": "1.22.2-r1",
                              "zlib": "1.3.2-r1"}, "<")

    assert built.returncode == 0, built.stderr
    assert (tmp_path / "apk.calls").read_text().splitlines() == [
        "add --no-logfile --no-cache krb5-libs=1.22.3-r0 zlib=1.4-r0"]
    assert list((tmp_path / "cache").iterdir()) == [], "the index apk cached stays in the layer"


@pytest.mark.parametrize("compares", ["=", ">"])
def test_the_build_refuses_a_raise_the_base_already_carries(tmp_path, compares):
    built = _build(tmp_path, {"krb5-libs": "1.22.3-r0", "zlib": "1.4-r0"}, compares)

    assert built.returncode == 1
    assert ("the base already carries krb5-libs 1.22.3-r0: "
            "drop krb5-libs=1.22.3-r0 from ALPINE_RAISE") in built.stderr
    assert not (tmp_path / "apk.calls").exists(), "nothing is installed by a refused build"


def test_the_build_refuses_a_raise_of_a_package_the_base_lacks(tmp_path):
    built = _build(tmp_path, {"krb5-libs": "1.22.2-r1", "zlib-dev": "1.3.2-r1"}, "<")

    assert built.returncode == 1
    assert "the base has no zlib: drop zlib=1.4-r0 from ALPINE_RAISE" in built.stderr
    assert not (tmp_path / "apk.calls").exists()


def _image() -> str:
    from valvur.engine_host import IMAGE

    return IMAGE


@pytest.mark.e2e
def test_the_image_holds_each_raised_package_at_its_exact_version():
    probe = ("import json; blocks = open('/lib/apk/db/installed').read().split('\\n\\n'); "
             "print(json.dumps({l[0][2:]: l[1][2:] for l in "
             "([x for x in b.splitlines() if x[:2] in ('P:', 'V:')] for b in blocks) "
             "if len(l) == 2}))")
    said = subprocess.run(["docker", "run", "--rm", _image(), "python3", "-c", probe],
                          capture_output=True, text=True, check=True).stdout
    installed = json.loads(said)

    assert len(installed) > 10, "the package database listed next to nothing"
    for raise_ in _raises():
        name, version = raise_.split("=")
        assert installed.get(name) == version, raise_


@pytest.mark.e2e
def test_the_image_gate_finds_none_of_the_32_in_krb5_libs_zlib_and_openssl():
    from valvur import cache

    database = cache.root() / "trivy"
    scan = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{database}:/db:ro",
         "--entrypoint", "trivy", _image(), "rootfs", "--cache-dir", "/db", "--cache-backend",
         "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--format",
         "json", "--scanners", "vuln", "--quiet", "/"],
        capture_output=True, text=True, check=True).stdout
    found = {(v["VulnerabilityID"], v["PkgName"]) for r in json.loads(scan).get("Results") or []
             for v in r.get("Vulnerabilities") or []}

    assert len(KRB5) == 21
    assert not {(i, "krb5-libs") for i in KRB5} & found
    assert not {(i, "zlib") for i in ZLIB} & found
    assert not {(i, package) for i in OPENSSL for package in ("libcrypto3", "libssl3")} & found
