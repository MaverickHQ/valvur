"""The Go Scanners, built from their release's source (D81w, the owner, 2026-10-31).

Gitleaks has been built from its release's Go module since 2026-10-25. On 2026-10-31 the
nightly blocked on 8 advisories in Trivy's, OSV-Scanner's and Syft's linked modules
(`golang.org/x/net` below 0.62.0, `go-jose/v4` below 4.1.6) that their projects had fixed
on their main branches and not released, and 44 more waited as acceptances. So each Go
Scanner's stage downloads its release's module, verified against Go's checksum database,
and builds it with the one current Go every Go stage shares, as upstream's release build
sets its flags and version. `<SCANNER>_RAISE` raises a linked module to an advisory's
fixed version, each at an exact version; the build refuses a raise the release already
requires, and one that would lower a module. The Scanner's own source is never changed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

#: Each Go Scanner's stage: its `ARG` prefix, its Go module, the package built, and the
#: version flags of upstream's release build (its goreleaser file at the tag).
GO_SCANNERS = {
    "trivy": ("TRIVY", "github.com/aquasecurity/trivy", "./cmd/trivy",
              "-s -w -X=github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}"),
    "gitleaks": ("GITLEAKS", "github.com/zricethezav/gitleaks/v8", ".",
                 "-X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}"),
    "syft": ("SYFT", "github.com/anchore/syft", "./cmd/syft",
             "-s -w -X=main.version=${SYFT_VERSION}"),
    "osv-scanner": ("OSV_SCANNER", "github.com/google/osv-scanner/v2", "./cmd/osv-scanner",
                    "-s -w -X=github.com/google/osv-scanner/v2/internal/version.OSVVersion="
                    "${OSV_SCANNER_VERSION}"),
}
#: `sum.golang.org/lookup/<module>@v<version>`, read 2026-10-31.
SUMS = {
    ("github.com/aquasecurity/trivy", "0.76.1"): "h1:xzXcxZpfkZpTxAHzfuG3KS5BRP17KG70+c0uFFwZUU4=",
    ("github.com/zricethezav/gitleaks/v8", "8.30.1"):
        "h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=",
    ("github.com/anchore/syft", "1.55.0"): "h1:IeBZJrF/g75ba3k0ITQ8v4NCVGiGsWU3Wa1P/eSAFa0=",
    ("github.com/google/osv-scanner/v2", "2.7.0"):
        "h1:7aOrJ9vB7qbzxC3R+QCXs03SHQiRuM80RJdqZhUEl2g=",
}
#: The binary each stage writes, and where the image installs it.
INSTALLED = {"trivy": ("/trivy", "/usr/local/bin/trivy"),
             "osv-scanner": ("/osv-scanner", "/usr/local/bin/osv-scanner"),
             "gitleaks": ("/gitleaks", "/usr/local/bin/gitleaks"),
             "syft": ("/syft", "/usr/local/bin/syft")}
#: How each binary says its version, and what it says for the version pinned.
SAYS = {"trivy": (["--version"], "Version: {}"),
        "osv-scanner": (["--version"], "osv-scanner version: {}"),
        "gitleaks": (["version"], "v{}"),
        "syft": (["version"], "Version:       {}")}
#: The upstream image each stage replaced.
UPSTREAM_IMAGES = {"trivy": "aquasec/trivy:", "osv-scanner": "ghcr.io/google/osv-scanner:",
                   "gitleaks": "zricethezav/gitleaks:", "syft": "anchore/syft:"}


def _dockerfile() -> str:
    return (REPO / "Dockerfile").read_text()


def _stage(name: str) -> str:
    text = _dockerfile()
    start = re.search(rf"^FROM \S+ AS {name}$", text, re.M)
    assert start, f"no stage named {name}"
    end = text.find("\nFROM ", start.end())
    return text[start.start():end]


def _arg(stage: str, name: str) -> str:
    match = re.search(rf'^ARG {name}="?([^"\n]*)"?$', stage, re.M)
    assert match, f"no ARG {name}"
    return match.group(1)


def _stage_of(tool: str) -> str:
    return "osv" if tool == "osv-scanner" else tool


@pytest.mark.parametrize("tool", sorted(GO_SCANNERS))
def test_each_is_its_release_s_module_verified_against_go_s_checksum_database(tool):
    prefix, module, _, _ = GO_SCANNERS[tool]
    stage = _stage(_stage_of(tool))
    version = _arg(stage, f"{prefix}_VERSION")

    assert re.match(r"FROM golang:\d+\.\d+\.\d+-alpine[\d.]+@sha256:[0-9a-f]{64} AS ", stage)
    assert _arg(stage, f"{prefix}_SUM") == SUMS[(module, version)]
    assert f'module="{module}@v${{{prefix}_VERSION}}"' in stage
    assert 'go mod download -json "$module" > /module.json' in stage
    assert f'grep -qF "\\"Sum\\": \\"${{{prefix}_SUM}}\\"" /module.json' in stage
    assert "ADD " not in stage


@pytest.mark.parametrize("tool", sorted(GO_SCANNERS))
def test_each_is_built_as_its_release_build_sets_its_flags_and_version(tool):
    _, _, package, ldflags = GO_SCANNERS[tool]
    stage = _stage(_stage_of(tool))
    built, _ = INSTALLED[tool]

    assert "CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build -trimpath " \
           "-buildvcs=false" in stage
    assert f'-ldflags="{ldflags}"' in stage
    assert re.search(rf"-o {re.escape(built)} {re.escape(package)};", stage)
    if tool == "syft":
        assert "-trimpath -buildvcs=false -tags=containers_image_openpgp," \
               "exclude_graphdriver_btrfs \\" in stage


@pytest.mark.parametrize("tool", sorted(GO_SCANNERS))
def test_each_raise_is_an_exact_version_and_the_build_refuses_a_stale_or_lower_one(tool):
    prefix = GO_SCANNERS[tool][0]
    stage = _stage(_stage_of(tool))
    raises = _arg(stage, f"{prefix}_RAISE").split()

    for raise_ in raises:
        assert re.fullmatch(r"[a-z0-9.\-]+(/[A-Za-z0-9.\-_]+)+@v\d+\.\d+\.\d+", raise_), raise_
    assert len({r.split("@")[0] for r in raises}) == len(raises), "a module raised twice"
    # A raise the release already requires is stale: its upgrade drops it.
    assert f'for raise in ${{{prefix}_RAISE}}; do' in stage
    assert ("test \"$(go list -m -f '{{.Version}}' \"${raise%@*}\")\" != \"${raise#*@}\"") \
        in stage
    assert f"go get ${{{prefix}_RAISE}} > /raise.log 2>&1" in stage
    assert "if grep -q downgraded /raise.log; then" in stage


def test_every_go_stage_builds_with_one_go_and_no_upstream_image_is_copied():
    text = _dockerfile()
    gos = set(re.findall(r"^FROM (golang:\S+) AS \S+$", text, re.M))

    assert len(gos) == 1, sorted(gos)
    for tool in GO_SCANNERS:
        built, installed = INSTALLED[tool]
        assert re.search(rf"^COPY --from={_stage_of(tool)} +{re.escape(built)} +"
                         rf"{re.escape(installed)}$", text, re.M)
        assert UPSTREAM_IMAGES[tool] not in text, f"{UPSTREAM_IMAGES[tool]} is still a stage"


@pytest.mark.e2e
@pytest.mark.parametrize("tool", sorted(GO_SCANNERS))
def test_each_says_its_release_s_version_and_links_its_raised_modules(tool):
    import scanner_upgrade

    from valvur.engine_host import IMAGE

    prefix = GO_SCANNERS[tool][0]
    stage = _stage(_stage_of(tool))
    version = _arg(stage, f"{prefix}_VERSION")
    args, said = SAYS[tool]
    out = subprocess.run(["docker", "run", "--rm", "--entrypoint", tool, IMAGE, *args],
                         capture_output=True, text=True, check=True).stdout
    assert said.format(version) in out
    go = re.search(r"^FROM golang:(\d+\.\d+\.\d+)", stage, re.M)
    assert go
    assert scanner_upgrade.image_toolchain(tool, IMAGE) == f"go{go[1]}"
    modules = scanner_upgrade.image_modules(tool, IMAGE)
    for raise_ in _arg(stage, f"{prefix}_RAISE").split():
        name, at = raise_.split("@")
        assert modules.get(name) == at, f"{tool} links {name} {modules.get(name)}, not {at}"


def _uvarint(n: int) -> bytes:
    out = b""
    while True:
        byte, n = n & 0x7F, n >> 7
        out += bytes([byte | (0x80 if n else 0)])
        if not n:
            return out


def test_a_binary_s_linked_modules_are_read_from_its_build_information(tmp_path):
    """What `go version -m` lists as `dep`, and a `=>` replacement in place of the module it
    replaces; the module information sits between two 16-byte markers, after the Go."""
    import scanner_upgrade

    header = b"\xff Go buildinf:" + bytes([8, 2])
    header += b"\x00" * (32 - len(header))
    toolchain = b"go1.27.3"
    mod = (bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
           + b"path\tgithub.com/aquasecurity/trivy/cmd/trivy\n"
             b"mod\tgithub.com/aquasecurity/trivy\t(devel)\t\n"
             b"dep\tgolang.org/x/net\tv0.62.0\th1:18EL=\n"
             b"dep\tgithub.com/a/b\tv1.0.0\n=>\tgithub.com/c/b\tv1.1.0\th1:x=\n"
             b"build\tCGO_ENABLED=0\n"
           + bytes.fromhex("f932433186182072008242104116d8f2"))
    binary = tmp_path / "trivy"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60 + header + _uvarint(len(toolchain)) + toolchain
                       + _uvarint(len(mod)) + mod + b"\x00" * 64)

    assert scanner_upgrade.go_modules(binary) == {"golang.org/x/net": "v0.62.0",
                                                  "github.com/a/b": "v1.1.0"}
    (tmp_path / "opengrep").write_bytes(b"\x7fELF" + b"\x00" * 200)
    assert scanner_upgrade.go_modules(tmp_path / "opengrep") == {}
