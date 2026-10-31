"""Gitleaks, built from its source with a current Go (the owner, 2026-10-25).

Gitleaks' last release, 8.30.1 (2026-03-12), ships a binary built with go1.24.13, which Go
stopped supporting when go1.26 was released; R43.4's image gate counted 69 findings in it,
most in that standard library. Its project has published nothing since (R47.1). So the image
builds the same release from its source: the tag's commit, `83d9cd6`, which is what the
published binary was built from (its build information says so; the Go module proxy still
serves `8d1f98c`, the commit the tag named before it moved), as a source archive pinned by
sha256, with `CGO_ENABLED=0 go build -trimpath` and fixed `-ldflags` that set its version.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
#: `sum.golang.org/lookup/github.com/zricethezav/gitleaks/v8@v8.30.1`, read 2026-10-25.
SUM = "h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w="


def _stage() -> str:
    text = (REPO / "Dockerfile").read_text()
    start = re.search(r"^FROM \S+ AS gitleaks$", text, re.M)
    assert start, "no stage named gitleaks"
    end = text.find("\nFROM ", start.end())
    return text[start.start():end]


def test_the_stage_builds_8_30_1_from_its_tag_s_commit_with_a_current_go():
    stage = _stage()

    base = re.match(r"FROM golang:(\d+\.\d+\.\d+)-alpine[\d.]+@sha256:[0-9a-f]{64} AS gitleaks",
                    stage)
    assert base, stage.splitlines()[0]
    assert re.search(r"^ARG GITLEAKS_VERSION=8\.30\.1$", stage, re.M)
    assert re.search(rf"^ARG GITLEAKS_SUM={re.escape(SUM)}$", stage, re.M)
    assert 'go mod download -json "$module"' in stage
    assert 'grep -qF "\\"Sum\\": \\"${GITLEAKS_SUM}\\"" /module.json' in stage
    assert "ADD " not in stage
    assert "CGO_ENABLED=0" in stage and "go build -trimpath" in stage
    assert "-buildvcs=false" in stage and "GOTOOLCHAIN=local" in stage
    assert ('-ldflags="-X=github.com/zricethezav/gitleaks/v8/version.Version='
            'v${GITLEAKS_VERSION}"') in stage
    assert "zricethezav/gitleaks:" not in (REPO / "Dockerfile").read_text()


@pytest.mark.e2e
def test_it_reports_8_30_1_and_its_build_names_the_go_that_built_it():
    import sys

    sys.path.insert(0, str(REPO / "scripts"))
    import scanner_upgrade

    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import IMAGE

    said = subprocess.run(["docker", "run", "--rm", "--entrypoint", "gitleaks", IMAGE,
                           "version"], capture_output=True, text=True, check=True).stdout
    assert said.strip() == "v8.30.1"
    assert GitleaksAdapter().version == "8.30.1"
    go = re.match(r"FROM golang:(\d+\.\d+)\.(\d+)", _stage())
    assert go
    assert scanner_upgrade.image_toolchain("gitleaks", IMAGE) == f"go{go[1]}.{go[2]}"


#: What the upstream 8.30.1 binary (`zricethezav/gitleaks:v8.30.1`) found on each fixture,
#: through the adapter's own command, recorded on 2026-10-25 before the stage moved.
UPSTREAM = {"broken-repo": [("aws-access-token", "/workspace/config.py", 9),
                            ("generic-api-key", "/workspace/config.py", 10)],
            "clean-repo": [], "monorepo": [], "workflows-repo": [], "dependency-reality": []}


@pytest.mark.e2e
@pytest.mark.parametrize("fixture", sorted(UPSTREAM))
def test_on_its_fixtures_it_finds_what_the_published_binary_found(fixture, mountable_tmp):
    import json

    from fixture_copy import copy_fixture

    from valvur import fileset
    from valvur.adapters import GitleaksAdapter
    from valvur.engine_host import ContainerRuntime, snapshot

    workspace = copy_fixture(REPO / "tests" / "fixtures" / fixture, mountable_tmp / "ws")
    scratch = mountable_tmp / "scratch"
    scratch.mkdir()
    invocation = GitleaksAdapter().command(workspace)
    ContainerRuntime().run([invocation], snapshot(workspace, fileset.build(workspace).files),
                           scratch)
    report = scratch / (invocation.report or "gitleaks.stdout")
    found = sorted((f["RuleID"], f["File"], f["StartLine"])
                   for f in json.loads(report.read_text() or "[]"))

    assert found == UPSTREAM[fixture]


def test_dependabot_s_docker_ecosystem_tracks_the_go_base():
    """Dependabot moves every `FROM name:tag@sha256:…` in the root Dockerfile, a new digest
    of a tag as well as a new tag, after the week's cooldown, unless an `ignore` names it.
    So the Go that builds Gitleaks is followed like every other base, and none ignores it."""
    config = (REPO / ".github" / "dependabot.yml").read_text()
    blocks = re.split(r"\n  - package-ecosystem: ", config)
    [docker] = [b for b in blocks if b.startswith("docker\n    directory: /\n")]

    assert "default-days: 7" in docker
    assert not re.search(r'dependency-name: "?golang', docker)
    assert re.match(r"FROM golang:\d+\.\d+\.\d+-alpine\d+\.\d+@sha256:[0-9a-f]{64} AS gitleaks$",
                    _stage().splitlines()[0])


@pytest.mark.e2e
def test_the_image_gate_finds_no_standard_library_advisory_in_it(tmp_path):
    """R43.4's gate counted 68 blocking findings in the published binary on 2026-10-25
    (69 the day before), 43 of them in go1.24.13's standard library. Built with a current
    Go, none of those is left. What remained was in the module's own pinned dependencies,
    which `GITLEAKS_RAISE` raises since D81w (`test_scanners_from_source.py`)."""
    import json

    from valvur.engine_host import IMAGE

    database = Path(__import__("valvur.cache", fromlist=["root"]).root()) / "trivy"
    scan = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{database}:/db:ro",
         "--entrypoint", "trivy", IMAGE, "rootfs", "--cache-dir", "/db", "--cache-backend",
         "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--format",
         "json", "--scanners", "vuln", "--quiet", "/usr/local/bin/gitleaks"],
        capture_output=True, text=True, check=True).stdout
    found = [v for r in json.loads(scan).get("Results") or []
             for v in r.get("Vulnerabilities") or []]

    assert found, "the scan read no module from the binary"
    stdlib = [v["VulnerabilityID"] for v in found
              if v["PkgName"] == "stdlib" and v.get("FixedVersion")]
    assert stdlib == []
