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
