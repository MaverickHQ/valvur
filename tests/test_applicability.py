"""Gating Checkov on infrastructure being present (task 12a.3).

Checkov costs 11.2s of fixed startup — measured 2026-09-05, more than every other
Scanner in `offline` combined. Skipping it takes a repository with no infrastructure
from 20.3s to 7.1s.

The risk is worse than the cost, which is why every test here has a partner. A
conditional Scanner is one that can silently stop running, and a detector that had
rotted to always-False would sail through a suite that only tested the skip.
"""

from __future__ import annotations

import json

import pytest

from valvur.applicability import iac_present


def _repo(root, files: dict[str, str]):
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


# ------------------------------------------------- infrastructure IS recognised

@pytest.mark.parametrize("name,body", [
    ("main.tf", 'resource "aws_s3_bucket" "b" {}'),
    ("variables.tfvars", 'region = "eu-west-2"'),
    ("Dockerfile", "FROM alpine\n"),
    ("Dockerfile.prod", "FROM alpine\n"),
    ("docker-compose.yml", "services:\n  web:\n    image: nginx\n"),
    ("serverless.yml", "service: api\n"),
    ("Chart.yaml", "name: app\n"),
    ("kustomization.yaml", "resources: []\n"),
    ("main.bicep", "param location string\n"),
    (".gitlab-ci.yml", "stages: [build]\n"),
    (".github/workflows/ci.yml", "on: push\njobs: {}\n"),
    (".circleci/config.yml", "version: 2.1\n"),
])
def test_infrastructure_by_name_is_recognised(tmp_path, name, body):
    """Names and suffixes that are infrastructure beyond argument."""
    assert iac_present(_repo(tmp_path, {name: body}))[0]


@pytest.mark.parametrize("name,body", [
    ("deploy/app.yaml", "apiVersion: apps/v1\nkind: Deployment\n"),
    ("stack.yaml", "AWSTemplateFormatVersion: '2010-09-09'\n"),
    ("cfn.json", '{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}'),
    ("api.yaml", "openapi: 3.0.0\n"),
    ("legacy.yaml", "swagger: '2.0'\n"),
])
def test_infrastructure_by_content_is_recognised(tmp_path, name, body):
    """Checkov's kubernetes, cloudformation and openapi runners act on files with no
    distinguishing name — deploy/app.yaml is a manifest or a CI config depending
    only on its contents."""
    assert iac_present(_repo(tmp_path, {name: body}))[0]


def test_the_evidence_names_the_file_that_decided_it():
    """"We skipped Checkov" is a claim the reader should be able to check."""
    from pathlib import Path

    found, evidence = iac_present(Path("tests/fixtures/broken-repo"))

    assert found
    assert evidence == "main.tf"


# ----------------------------------------------------- and code is NOT mistaken

def test_a_repository_of_plain_code_has_no_infrastructure(tmp_path):
    _repo(tmp_path, {
        "app.py": "import os\n",
        "requirements.txt": "flask==3.0.0\n",
        "package.json": json.dumps({"name": "x", "dependencies": {"left-pad": "1.0"}}),
        "README.md": "# hi\n",
        "data.json": json.dumps({"users": [{"name": "a"}]}),
        "config.yaml": "database:\n  host: localhost\n",
    })

    assert not iac_present(tmp_path)[0]


def test_a_vendored_manifest_does_not_trigger_a_scan(tmp_path):
    """node_modules routinely ships Dockerfiles. Findings there are dropped anyway,
    so paying 11 seconds to produce them would be pure waste."""
    _repo(tmp_path, {"node_modules/pkg/Dockerfile": "FROM alpine\n", "app.py": "x = 1\n"})

    assert not iac_present(tmp_path)[0]


# --------------------------------------------------- unresolved cases still scan

def test_an_unreadable_file_counts_as_infrastructure(tmp_path, monkeypatch):
    """Rule 1: bias to running. We cannot tell what the file holds, so we scan."""
    from pathlib import Path

    _repo(tmp_path, {"maybe.yaml": "irrelevant\n"})

    def boom(self, *a, **k):
        raise OSError("unreadable")

    monkeypatch.setattr(Path, "read_text", boom)

    assert iac_present(tmp_path)[0]


# ------------------------------------------------------- the skip is never silent

def test_the_adapter_skips_only_when_nothing_applies(tmp_path):
    from valvur.adapters.checkov import CheckovAdapter

    _repo(tmp_path, {"app.py": "x = 1\n"})
    applies, why = CheckovAdapter().applies_to(tmp_path)

    assert applies is False
    assert "no Dockerfile" in why

    _repo(tmp_path, {"main.tf": "resource {}\n"})
    assert CheckovAdapter().applies_to(tmp_path)[0] is True


def test_a_skipped_scanner_is_not_a_failure_and_is_reported(workspace, runner_finding_nothing):
    """The Scan Run stays complete, but the reader is told. A Scanner that did not
    run must never look like one that ran and found nothing."""
    from valvur.adapters.base import ScannerAdapter
    from valvur.api import scan
    from valvur.results import _provenance
    from valvur.summary import render as _summary

    class NothingApplies(ScannerAdapter):
        kind = "scanner"
        name = "checkov"

        def applies_to(self, workspace):
            return False, "no infrastructure files found"

        def run(self, runner, workspace):
            raise AssertionError("must not run when it does not apply")

        def parse(self, output):
            return []

    run = scan(workspace, runner=runner_finding_nothing, adapters=[NothingApplies()])

    assert not run.failures, "a skip is not a failure"
    assert json.loads(_provenance(run))["scanners_skipped"] == {
        "checkov": "no infrastructure files found"
    }
    assert "Not run, having nothing to analyse" in _summary(run)
    assert "checkov" in _summary(run)
