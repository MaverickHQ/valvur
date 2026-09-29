"""R10.2: Checkov runs without its secrets framework; Gitleaks owns secrets (D31).

On a repository with infrastructure, Checkov's secrets framework reported the same
secrets Gitleaks did: R5's planted flood of machine-written keys came back as 3,694
Gitleaks findings and 3,890 `CKV_SECRET_6`, and since a secret's identity carries its
rule the two could never merge. One Scanner answers the question now.
"""

from __future__ import annotations

import pytest


def test_checkov_is_told_to_skip_its_secrets_framework(tmp_path):
    from valvur.adapters import CheckovAdapter

    argv = CheckovAdapter().command(tmp_path).argv
    skipped = argv[argv.index("--skip-framework") + 1:]

    assert "secrets" in skipped and "github_actions" in skipped


@pytest.mark.e2e
def test_a_secret_beside_terraform_is_reported_once_by_gitleaks(tmp_path):
    """Through the image: a planted key in a Terraform module, assembled at runtime."""
    import json
    import os
    import subprocess
    import sys

    key = "AK" + "IA" + "Q3EGRTWZMJ5KX7PL"
    # In the Terraform itself, where Checkov's secrets framework looks: a `.env`
    # beside it is not read by that framework, so it would prove nothing.
    (tmp_path / "main.tf").write_text(
        f'provider "aws" {{\n  region     = "eu-west-1"\n  access_key = "{key}"\n}}\n\n'
        'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n')
    subprocess.run([sys.executable, "-c",
                    "from valvur.cli import main; raise SystemExit(main())",
                    "scan", str(tmp_path)], check=True, capture_output=True,
                   env={**os.environ})
    findings = json.loads((tmp_path / ".security-scan" / "findings.json").read_text())[
        "findings"]

    secrets = [f for f in findings if "gitleaks" in f["sources"]
               or str(f["rule"]).startswith("CKV_SECRET")]
    assert [f["sources"] for f in secrets] == [["gitleaks"]]
    assert not [f for f in findings if str(f["rule"]).startswith("CKV_SECRET")]
