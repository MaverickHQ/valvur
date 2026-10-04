"""A project whose own ignores each hide one planted finding (R38, D77).

Built at runtime, never committed: the credentials are assembled here, since push
protection is on, and a committed copy would carry ignores the repository's own
scans would read. Each ignore D77 names hides one finding, beside a twin it does not
hide, so a scan shows both what the rule finds and what the ignore takes away.
"""

from __future__ import annotations

from pathlib import Path

#: Three AWS access key IDs, one for each Gitleaks ignore; assembled, never literal.
KEYS = {name: "AKIA" + body for name, body in (
    ("allow", "QX3ZR5TW7YB2MN4P"), ("ignorefile", "ZT4WM7QK2RX6PB3N"),
    ("toml", "MB6RX2TQ7WZ4KN3P"), ("twin", "RW3QZ7TB4XM2PN6K"))}

#: The command injection valvur's own rule reports, once ignored and once not.
INJECTION = ("import subprocess\n\n\ndef run(cmd):\n"
             "    return subprocess.run(cmd, shell=True, capture_output=True){comment}\n")

#: An S3 bucket Checkov reports, once with an inline skip and once without.
BUCKET = '''resource "aws_s3_bucket" "{name}" {{
{skip}  bucket = "valvur-fixture-{name}"
}}
'''

#: urllib3 1.24.1: Trivy and OSV-Scanner each report CVE-2019-11324 (PYSEC-2019-133)
#: and CVE-2019-11236 (PYSEC-2019-132); one is ignored for each.
TRIVY_IGNORED = "CVE-2019-11324"
OSV_IGNORED = "PYSEC-2019-132"

#: Each ignore, the file it hides a finding in, and that finding's rule as valvur names
#: it once measured (R38.1). The rule is what a test looks for.
HIDES = {
    "nosemgrep": "app/ignored.py",
    "gitleaks:allow": "secrets/allowed.py",
    ".gitleaksignore": "secrets/listed.py",
    ".gitleaks.toml": "vendored/secret.py",
    "checkov:skip": "infra/skipped.tf",
    ".trivyignore": "requirements.txt",
    "osv-scanner.toml": "requirements.txt",
}


def build(root: Path) -> Path:
    """Write the project under `root` and return it."""
    files = {
        "app/ignored.py": INJECTION.format(comment="  # nosemgrep"),
        "app/twin.py": INJECTION.format(comment=""),
        "secrets/allowed.py": f'AWS_KEY = "{KEYS["allow"]}"  # gitleaks:allow\n',
        "secrets/listed.py": f'AWS_KEY = "{KEYS["ignorefile"]}"\n',
        "vendored/secret.py": f'AWS_KEY = "{KEYS["toml"]}"\n',
        "secrets/twin.py": f'AWS_KEY = "{KEYS["twin"]}"\n',
        ".gitleaksignore": "secrets/listed.py:aws-access-token:1\n",
        ".gitleaks.toml": ('[extend]\nuseDefault = true\n\n[allowlist]\n'
                           "description = \"vendored code\"\npaths = ['''vendored/''']\n"),
        "infra/skipped.tf": BUCKET.format(
            name="skipped", skip="  #checkov:skip=CKV_AWS_18:access logs are elsewhere\n"),
        "infra/twin.tf": BUCKET.format(name="twin", skip=""),
        "requirements.txt": "urllib3==1.24.1\n",
        ".trivyignore": f"{TRIVY_IGNORED}\n",
        "osv-scanner.toml": (f'[[IgnoredVulns]]\nid = "{OSV_IGNORED}"\n'
                             'reason = "measured by R38.1"\n'),
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root
