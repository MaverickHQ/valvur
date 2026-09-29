"""R10.8: a placeholder key block is not a secret (the Score's secrets track, R9).

Documentation shows a private key's shape with `...` between the markers. Gitleaks
reports that block as a private key, at critical: the Score's placeholder twin drew
it, which the honesty gate refuses from R10's exit. A real key block still reports.
Markers are assembled at runtime: push protection is on for this repository.
"""

from __future__ import annotations

import json
import random
import string

from valvur.adapters import GitleaksAdapter
from valvur.runner import ScannerOutput

HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
FOOTER = "-----END RSA " + "PRIVATE KEY-----"


def _item(path: str, secret: str) -> dict:
    return {"RuleID": "private-key", "Description": "Identified a Private Key",
            "File": f"/workspace/{path}", "StartLine": 1, "Secret": secret, "Match": secret}


def _parse(*items: dict) -> list:
    return GitleaksAdapter().parse(ScannerOutput(
        tool="gitleaks", version="8.30.1", stdout=json.dumps(list(items)), stderr="",
        exit_code=0))


def test_a_key_block_with_a_placeholder_body_is_not_reported():
    assert _parse(_item("docs/key.pem.example", f"{HEADER}\n...\n{FOOTER}")) == []
    assert _parse(_item("docs/key.md", f"{HEADER}\n<your key here>\n{FOOTER}")) == []


def test_a_real_key_block_still_is():
    rng = random.Random(3)  # noqa: S311 — seeded, to plant the same fake key each run
    body = "\n".join("".join(rng.choice(string.ascii_letters + string.digits + "+/")
                             for _ in range(64)) for _ in range(12))

    [finding] = _parse(_item("deploy/id_rsa", f"{HEADER}\n{body}\n{FOOTER}"))

    assert (finding.rule, finding.path) == ("private-key", "deploy/id_rsa")
