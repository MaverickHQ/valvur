"""R10.3: an npm project's own registry configuration (D27, F3.15).

Until R10 every name missing from the public index read as hallucinated, at high.
A regulated company's internal packages, which this product's buyers have, all did:
the Score's package-reality track flagged its privately registered npm case. The
project says where its packages come from, in `.npmrc` or `.yarnrc.yml`; the Check
now reads it.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.checks.dependency_reality import DependencyRealityCheck

INTERNAL = "https://npm.internal.example/"


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _manifest(*names: str) -> str:
    return json.dumps({"name": "app", "dependencies": {n: "^1.0.0" for n in names}})


def test_a_scope_bound_to_a_private_registry_in_npmrc_is_not_looked_up_publicly(
    tmp_path, name_index
):
    name_index(npm=["express"])
    repo = _repo(tmp_path, {"package.json": _manifest("@acme/billing-client", "express"),
                            ".npmrc": f"@acme:registry={INTERNAL}\n"})

    found = DependencyRealityCheck().run(repo)

    assert [(f["rule"], f["severity"]) for f in found] == [
        ("valvur.dependency.private-registry", "low")]
    assert "@acme" in found[0]["title"] and "npm.internal.example" in found[0]["title"]


def test_a_scope_bound_to_a_private_registry_in_yarnrc_is_not_looked_up_publicly(
    tmp_path, name_index
):
    name_index(npm=["express"])
    repo = _repo(tmp_path, {
        "package.json": _manifest("@acme/billing-client", "express"),
        ".yarnrc.yml": 'nodeLinker: node-modules\nnpmScopes:\n  acme:\n'
                       '    npmRegistryServer: "https://npm.internal.example"\n'})

    found = DependencyRealityCheck().run(repo)

    assert [f["rule"] for f in found] == ["valvur.dependency.private-registry"]


def test_a_name_missing_where_the_whole_registry_is_replaced_is_advice_to_reserve_it(
    tmp_path, name_index
):
    name_index(npm=["express"])
    repo = _repo(tmp_path, {"package.json": _manifest("billing-client", "express"),
                            ".npmrc": f"registry={INTERNAL}\n"})

    found = DependencyRealityCheck().run(repo)

    assert [(f["rule"], f["severity"]) for f in found] == [
        ("valvur.dependency.not-public", "low")]
    assert "billing-client" in found[0]["title"]
    assert "npm.internal.example" in found[0]["evidence"]


def test_with_no_configuration_a_missing_name_says_how_old_the_index_is(
    tmp_path, name_index
):
    name_index(npm=["express"], built_at="2026-09-28T03:23:00Z")
    repo = _repo(tmp_path, {"package.json": _manifest("@acme/billing-client", "express")})

    found = DependencyRealityCheck().run(repo)

    assert [(f["rule"], f["severity"]) for f in found] == [
        ("valvur.dependency.nonexistent", "high")]
    assert "2026-09-28" in found[0]["evidence"]
    assert ".npmrc" in found[0]["evidence"]
