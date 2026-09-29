"""R10.10: a Composer project's own repositories (D27 extended, ADR-0028).

A `composer`-type repository, private Packagist or Satis, is canonical by default:
Composer takes a package from it before Packagist, so a name missing from Packagist
is served privately. With `"canonical": false` it merges with Packagist, and a name
registered there wins. `"packagist.org": false` turns Packagist off altogether. The
Score's privately served Composer case read as hallucinated at high until this task.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.checks.dependency_reality import DependencyRealityCheck

PRIVATE = "https://packages.internal.example"


def _rules(root: Path, repositories) -> list[tuple[str, str]]:
    (root / "composer.json").write_text(json.dumps({
        "name": "acme/app", "repositories": repositories,
        "require": {"acme/billing-client": "^1.0", "monolog/monolog": "^3.0"}}))
    return [(f["rule"], f["severity"]) for f in DependencyRealityCheck().run(root)]


def test_a_canonical_private_repository_makes_a_missing_name_advice(tmp_path, name_index):
    name_index(composer=["monolog/monolog"])

    assert _rules(tmp_path, [{"type": "composer", "url": PRIVATE}]) == [
        ("valvur.dependency.not-public", "low")]


def test_a_non_canonical_one_merges_with_packagist_and_is_confusion(tmp_path, name_index):
    name_index(composer=["monolog/monolog"])

    assert _rules(tmp_path, [{"type": "composer", "url": PRIVATE, "canonical": False}]) == [
        ("valvur.dependency.confusion", "high")]


def test_packagist_turned_off_is_replaced(tmp_path, name_index):
    name_index(composer=["monolog/monolog"])

    assert _rules(tmp_path, {"private": {"type": "composer", "url": PRIVATE},
                             "packagist.org": False}) == [
        ("valvur.dependency.not-public", "low")]
