"""1.4.0: every release carries its build provenance as an asset Scorecard counts.

Scorecard's Signed-Releases scores each of the last five releases 10 when one of its
assets ends `.intoto.jsonl`, 8 for a signature file, and 0 otherwise (its
`releasesHaveProvenance` and `releasesAreSigned` probes, read 2026-10-04). valvur's
releases carried PyPI's `.publish.attestation` files, which it does not count, so the
check scored 0 although the image has been attested since 26.1.3. `stage` now attests
the Python distributions too, `promote` attaches both bundles to the release, and
`artifact` verifies the distributions' as it verifies the image's.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RELEASE = REPO / ".github" / "workflows" / "release.yml"
SCRIPT = REPO / "scripts" / "release_provenance.py"
ATTEST = "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"


def _job(name: str) -> str:
    text = RELEASE.read_text()
    start = re.search(rf"^  {re.escape(name)}:\n", text, re.M)
    assert start, f"no job {name}"
    end = re.search(r"^  [a-z][a-z-]*:\n", text[start.end():], re.M)
    return text[start.start(): start.end() + (end.start() if end else len(text))]


def test_stage_attests_the_python_distributions_with_the_pinned_action():
    stage = _job("stage")

    assert stage.count(ATTEST) == 2, "the image's attestation and the distributions'"
    assert "id: attest-image" in stage and "id: attest-dist" in stage
    assert re.search(r"subject-path: dist/\*", stage)


def test_stage_keeps_both_bundles_as_intoto_jsonl_named_for_the_version():
    stage = _job("stage")

    assert "steps.attest-image.outputs.bundle-path" in stage
    assert "steps.attest-dist.outputs.bundle-path" in stage
    assert 'provenance/valvur-${PUBLISH}.image.intoto.jsonl' in stage
    assert 'provenance/valvur-${PUBLISH}.dist.intoto.jsonl' in stage
    assert re.search(r"name: provenance\n\s+path: provenance/\*", stage)


def test_promote_attaches_the_provenance_to_the_release():
    promote = _job("promote")

    assert re.search(r"name: provenance\n\s+path: provenance", promote)
    create = promote[promote.index("gh release create"):]
    assert "provenance/*.intoto.jsonl" in create.split("\n\n")[0]


def test_artifact_verifies_the_distributions_provenance():
    artifact = _job("artifact")

    assert re.search(r'gh attestation verify "\$file" --repo MaverickHQ/valvur', artifact)
    assert "for file in dist/*.whl dist/*.tar.gz" in artifact


def _script():
    spec = importlib.util.spec_from_file_location("release_provenance", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["release_provenance"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_an_earlier_release_gets_its_images_provenance_under_scorecards_name(tmp_path):
    """Releases before 1.4.0 have GitHub's attestation of their image, made by the
    release that built them; the script attaches it, under the name `stage` uses."""
    script = _script()

    assert script.asset_name("v1.3.1") == "valvur-1.3.1.image.intoto.jsonl"
    assert script.download_command("v1.3.1") == [
        "gh", "attestation", "download", "oci://ghcr.io/maverickhq/valvur:1.3.1",
        "--repo", "MaverickHQ/valvur"]
    bundle = tmp_path / "x.intoto.jsonl"
    assert script.upload_command("v1.3.1", bundle) == [
        "gh", "release", "upload", "v1.3.1", str(bundle), "--repo", "MaverickHQ/valvur"]


@pytest.mark.parametrize("tag", ["1.3.1", "v1.3", "latest"])
def test_a_tag_that_is_not_a_release_version_is_refused(tag):
    with pytest.raises(ValueError, match="tag"):
        _script().asset_name(tag)
