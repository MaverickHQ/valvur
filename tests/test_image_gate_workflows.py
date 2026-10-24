"""R43.4: where the image gate runs, and what no document claims (D81t, N2.7).

In `ci.yml`, after the image is built, on both architectures and not required; in
`release.yml`, on the staged image before `promote`; nightly, against the latest
published image. Each runs the image's own Trivy with no network. It is the project
checking its own image, so no document offers image scanning to users, and the
ROADMAP's row stays where it is.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1]
    keys = list(re.finditer(r"^  ([a-z][\w-]*):$", body, re.M))
    return {k[1]: body[k.end():keys[i + 1].start() if i + 1 < len(keys) else len(body)]
            for i, k in enumerate(keys)}


def _trivy_rootfs_without_network(block: str) -> None:
    command = " ".join(line.strip().rstrip("\\") for line in block.splitlines())
    assert "docker run --rm --network none" in command
    assert "--entrypoint trivy" in command and " rootfs " in command
    assert "--skip-db-update" in command and "--offline-scan" in command
    assert "python3 scripts/image_gate.py" in block


def test_ci_scans_the_image_it_built_on_both_architectures():
    job = _jobs((WORKFLOWS / "ci.yml").read_text())["imagegate"]

    assert "\n    needs: image\n" in job and "\n    if: ${{ !cancelled() }}\n" in job
    assert "- arch: amd64" in job and "- arch: arm64" in job
    assert "name: image-${{ matrix.arch }}" in job and "docker load" in job
    assert "docker buildx bake" not in job
    _trivy_rootfs_without_network(job)
    assert "name: image-gate-${{ matrix.arch }}" in job


def test_the_image_check_is_not_a_required_check_until_the_owner_makes_it_one():
    spec = importlib.util.spec_from_file_location("ci_verdict", REPO / "scripts" / "ci_verdict.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    assert not any("scanned as it ships" in name for name in module.REQUIRED)


def test_the_release_judges_the_staged_image_before_promote():
    jobs = _jobs((WORKFLOWS / "release.yml").read_text())
    artifact = jobs["artifact"]

    assert "name: The staged image, scanned as it ships" in artifact
    step = artifact.split("name: The staged image, scanned as it ships", 1)[1]
    step = step.split("\n      - ", 1)[0]
    _trivy_rootfs_without_network(step)
    assert "${{ env.IMAGE }}@${{ env.DIGEST }}" in step and "${{" not in step.split("run:", 1)[1]
    assert re.search(r"^    needs: \[[^\]]*\bartifact\b[^\]]*\]$", jobs["promote"], re.M)


def test_the_nightly_judges_the_latest_published_image():
    job = _jobs((WORKFLOWS / "acceptance.yml").read_text())["image"]

    assert "ghcr.io/maverickhq/valvur:latest" in job
    _trivy_rootfs_without_network(job)
    assert "title: the published image has a fixable vulnerability" in job


def test_no_document_offers_image_scanning_to_users():
    claims = re.compile(r"(scans?|scanning) (your |a |the )?(container )?images?\b"
                        r"|image scanning", re.I)
    documents = [REPO / "README.md", *sorted((REPO / "docs").glob("*.md"))]
    for path in documents:
        for line in path.read_text().splitlines():
            assert not claims.search(line), (path.name, line)
    roadmap = (REPO / "ROADMAP.md").read_text()
    being_considered = roadmap.split("## Being considered", 1)[1].split("\n## ", 1)[0]
    assert "| Container images scanned offline |" in being_considered
