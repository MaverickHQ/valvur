"""Attach an earlier release's image build provenance to its GitHub release (1.4.0).

    uv run python scripts/release_provenance.py v1.1.0 v1.2.0 v1.3.0 v1.3.1           # check
    uv run python scripts/release_provenance.py --upload v1.1.0 v1.2.0 v1.3.0 v1.3.1  # attach

Scorecard's Signed-Releases looks at the last five releases and counts one with an asset
ending `.intoto.jsonl` as 10, so 1.4.0's alone would read 2. Every release since 26.1.3
has GitHub's attestation of its image, made by the release workflow that built it, but
none carried it as an asset. This downloads that attestation with `gh attestation
download` and attaches it under the name 1.4.0's `stage` uses. Without `--upload` it
only downloads, which proves the attestation is there and changes nothing. With it, the
release gains one asset, and nothing else on it changes. Uploading changes a public
release, so the owner runs it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = "MaverickHQ/valvur"
IMAGE = "ghcr.io/maverickhq/valvur"
_TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")


def _version(tag: str) -> str:
    match = _TAG.match(tag)
    if not match:
        raise ValueError(f"not a release tag: {tag!r} (expected vX.Y.Z)")
    return match.group(1)


def asset_name(tag: str) -> str:
    return f"valvur-{_version(tag)}.image.intoto.jsonl"


def download_command(tag: str) -> list[str]:
    return ["gh", "attestation", "download", f"oci://{IMAGE}:{_version(tag)}",
            "--repo", REPOSITORY]


def upload_command(tag: str, path: Path) -> list[str]:
    _version(tag)
    return ["gh", "release", "upload", tag, str(path), "--repo", REPOSITORY]


def attach(tag: str, *, upload: bool) -> int:
    with tempfile.TemporaryDirectory(prefix="valvur-provenance-") as scratch:
        done = subprocess.run(download_command(tag), cwd=scratch,  # noqa: S603 — gh, fixed arguments
                              capture_output=True, text=True, check=False)
        bundles = sorted(Path(scratch).glob("*.jsonl"))
        if done.returncode != 0 or len(bundles) != 1:
            print(f"{tag}: no single attestation downloaded: {done.stderr.strip()[:200]}")
            return 1
        asset = bundles[0].rename(Path(scratch) / asset_name(tag))
        if not upload:
            print(f"{tag}: attestation found; would attach {asset.name}")
            return 0
        done = subprocess.run(upload_command(tag, asset),  # noqa: S603 — gh, fixed arguments
                              capture_output=True, text=True, check=False)
        print(f"{tag}: {'attached ' + asset.name if done.returncode == 0 else done.stderr.strip()}")
        return done.returncode


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    upload = "--upload" in args
    tags = [a for a in args if a != "--upload"]
    if not tags:
        print(__doc__)
        return 2
    return max(attach(tag, upload=upload) for tag in tags)


if __name__ == "__main__":
    sys.exit(main())
