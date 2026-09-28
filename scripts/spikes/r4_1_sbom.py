"""R4.1 part 3: Trivy's CycloneDX, from the pass valvur already runs, against Syft's.

D8: Trivy's SBOM replaces Syft if its component count is within 5% of Syft's on the
corpus. Trivy runs as valvur runs it, plus `--list-all-pkgs`, and `trivy convert`
turns that JSON into CycloneDX; Syft runs as valvur runs it. Both in the image with no
network; the vulnerability database comes from the host cache. Counted: components
carrying a purl, i.e. packages. Usage:

    uv run python scripts/spikes/r4_1_sbom.py <trivy-db-dir> <repo>... > out.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

IMAGE = "valvur:dev"


def _in_image(repo: Path, db: Path, script: str) -> tuple[str, float]:
    cmd = ["docker", "run", "--rm", "--network=none", "-v", f"{repo}:/workspace:ro",
           "-v", f"{db}:/cache/trivy:ro",
           "--tmpfs", "/tmp:rw,exec",  # noqa: S108 — the container's own tmpfs
           "--entrypoint", "sh", IMAGE, "-c", script]
    started = time.monotonic()
    out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout  # noqa: S603
    return out, round(time.monotonic() - started, 1)


def _packages(cyclonedx: str) -> set[str]:
    try:
        data = json.loads(cyclonedx or "{}")
    except ValueError:
        return set()
    return {c["purl"].split("?")[0] for c in data.get("components", []) if c.get("purl")}


def main(argv: list[str]) -> int:
    db = Path(argv[0]).resolve()
    results = {}
    for arg in argv[1:]:
        repo = Path(arg).resolve()
        syft, syft_s = _in_image(repo, db, "syft scan dir:/workspace -o cyclonedx-json -q")
        trivy, trivy_s = _in_image(repo, db, (
            "trivy fs /workspace --cache-dir /cache/trivy --disable-telemetry "
            "--skip-version-check --skip-db-update --skip-java-db-update --format json "
            "--list-all-pkgs --scanners vuln --include-dev-deps --quiet -o /tmp/t.json && "
            "trivy convert --format cyclonedx --quiet /tmp/t.json"))
        s, t = _packages(syft), _packages(trivy)
        def types(purls: set[str]) -> dict[str, int]:
            counts: dict[str, int] = {}
            for purl in purls:
                kind = purl.split("/", 1)[0]
                counts[kind] = counts.get(kind, 0) + 1
            return counts

        results[repo.name] = {"syft": len(s), "trivy": len(t), "both": len(s & t),
                              "syft_types": types(s), "trivy_types": types(t),
                              "syft_only": sorted(s - t)[:20], "trivy_only": sorted(t - s)[:20],
                              "syft_s": syft_s, "trivy_s": trivy_s}
        print(f"{repo.name}: syft {len(s)}, trivy {len(t)}, both {len(s & t)}", file=sys.stderr)
    json.dump(results, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
