"""R4.1 part 2: KICS and Trivy against Checkov on infrastructure, workflows aside.

D8: KICS replaces Checkov only if it finds at least 90% of Checkov's distinct failed
rules on repositories 5 and 6 and the corpus infrastructure, and runs at least twice
as fast. Workflows are zizmor's (part 1), so every tool skips them, and secrets are
Gitleaks's. Checkov and Trivy run in the valvur image, KICS in its own, all with no
network; each repository once per tool, sequentially, so the times do not contend.
Usage:

    uv run python scripts/spikes/r4_1_infrastructure.py <repo>... > out.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

IMAGE = "valvur:dev"
KICS = "checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602"


def _run(repo: Path, image: str, script: str) -> tuple[str, float]:
    cmd = ["docker", "run", "--rm", "--network=none", "-v", f"{repo}:/workspace:ro",
           "--tmpfs", "/tmp:rw,exec",  # noqa: S108 — the container's own tmpfs
           "--entrypoint", "sh", image, "-c", script]
    started = time.monotonic()
    out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout  # noqa: S603
    return out, round(time.monotonic() - started, 1)


def checkov(repo: Path) -> tuple[list[dict], float]:
    out, seconds = _run(repo, IMAGE, "checkov -d /workspace -o json --quiet --compact "
                        "--skip-download --skip-framework github_actions secrets")
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return [], seconds
    found = []
    for report in data if isinstance(data, list) else [data]:
        for check in (report.get("results") or {}).get("failed_checks", []):
            found.append({"rule": check["check_id"], "name": check.get("check_name", ""),
                          "file": check["file_path"].lstrip("/"),
                          "resource": check.get("resource", "")})
    return found, seconds


def kics(repo: Path) -> tuple[list[dict], float]:
    out, seconds = _run(repo, KICS, (
        "kics scan -p /workspace -o /tmp/k --report-formats json --disable-full-descriptions "
        "--disable-secrets --exclude-type CICD --no-progress --ci >/dev/null 2>&1; "
        "cat /tmp/k/results.json"))
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return [], seconds
    found = []
    for query in data.get("queries", []):
        for hit in query.get("files", []):
            found.append({"rule": query["query_id"], "name": query["query_name"],
                          "severity": query["severity"],
                          "file": hit["file_name"].split("/workspace/", 1)[-1],
                          "resource": hit.get("resource_name", "")})
    return found, seconds


def trivy(repo: Path) -> tuple[list[dict], float]:
    out, seconds = _run(repo, IMAGE, (
        "trivy config /workspace --disable-telemetry --skip-version-check "
        "--skip-check-update --format json --quiet"))
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return [], seconds
    found = []
    for result in data.get("Results", []):
        for miss in result.get("Misconfigurations", []):
            if miss.get("Status") == "FAIL":
                found.append({"rule": miss["ID"], "name": miss.get("Title", ""),
                              "file": result["Target"]})
    return found, seconds


def main(argv: list[str]) -> int:
    results = {}
    for arg in argv:
        repo = Path(arg).resolve()
        (ck, ck_s), (ki, ki_s), (tr, tr_s) = checkov(repo), kics(repo), trivy(repo)
        results[repo.name] = {"checkov": ck, "checkov_s": ck_s, "kics": ki, "kics_s": ki_s,
                              "trivy": tr, "trivy_s": tr_s}
        print(f"{repo.name}: checkov {len(ck)} ({ck_s}s), kics {len(ki)} ({ki_s}s), "
              f"trivy {len(tr)} ({tr_s}s)", file=sys.stderr)
    json.dump(results, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
