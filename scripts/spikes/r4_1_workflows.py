"""R4.1 part 1: zizmor against what valvur reports on GitHub Actions workflows today.

D8: zizmor is adopted if it reports every unpinned action and every write permission
that the current tools find on the corpus. Today unpinned actions come from valvur's
own Opengrep rule `valvur.pinning.mutable-action-ref` and permissions from Checkov's
GitHub Actions checks. Everything runs with no network: Checkov and Opengrep in the
image, zizmor with `--offline`. Usage:

    uv run python scripts/spikes/r4_1_workflows.py <repo>... > out.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE = "valvur:dev"
ZIZMOR = "zizmor==1.30.1"
#: valvur's rule flags every action not pinned by hash; zizmor's default lets
#: `actions/*` and `github/*` stay on a tag. Measured both ways.
HASH_EVERYTHING = ("rules:\n  unpinned-uses:\n    config:\n      policies:\n"
                   "        \"*\": hash-pin\n")


def _in_image(repo: Path, *argv: str) -> str:
    cmd = ["docker", "run", "--rm", "--network=none", "-v", f"{repo}:/workspace:ro",
           "--tmpfs", "/tmp:rw,exec",  # noqa: S108 — the container's own tmpfs
           "--entrypoint", "sh", IMAGE, "-c", " ".join(argv)]
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout  # noqa: S603


def checkov(repo: Path) -> list[dict]:
    out = _in_image(repo, "checkov", "-d", "/workspace", "--framework", "github_actions",
                    "-o", "json", "--quiet", "--compact", "--skip-download")
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return []
    reports = data if isinstance(data, list) else [data]
    found = []
    for report in reports:
        for check in (report.get("results") or {}).get("failed_checks", []):
            found.append({"rule": check["check_id"], "file": check["file_path"].lstrip("/"),
                          "line": (check.get("file_line_range") or [0])[0]})
    return found


def pins(repo: Path) -> list[dict]:
    out = _in_image(repo, "mkdir -p /tmp/w && cd /tmp/w && printf '#\\n' > .semgrepignore &&",
                    "opengrep", "scan", "--config", "/opt/valvur-rules/pinning-hygiene.yaml",
                    "--json", "--quiet", "--no-git-ignore", "/workspace")
    try:
        results = json.loads(out or "{}").get("results", [])
    except ValueError:
        return []
    return [{"rule": r["check_id"].rsplit(".", 1)[-1],
             "file": r["path"].removeprefix("/workspace/"), "line": r["start"]["line"]}
            for r in results if r["check_id"].endswith("mutable-action-ref")]


def zizmor(repo: Path, config: str | None) -> list[dict]:
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(config or "")
    args = ["uvx", ZIZMOR, "--offline", "--format", "json", "--no-progress", "--persona", "regular"]
    args += ["--config", handle.name] if config else ["--no-config"]
    out = subprocess.run([*args, str(repo)], capture_output=True, text=True,  # noqa: S603
                         check=False).stdout
    try:
        data = json.loads(out or "[]")
    except ValueError:
        return []
    found = []
    for finding in data:
        for location in finding.get("locations", []):
            if not location.get("symbolic", {}).get("kind") == "Primary":
                continue
            key = location["symbolic"]["key"]
            local = key.get("Local") or {}
            path = local.get("verbatim_path") or local.get("given_path", "")
            row = location["concrete"]["location"]["start_point"]["row"] + 1
            found.append({"rule": finding["ident"], "file": _relative(path, repo),
                          "line": row, "severity": finding["determinations"]["severity"]})
    return found


def _relative(path: str, repo: Path) -> str:
    """zizmor gives the path as it collected it: absolute, relative, or empty."""
    resolved = Path(path).resolve() if path else repo
    try:
        return resolved.relative_to(repo).as_posix()
    except ValueError:
        return path


def main(argv: list[str]) -> int:
    results = {}
    for arg in argv:
        repo = Path(arg).resolve()
        results[repo.name] = {"checkov": checkov(repo), "pins": pins(repo),
                              "zizmor": zizmor(repo, None),
                              "zizmor_hash_everything": zizmor(repo, HASH_EVERYTHING)}
        print(f"{repo.name}: checkov {len(results[repo.name]['checkov'])}, pins "
              f"{len(results[repo.name]['pins'])}, zizmor {len(results[repo.name]['zizmor'])}",
              file=sys.stderr)
    json.dump(results, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
