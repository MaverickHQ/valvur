"""R13.5: tracks 1 and 2 through the shipped rules, with and without Opengrep's
intra-file cross-function taint (`--taint-intrafile`), per D29.

    python scripts/eval/taint.py WORK [BENCHMARK]

Opengrep alone, through the image, over each track read as a scan reads it, scored
by the Score's own formula: a measurement of one flag, not a Score. Gitleaks' part of
track 2 is not in it, so track 2 here is Opengrep's share.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts" / "eval"))

import cwe  # noqa: E402  # type: ignore[import-not-found]
import owasp  # noqa: E402  # type: ignore[import-not-found]
import per_rule  # noqa: E402  # type: ignore[import-not-found]
import score  # noqa: E402  # type: ignore[import-not-found]
import twins  # noqa: E402  # type: ignore[import-not-found]


def measure(work: Path, benchmark: Path, image: str = "valvur:dev") -> list[dict]:
    from valvur.adapters.opengrep import _short_rule

    cwe_of = cwe.lookup(REPO / "rules")
    js = work / "sast-js"
    shutil.rmtree(js, ignore_errors=True)
    rows = []
    for name, root, cases in (("sast-python", benchmark, owasp.cases(benchmark)),
                              ("sast-js", js, twins.build("sast-js", js))):
        copy = per_rule.readable(root, work / f"copy-{name}")
        for flags in ([], ["--taint-intrafile"]):
            started = time.monotonic()
            done = subprocess.run(  # noqa: S603 — the runtime, fixed arguments
                ["docker", "run", "--rm", "--network=none", "-w", "/src",
                 "-v", f"{REPO / 'rules'}:/rules:ro", "-v", f"{copy}:/src:ro",
                 "--entrypoint", "opengrep", image, "scan", "--config", "/rules", "--json",
                 "--quiet", "--no-git-ignore", *flags, "/src"],
                capture_output=True, text=True, check=True)
            report = json.loads(done.stdout)
            findings = [{"path": r["path"].removeprefix("/src/"), "status": "new",
                         "rule": _short_rule(r["check_id"]),
                         "cwe": (r["extra"].get("metadata") or {}).get("cwe")}
                        for r in report["results"]]
            scored = score.score_track(cases, findings, cwe_of)
            rows.append({"track": name, "flags": " ".join(flags) or "default",
                         "score": scored.score,
                         "tp": sum(r.tp for r in scored.categories.values()),
                         "fp": sum(r.fp for r in scored.categories.values()),
                         "seconds": round(time.monotonic() - started, 1)})
    return rows


if __name__ == "__main__":
    work = Path(sys.argv[1])
    bench = Path(sys.argv[2]) if len(sys.argv) > 2 else owasp.checkout(work / "BenchmarkPython")
    for row in measure(work, bench):
        print(json.dumps(row))
