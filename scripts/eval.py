#!/usr/bin/env python3
"""The Score (task R9.3, ADR-0026): scan each track, score it, record it.

    python3 scripts/eval.py [--tracks a,b] [--out DIR] [--compare BASELINE]

Each track is a tree of vulnerable cases and their safe twins. The harness builds
it, runs `valvur scan` on it with the image `VALVUR_IMAGE` names, and scores what
came back by the OWASP Benchmark's formula (`scripts/eval/score.py`). The result
records the image, the data's ages and each track's cases, so a score can be
measured again on the same cases.
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "eval"))

import score  # type: ignore[import-not-found]  # noqa: E402
import twins  # type: ignore[import-not-found]  # noqa: E402

#: The awesome-cursorrules checkout the corpus keeps, whose real files join the
#: agent-configuration track's safe cases.
CURSORRULES = REPO / "tests" / "corpus" / ".checkouts" / "awesome-cursorrules"


def _cli_scan(workspace: Path) -> None:
    """`valvur scan <workspace>` through the CLI, as a user runs it."""
    import subprocess

    subprocess.run([sys.executable, "-c",  # noqa: S603 — this interpreter, the CLI
                    "from valvur.cli import main; raise SystemExit(main())",
                    "scan", str(workspace)], check=False, capture_output=True)


def _image_id(image: str) -> str:
    import subprocess

    out = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"],  # noqa: S603
                         capture_output=True, text=True, check=False)
    return out.stdout.strip()


def _read(root: Path) -> tuple[list[dict], dict]:
    folder = root / ".security-scan"
    findings = json.loads((folder / "findings.json").read_text())["findings"]
    return findings, json.loads((folder / "run.json").read_text())


def run(tracks: list[str], work: Path, *, scan: Callable[[Path], None] = _cli_scan,
        image: str = "valvur:dev", image_id: Callable[[str], str] = _image_id,
        seed: int = 20260929) -> dict:
    """Build, scan and score each track under `work`, which is rebuilt."""
    started = time.monotonic()
    result: dict = {"schema": 1, "image": {"name": image, "id": image_id(image)},
                    "seed": seed, "tracks": {}, "data": {}}
    for track in tracks:
        root = work / track
        if root.exists():
            shutil.rmtree(root)
        extra = {"corpus": CURSORRULES if CURSORRULES.is_dir() else None} \
            if track == "agent-configuration" else {}
        cases = twins.build(track, root, seed=seed, **extra)
        began = time.monotonic()
        scan(root)
        findings, run_json = _read(root)
        scored = score.score_track(cases, findings)
        result["tracks"][track] = {
            "score": scored.score,
            "categories": {name: {"tp": r.tp, "fn": r.fn, "fp": r.fp, "tn": r.tn,
                                  "tpr": round(r.tpr, 3), "fpr": round(r.fpr, 3)}
                           for name, r in sorted(scored.categories.items())},
            "vulnerable": sum(c.vulnerable for c in cases),
            "safe": sum(not c.vulnerable for c in cases),
            "complete": bool(run_json.get("complete")),
            "status": run_json.get("status"),
            "what_left_the_machine": (run_json.get("network") or {}).get(
                "what_left_the_machine"),
            "seconds": round(time.monotonic() - began, 1),
        }
        result["data"] = {
            "database_age_days": (run_json.get("database") or {}).get("age_days"),
            "name_index_age_days": (run_json.get("name_index") or {}).get("age_days"),
            "kev_age_days": (run_json.get("enrichment") or {}).get("kev_age_days"),
        }
    scores = [t["score"] for t in result["tracks"].values()]
    result["score"] = round(sum(scores) / len(scores), 1) if scores else 0.0
    result["duration_s"] = round(time.monotonic() - started, 1)
    return result


def scorecard(result: dict) -> str:
    lines = [f"**The Score: {result['score']}** on `{result['image']['name']}` "
             f"(`{result['image']['id'][:19]}`), {result['duration_s']} s", "",
             "| track | score | vulnerable | safe | complete | seconds |",
             "|---|---|---|---|---|---|"]
    for name, track in result["tracks"].items():
        lines.append(f"| {name} | {track['score']} | {track['vulnerable']} | {track['safe']} "
                     f"| {'yes' if track['complete'] else 'NO'} | {track['seconds']} |")
    return "\n".join(lines) + "\n"


def write(result: dict, out: Path) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = {"json": out / "score.json", "markdown": out / "scorecard.md"}
    paths["json"].write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    paths["markdown"].write_text(scorecard(result), encoding="utf-8")
    return paths


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os

    home = Path(os.environ.get("HOME", "~")) / ".cache" / "valvur-build"
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tracks", default=",".join(twins.BUILDERS),
                        help="comma-separated; all of the generated tracks by default")
    parser.add_argument("--work", type=Path, default=home / "eval" / "work")
    parser.add_argument("--out", type=Path, default=home / "eval" / "report")
    args = parser.parse_args(argv)
    image = os.environ.get("VALVUR_IMAGE", "valvur:dev")
    result = run([t for t in args.tracks.split(",") if t], args.work.resolve(), image=image)
    write(result, args.out.resolve())
    print(scorecard(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
