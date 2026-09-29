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

import cwe  # type: ignore[import-not-found]  # noqa: E402
import owasp  # type: ignore[import-not-found]  # noqa: E402
import score  # type: ignore[import-not-found]  # noqa: E402
import twins  # type: ignore[import-not-found]  # noqa: E402

#: Every track, in the order the Score reports them: the OWASP Benchmark first,
#: then the generated ones (ADR-0026).
TRACKS = ["sast-python", *twins.BUILDERS]

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


#: The dependency track's ranking fixture (D21's ranking gate): Log4Shell, in CISA
#: KEV, beside a test-scoped critical, in one project.
RANKING_PATH, RANKING_FIRST = "deps/ranking/pom.xml", "CVE-2021-44228"


def _ranked_first(findings: list[dict]) -> bool | None:
    """Whether the known-exploited CVE outranks every other finding in the fixture;
    None when the fixture drew nothing to rank."""
    here = [f for f in findings if f.get("path") == RANKING_PATH and not f.get("suppressed")]
    if not here:
        return None
    first = min(here, key=lambda f: f.get("rank") or 10**9)
    return RANKING_FIRST in (first.get("rule"), (first.get("exploit") or {}).get("cve"))


def _safe_flagged_high(cases: list, findings: list[dict]) -> list[str]:
    loud = [f for f in findings if f.get("severity") in ("high", "critical")]
    return [case.path for case in cases
            if not case.vulnerable and score.flagged(case, loud)]


def run(tracks: list[str], work: Path, *, scan: Callable[[Path], None] = _cli_scan,
        image: str = "valvur:dev", image_id: Callable[[str], str] = _image_id,
        seed: int = 20260929, tasks_text: str | None = None,
        index_dir: Path | None = None, benchmark: Path | None = None,
        verify: Callable[[Path], None] = owasp.verify) -> dict:
    """Build, scan and score each track under `work`, which is rebuilt. The
    benchmark is scanned where it is checked out, `benchmark` or the build cache's."""
    started = time.monotonic()
    ranking_first: bool | None = None
    result: dict = {"schema": 1, "image": {"name": image, "id": image_id(image)},
                    "seed": seed, "tracks": {}, "data": {}}
    cwe_of = cwe.lookup(REPO / "rules")
    for track in tracks:
        if track == "sast-python":
            root = benchmark or owasp.checkout(work.parent / "BenchmarkPython")
            verify(root)
            cases = owasp.cases(root)
        else:
            root = work / track
            if root.exists():
                shutil.rmtree(root)
            extra = {"corpus": CURSORRULES if CURSORRULES.is_dir() else None} \
                if track == "agent-configuration" else {}
            cases = twins.build(track, root, seed=seed, **extra)
        began = time.monotonic()
        scan(root)
        findings, run_json = _read(root)
        invalid: dict[str, str] = {}
        if track == "package-reality":
            from valvur import cache

            invalid = twins.invalid_cases(cases, index_dir or cache.name_index())
            cases = [case for case in cases if case.id not in invalid]
        scored = score.score_track(cases, findings, cwe_of)
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
            "safe_flagged_high": _safe_flagged_high(cases, findings),
            "invalid": invalid,
        }
        if track == "dependencies":
            ranking_first = _ranked_first(findings)
        result["data"] = {
            "database_age_days": (run_json.get("database") or {}).get("age_days"),
            "name_index_age_days": (run_json.get("name_index") or {}).get("age_days"),
            "kev_age_days": (run_json.get("enrichment") or {}).get("kev_age_days"),
        }
    result["gates"] = judge_gates(result["tracks"], result["data"],
                                  ranking_first=ranking_first,
                                  tasks_text=_tasks_text() if tasks_text is None else tasks_text)
    scores = [t["score"] for t in result["tracks"].values()]
    result["score"] = round(sum(scores) / len(scores), 1) if scores else 0.0
    result["duration_s"] = round(time.monotonic() - started, 1)
    return result


#: Each gate, and the phase from whose close it is judged (D21): before that it is
#: recorded, so a baseline can say what is wrong without failing a phase that
#: cannot yet fix it.
GATES = {"offline": 9, "honesty": 10, "freshness": 11, "ranking": 11, "speed": 14}

#: D24's refresh thresholds, in days: the oldest data a scan should be using.
FRESH_DAYS = {"database": 7.0, "name_index": 2.0, "kev": 2.0, "epss": 2.0, "osv": 7.0}


def _phase_closed(phase: int, tasks_text: str) -> bool:
    import re

    marks = re.findall(rf"^- \[([ xX])\] \*\*R{phase}\.\d+\*\*", tasks_text, re.M)
    return bool(marks) and all(mark != " " for mark in marks)


def _tasks_text() -> str:
    """The live task list and its archives, as the acceptance harness reads them."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("acceptance_harness",
                                                  REPO / "scripts" / "acceptance.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # Registered first: its dataclasses look their module up in sys.modules.
    sys.modules["acceptance_harness"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.task_list(REPO)


def judge_gates(tracks: dict, data: dict, *, ranking_first: bool | None,
                tasks_text: str) -> dict[str, dict]:
    """Pass or fail, each with its reason and whether its phase has closed."""
    leaked = [f"{name} ({t['what_left_the_machine']})" for name, t in tracks.items()
              if t.get("what_left_the_machine") != "nothing"]
    false_clean = [name for name, t in tracks.items()
                   if t.get("status") == "clean" and not t.get("complete")]
    loud_twins = [path for t in tracks.values() for path in t.get("safe_flagged_high", [])]
    stale = [f"{name} {data[f'{name}_age_days']} days (over {limit:g})"
             for name, limit in FRESH_DAYS.items()
             if data.get(f"{name}_age_days") is not None
             and data[f"{name}_age_days"] > limit]
    outcomes = {
        "offline": (not leaked, "left the machine: " + "; ".join(leaked)),
        "honesty": (not false_clean and not loud_twins,
                    "; ".join(filter(None, [
                        false_clean and "clean while incomplete: " + ", ".join(false_clean),
                        loud_twins and "safe twins at high or critical: "
                        + ", ".join(loud_twins)]))),
        "freshness": (not stale, "stale: " + ", ".join(stale)),
        "ranking": (ranking_first is True,
                    "the known-exploited CVE did not rank first"
                    if ranking_first is False else "the ranking fixture was not scanned"),
        "speed": (True, "recorded"),
    }
    return {name: {"judged": _phase_closed(GATES[name], tasks_text), "ok": ok,
                   "reason": "" if ok else reason, "from": f"R{GATES[name]}"}
            for name, (ok, reason) in outcomes.items()}


#: How far a track may fall under its baseline before a comparison fails (N4.2).
TOLERANCE = 2.0


def compare(result: dict, baseline: dict) -> list[str]:
    """What fails against the baseline: a track more than `TOLERANCE` points under
    it, or a gate judged and failed. A track this run did not measure is not judged."""
    failures = []
    for name, recorded in (baseline.get("tracks") or {}).items():
        track = result["tracks"].get(name)
        if track is not None and track["score"] < recorded - TOLERANCE:
            failures.append(f"{name}: {track['score']}, more than {TOLERANCE:g} points "
                            f"under its baseline of {recorded}")
    for name, gate in (result.get("gates") or {}).items():
        if gate.get("judged") and not gate.get("ok"):
            failures.append(f"gate {name}: {gate.get('reason', 'failed')}")
    return failures


def update_baseline(result: dict, path: Path) -> list[str]:
    """Raise each track the run beat, keep the others (N4.2: only upward). Returns
    a sentence per track kept."""
    baseline = json.loads(path.read_text()) if path.is_file() else {"tracks": {}}
    tracks, kept = dict(baseline.get("tracks") or {}), []
    for name, track in result["tracks"].items():
        recorded = tracks.get(name)
        if recorded is not None and track["score"] < recorded:
            kept.append(f"{name}: {track['score']} is under the recorded {recorded}; kept")
            continue
        tracks[name] = track["score"]
    baseline["tracks"] = tracks
    baseline["recorded_on"] = {"image": result.get("image"), "data": result.get("data"),
                               "seed": result.get("seed")}
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    return kept


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
    parser.add_argument("--tracks", default=",".join(TRACKS),
                        help="comma-separated; every track by default")
    parser.add_argument("--work", type=Path, default=home / "eval" / "work")
    parser.add_argument("--out", type=Path, default=home / "eval" / "report")
    parser.add_argument("--compare", type=Path, metavar="BASELINE",
                        help="fail when a track falls more than 2 points under it")
    parser.add_argument("--update-baseline", type=Path, metavar="BASELINE",
                        help="raise the tracks this run beat; never lower one")
    args = parser.parse_args(argv)
    image = os.environ.get("VALVUR_IMAGE", "valvur:dev")
    result = run([t for t in args.tracks.split(",") if t], args.work.resolve(), image=image)
    write(result, args.out.resolve())
    print(scorecard(result))
    status = 0
    if args.compare:
        failures = compare(result, json.loads(args.compare.read_text()))
        for failure in failures:
            print(f"FAIL {failure}")
        status = 1 if failures else 0
    if args.update_baseline:
        for sentence in update_baseline(result, args.update_baseline):
            print(sentence)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
