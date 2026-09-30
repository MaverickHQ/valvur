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
import precision  # type: ignore[import-not-found]  # noqa: E402
import score  # type: ignore[import-not-found]  # noqa: E402
import twins  # type: ignore[import-not-found]  # noqa: E402

#: Every track, in the order the Score reports them: the OWASP Benchmark first,
#: then the generated ones, then precision on the corpus (ADR-0026).
TRACKS = ["sast-python", *twins.BUILDERS, "real-code-precision"]
CORPUS = REPO / "tests" / "corpus"
LABELS = REPO / "tests" / "eval" / "labels" / "corpus.toml"



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


def _corpus_harness():
    """`scripts/corpus.py`, which pins and fetches the corpus's checkouts."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("corpus_harness",
                                                  REPO / "scripts" / "corpus.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["corpus_harness"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _cursorrules() -> Path:
    """awesome-cursorrules at the corpus's pin, fetched when absent: its real files
    join the agent-configuration track's safe cases on every lane."""
    harness = _corpus_harness()
    harness.fetch([e for e in harness.repos() if e["name"] == "awesome-cursorrules"])
    return harness.CHECKOUTS / "awesome-cursorrules"


def _real_code(scan: Callable[[Path], None], corpus: list[dict] | None,
               checkouts: Path | None, labels: Path) -> dict:
    """Track 8: scan each corpus project at its pin and judge the owned findings."""
    if corpus is None or checkouts is None:
        harness = _corpus_harness()
        corpus, checkouts = harness.repos(), harness.CHECKOUTS
        harness.fetch(corpus)
    findings_by_repo, complete = {}, True
    for entry in corpus:
        root = checkouts / entry["name"]
        scan(root)
        findings, run_json = _read(root)
        findings_by_repo[entry["name"]] = findings
        complete = complete and bool(run_json.get("complete"))
    judged = precision.judge(findings_by_repo, precision.load(labels) if labels.is_file() else {})
    return {"score": judged.score, "tp": judged.tp, "fp": judged.fp,
            "unlabelled": judged.unlabelled, "others": judged.others,
            "repositories": len(corpus), "complete": complete, "status": None,
            "what_left_the_machine": "nothing", "safe_flagged_high": [], "invalid": {},
            "vulnerable": judged.tp, "safe": judged.fp}


def run(tracks: list[str], work: Path, *, scan: Callable[[Path], None] = _cli_scan,
        image: str = "valvur:dev", image_id: Callable[[str], str] = _image_id,
        seed: int = 20260929, tasks_text: str | None = None,
        index_dir: Path | None = None, benchmark: Path | None = None,
        verify: Callable[[Path], None] = owasp.verify, corpus: list[dict] | None = None,
        checkouts: Path | None = None, labels: Path = LABELS,
        cursorrules: Callable[[], Path] = _cursorrules) -> dict:
    """Build, scan and score each track under `work`, which is rebuilt. The
    benchmark is scanned where it is checked out, `benchmark` or the build cache's."""
    started = time.monotonic()
    ranking_first: bool | None = None
    result: dict = {"schema": 1, "image": {"name": image, "id": image_id(image)},
                    "seed": seed, "tracks": {}, "data": {}}
    cwe_of = cwe.lookup(REPO / "rules")
    for track in tracks:
        if track == "real-code-precision":
            began = time.monotonic()
            result["tracks"][track] = _real_code(scan, corpus, checkouts, labels)
            result["tracks"][track]["seconds"] = round(time.monotonic() - began, 1)
            continue
        if track == "sast-python":
            root = benchmark or owasp.checkout(work.parent / "BenchmarkPython")
            verify(root)
            cases = owasp.cases(root)
        else:
            root = work / track
            if root.exists():
                shutil.rmtree(root)
            extra = {"corpus": cursorrules()} if track == "agent-configuration" else {}
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
        if track == "package-reality":
            # R12.4: the same cases asked of `check_package`, the tool an agent calls
            # before the install. Reported beside the scan's score, not averaged in.
            result["tracks"][track]["check_package"] = _through_check_package(
                cases, root, cwe_of)
        if track == "dependencies":
            ranking_first = _ranked_first(findings)
        # The oldest each dataset was in any track's scan: only some tracks read
        # some data (OSV's databases, for one), and the last track need not.
        result["data"] = _oldest(result["data"], data_ages(run_json))
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
FRESH_DAYS = {"database": 7.0, "name_index": 2.0, "malicious": 2.0, "kev": 2.0,
              "epss": 2.0, "osv": 7.0}


def _through_check_package(cases: list, root: Path, cwe_of) -> float:
    """Track 5's cases scored by `check_package`'s answers, by the track's own formula:
    a case is flagged when the answer about its package is, with the case's
    directory as the project whose registry configuration applies."""
    from valvur import packages

    findings = []
    for case in cases:
        [answer] = packages.check([(case.category, case.subject, None)],
                                  workspace=root / case.path)
        if answer.flagged:
            findings.append({"path": f"{case.path}/{answer.verdict}", "status": "new",
                             "rule": f"valvur.dependency.{answer.verdict}"})
    return score.score_track(cases, findings, cwe_of).score


def _oldest(seen: dict, ages: dict) -> dict:
    """Each age the older of the two, where either says one."""
    merged = dict(seen)
    for name, age in ages.items():
        if age is not None and (merged.get(name) is None or age > merged[name]):
            merged[name] = age
        merged.setdefault(name, None)
    return merged


def data_ages(run_json: dict) -> dict:
    """Each dataset's age from `run.json`'s `data` block (R11.6), as the gate reads
    it: OSV's oldest export stands for OSV, since any of them can be the stale one."""
    data = run_json.get("data") or {}
    ages = {f"{name}_age_days": (data.get(name) or {}).get("age_days")
            for name in FRESH_DAYS if name != "osv"}
    osv = [e.get("age_days") for e in (data.get("osv") or {}).values()
           if isinstance(e, dict) and e.get("age_days") is not None]
    ages["osv_age_days"] = max(osv) if osv else None
    return ages


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
    # A partial run (`--tracks`) that scanned no ranking fixture did not measure the
    # ranking: recorded, never judged, since it cannot pass or fail on nothing.
    unmeasured = {"ranking"} if ranking_first is None else set()
    return {name: {"judged": _phase_closed(GATES[name], tasks_text) and name not in unmeasured,
                   "ok": ok, "reason": "" if ok else reason, "from": f"R{GATES[name]}"}
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
    for name, track in result["tracks"].items():
        if track.get("unlabelled"):
            failures.append(f"{name}: {len(track['unlabelled'])} finding(s) with no label: "
                            + "; ".join(track["unlabelled"]))
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
    through = (result["tracks"].get("package-reality") or {}).get("check_package")
    if through is not None:
        # R12.4: the same cases, asked of the tool an agent calls before an install.
        lines += ["", f"Package reality through `check_package`: **{through}**"]
    return "\n".join(lines) + "\n"


def write(result: dict, out: Path) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = {"json": out / "score.json", "markdown": out / "scorecard.md"}
    paths["json"].write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    paths["markdown"].write_text(scorecard(result), encoding="utf-8")
    return paths


def per_rule(rules: Path, work: Path, *, image: str = "valvur:dev",
             benchmark: Path | None = None, corpus: list[dict] | None = None,
             checkouts: Path | None = None, labels: Path = LABELS, run=None,
             verify: Callable[[Path], None] = owasp.verify) -> dict:
    """R13.2: each rule in `rules`, measured over track 1, track 2 and the corpus
    (D29), through the image's Opengrep. `rules` holds `.yaml` files, as
    `scripts/eval/sast_rules.py --stage` writes them."""
    import tomllib

    import per_rule as _per_rule  # type: ignore[import-not-found]

    root = benchmark or owasp.checkout(work.parent / "BenchmarkPython")
    verify(root)
    js_root = work / "sast-js"
    if js_root.exists():
        shutil.rmtree(js_root)
    js_cases = twins.build("sast-js", js_root)
    if corpus is None or checkouts is None:
        harness = _corpus_harness()
        corpus, checkouts = harness.repos(), harness.CHECKOUTS
        harness.fetch(corpus)
    labelled = tomllib.loads(labels.read_text()).get("label", []) if labels.is_file() else []
    by_place = {(e.get("repo", ""), e.get("rule", ""), e.get("path", "")): e.get("verdict", "")
                for e in labelled}
    return _per_rule.measure(
        rules.resolve(), cwe.rule_cwes(rules),
        [("sast-python", root, owasp.cases(root)), ("sast-js", js_root, js_cases)],
        [(entry["name"], checkouts / entry["name"]) for entry in corpus],
        by_place, work / "per-rule", image=image,
        **({"run": run} if run is not None else {}))


def per_rule_table(report: dict) -> str:
    lines = ["| rule | CWE | true | false | outside | precision | ships | seconds |",
             "|---|---|---|---|---|---|---|---|"]
    for rule, row in report["rules"].items():
        lines.append(f"| {rule} | {', '.join(str(n) for n in row['cwe'])} | {row['tp']} "
                     f"| {row['fp']} | {row['outside']} | {row['precision']} "
                     f"| {'yes' if row['ships'] else 'no'} | {row['seconds']} |")
    lines += ["", f"{len(report['ships'])} of {len(report['rules'])} meet D29's bar."]
    return "\n".join(lines) + "\n"


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
    parser.add_argument("--per-rule", type=Path, metavar="RULES",
                        help="measure each rule in RULES over tracks 1 and 2 and the "
                        "corpus instead (R13.2, D29)")
    args = parser.parse_args(argv)
    image = os.environ.get("VALVUR_IMAGE", "valvur:dev")
    if args.per_rule:
        report = per_rule(args.per_rule, args.work.resolve(), image=image)
        out = args.out.resolve()
        out.mkdir(parents=True, exist_ok=True)
        (out / "per-rule.json").write_text(json.dumps(report, indent=1) + "\n")
        (out / "per-rule.md").write_text(per_rule_table(report))
        print(per_rule_table(report))
        return 0
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
