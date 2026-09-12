#!/usr/bin/env python3
"""The public corpus: fetch, scan, judge (task 22.E.1).

    python3 scripts/corpus.py fetch                 # clone each repository at its pin
    python3 scripts/corpus.py run [--profile P]     # scan each, judge, write the report
    python3 scripts/corpus.py rules                 # per-rule hit counts (task 22.E.2)

`tests/corpus/corpus.toml` is the corpus: pinned commits and expectations. The bytes
live in `tests/corpus/.checkouts/`, ignored by git and by the self-scan. `run` writes
`tests/corpus/report.json` and prints a table; it exits non-zero when any of the four
19.F.5 conditions fails on any repository, and names which.

The conditions are deliberately about valvur, not about the projects. A corpus of
maintained, permissively-licensed projects is not expected to be clean — Trivy and
Checkov will find things, and should. What must NOT happen is a Scanner failing, an
omission going unnamed, a status contradicting its own counts, or valvur's own
Checks accusing a real project of something a reviewer would laugh at.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "tests" / "corpus"
MANIFEST = CORPUS / "corpus.toml"
CHECKOUTS = CORPUS / ".checkouts"
REPORT = CORPUS / "report.json"

#: Findings from valvur's own Checks that, on a maintained real project, are far
#: more likely to be our defect than theirs. Zero of each unless the manifest
#: accepts one with a reason.
SUSPECT_RULES = (
    "valvur.dependency.nonexistent",
    "valvur.dependency.near-miss",
    "valvur.dependency.newly-registered",
    "valvur.ai-artifact.prompt-injection",
    "valvur.ai-artifact.permission-bypass",
    "valvur.ai-artifact.hidden-unicode",
)


def repos() -> list[dict]:
    return tomllib.loads(MANIFEST.read_text(encoding="utf-8"))["repo"]


# ------------------------------------------------------------------------ fetch

def fetch(entries: list[dict]) -> int:
    CHECKOUTS.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        target = CHECKOUTS / entry["name"]
        stamp = target / ".valvur-corpus-pin"
        if stamp.is_file() and stamp.read_text().strip() == entry["commit"]:
            print(f"  {entry['name']}: at pin")
            continue
        if target.exists():
            import shutil

            shutil.rmtree(target)
        target.mkdir(parents=True)
        # A shallow fetch of ONE commit, by hash. GitHub allows a depth-1 fetch of a
        # reachable SHA, which is what makes "pinned by commit" cheap.
        for argv in (
            ["git", "init", "-q"],
            ["git", "remote", "add", "origin", entry["url"]],
            ["git", "fetch", "-q", "--depth", "1", "origin", entry["commit"]],
            ["git", "checkout", "-q", "FETCH_HEAD"],
        ):
            subprocess.run(argv, cwd=target, check=True)  # noqa: S603
        stamp.write_text(entry["commit"] + "\n")
        print(f"  {entry['name']}: fetched {entry['commit'][:12]}")
    return 0


# -------------------------------------------------------------------------- run

def _scan(target: Path, profile: str) -> tuple[dict, list[dict]]:
    from valvur import cache
    from valvur.api import scan
    from valvur.runner import ContainerRunner

    if not cache.name_index_present():
        sys.exit("no package-name index in the cache; run `valvur update` first")
    scan(target, runner=ContainerRunner(), profile=profile)
    results = target / ".security-scan"
    run = json.loads((results / "run.json").read_text(encoding="utf-8"))
    findings = json.loads((results / "findings.json").read_text(encoding="utf-8"))["findings"]
    return run, findings


def _judge(entry: dict, run: dict, findings: list[dict]) -> list[str]:
    """The 19.F.5 conditions. Every string returned is one failure, named."""
    failures: list[str] = []
    accepted = (entry.get("expect") or {}).get("accept") or {}

    # 1. No Scanner failed.
    if not run.get("complete"):
        failed = [s["tool"] for s in run.get("scanners", []) if not s.get("ok")]
        failures.append(f"incomplete: {', '.join(failed)} did not complete")

    # 2. Every omission is named. An ecosystem present with no existence check must
    #    produce its coverage note — silence is the failure this corpus exists for.
    from valvur import ecosystems as _eco
    from valvur.name_index import FILES as _indexed

    present_unread = [
        m.label for key, m in _eco.MANIFESTS.items()
        if not m.reads and any(
            p.is_file() for pat in m.sees for p in (CHECKOUTS / entry["name"]).rglob(pat)
            if "node_modules" not in p.parts and "vendor" not in p.parts
        )
    ]
    noted = {f["title"] for f in findings if f["rule"] == "valvur.dependency.ecosystem-not-covered"}
    for label in present_unread:
        if not any(label in title for title in noted):
            failures.append(f"silent omission: {label} manifests present, no coverage note")
    full_only = [
        m.label for key, m in _eco.MANIFESTS.items()
        if m.reads and key not in _indexed and any(
            p.is_file() for pat in m.reads for p in (CHECKOUTS / entry["name"]).rglob(pat)
        )
    ]
    ignores = " ".join((run.get("coverage") or {}).get("dependency-reality", {}).get("ignores", []))
    if run.get("profile") == "offline":
        for label in full_only:
            if f"{label}: existence checked on `full` only" not in ignores:
                failures.append(f"silent omission: {label} read on full only, contract silent")
    # And the other question: an ecosystem present must either have a manifest
    # Trivy reads for vulnerabilities, or the note saying it did not. This is the
    # condition the first corpus run failed on: Express, no lockfile, `clean`.
    vuln_noted = {
        f["title"] for f in findings
        if f["rule"] == "valvur.dependency.vulnerabilities-unchecked"
    }
    checkout = CHECKOUTS / entry["name"]

    def _has(patterns) -> bool:
        return any(p.is_file() for pat in patterns for p in checkout.rglob(pat)
                   if "node_modules" not in p.parts and "vendor" not in p.parts)

    for key, m in _eco.MANIFESTS.items():
        if not _has(m.reads + m.sees):
            continue
        # A lockfile Trivy reads may legitimately produce no result — an empty one
        # (awesome-cursorrules' pnpm-lock.yaml, first corpus run). The silence that
        # matters is a manifest with NOTHING Trivy reads beside it, and no note.
        readable = _has(_eco.VULNERABILITY_MANIFESTS.get(key, ()))
        noted = any(m.label in t for t in vuln_noted)
        if not readable and not noted:
            failures.append(f"silent omission: {m.label} present, nothing Trivy reads, no note")

    # 3. No confusing status.
    counts = run.get("findings") or {}
    status, reason = run.get("status"), run.get("status_reason") or ""
    if status == "findings" and not counts.get("active"):
        failures.append("status `findings` with zero active findings")
    if status == "clean" and counts.get("active"):
        failures.append("status `clean` with active findings")
    if status == "inconclusive" and "not evidence" not in reason:
        failures.append("status `inconclusive` with no stated doubt")
    if status not in {"findings", "clean", "inconclusive"}:
        failures.append(f"unknown status {status!r}")

    # 4. No false positive from valvur itself.
    for rule in SUSPECT_RULES:
        hits = [f for f in findings if f["rule"] == rule and not f.get("suppressed")]
        if hits and rule not in accepted:
            where = "; ".join(f"{f['path']}: {f['title'][:70]}" for f in hits[:3])
            failures.append(f"suspect {rule} x{len(hits)}: {where}")
    return failures


def run(entries: list[dict], profile: str) -> int:
    report: dict = {"profile": profile, "repos": {}}
    any_failed = False
    print(f"{'repo':<22} {'status':<13} {'active':>6} {'notes':>5} {'fails':>5}  problems")
    for entry in entries:
        target = CHECKOUTS / entry["name"]
        if not target.is_dir():
            sys.exit(f"{entry['name']} is not fetched; run `scripts/corpus.py fetch`")
        run_json, findings = _scan(target, profile)
        failures = _judge(entry, run_json, findings)
        any_failed |= bool(failures)
        by_source = Counter(s for f in findings for s in f.get("sources", []))
        report["repos"][entry["name"]] = {
            "commit": entry["commit"],
            "status": run_json.get("status"),
            "status_reason": run_json.get("status_reason"),
            "complete": run_json.get("complete"),
            "findings": run_json.get("findings"),
            "by_source": dict(by_source),
            "by_rule": dict(Counter(f["rule"] for f in findings)),
            "failures": failures,
        }
        counts = run_json.get("findings") or {}
        print(f"{entry['name']:<22} {run_json.get('status', '?'):<13} "
              f"{counts.get('active', 0):>6} {counts.get('not_covered', 0):>5} "
              f"{len(failures):>5}  {'; '.join(failures)[:90]}")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nreport: {REPORT}")
    if any_failed:
        print("\nCORPUS FAILED — see the problems column; each is a defect in valvur "
              "until a reviewer says otherwise in corpus.toml.")
        return 1
    print("\nCORPUS PASSED — every Scanner completed, every omission named, every "
          "status consistent, nothing suspect from valvur's own Checks.")
    return 0


# ------------------------------------------------------------------------ rules

def rules(entries: list[dict]) -> int:
    """Per-rule hits across the corpus, from the last `run` (task 22.E.2)."""
    if not REPORT.is_file():
        sys.exit("no report yet; run `scripts/corpus.py run` first")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    ours = Counter()
    where: dict[str, list[str]] = {}
    for name, entry in report["repos"].items():
        for rule, count in entry["by_rule"].items():
            if rule.startswith("valvur."):
                ours[rule] += count
                where.setdefault(rule, []).append(f"{name}:{count}")
    print(f"{'rule':<45} {'hits':>5}  where")
    for rule, count in sorted(ours.items()):
        print(f"{rule:<45} {count:>5}  {', '.join(where[rule])}")
    shipped = sorted(
        line.split("id:")[1].strip()
        for path in (REPO / "rules").glob("*.yaml")
        for line in path.read_text().splitlines() if line.strip().startswith("- id:")
    )
    silent = [r for r in shipped if r not in ours]
    print(f"\nshipped rules with zero hits on the corpus: {len(silent)}/{len(shipped)}")
    for r in silent:
        print(f"  {r}")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in {"fetch", "run", "rules"}:
        print(__doc__)
        return 2
    entries = repos()
    if argv[0] == "fetch":
        return fetch(entries)
    if argv[0] == "rules":
        return rules(entries)
    profile = "offline"
    if "--profile" in argv:
        profile = argv[argv.index("--profile") + 1]
    return run(entries, profile)


if __name__ == "__main__":
    sys.path.insert(0, str(REPO / "src"))
    raise SystemExit(main(sys.argv[1:]))
