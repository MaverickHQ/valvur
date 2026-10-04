"""What valvur misses, by a second engine: CodeQL over the corpus (R29.4, D65c).

    python3 scripts/codeql_corpus.py matrix                  # the projects, as JSON
    python3 scripts/codeql_corpus.py lines NAME SARIF        # one line per result
    python3 scripts/codeql_corpus.py candidates LOG          # CodeQL's lines valvur missed

`codeql-corpus.yml` analyses each project with CodeQL's default queries and prints its
results to the log, one `CODEQL <project> <rule> <path>:<line>` line each. Read against
the findings valvur's own scan of the same project wrote (the corpus's checkouts, after
track 8), the lines valvur does not report are candidate rules, listed in
`docs/acceptance/r29.md`. Nothing of CodeQL ships: no query, no result, no binary.

Its terms were read before it ran (`TERMS`): the corpus's projects are Open Source
Codebases hosted on GitHub.com, which the terms allow analysing, in CI too. A project
whose licence is not OSI-approved is left out. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: What allows this, read 2026-10-04 (D65c).
TERMS = {
    "name": "GitHub CodeQL Terms and Conditions",
    "source": "https://github.com/github/codeql-cli-binaries",
    "allows": ("Perform analysis on the Open Source Codebase; if it is hosted and "
               "maintained on GitHub.com, generate CodeQL databases for or during "
               "automated analysis, CI, or CD"),
    "open_source_codebase": "a codebase released under an OSI-approved License",
}

#: The licences in the corpus that the OSI has approved. CC0-1.0 is not one.
OSI = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "0BSD"}
#: CodeQL's language for each corpus language it analyses without a build.
LANGUAGES = {"python": "python", "javascript": "javascript-typescript",
             "typescript": "javascript-typescript"}
_LINE = re.compile(r"CODEQL (\S+) (\S+) (.+):(\d+)\s*$")


def corpus() -> list[dict]:
    return tomllib.loads((REPO / "tests" / "corpus" / "corpus.toml").read_text())["repo"]


def matrix(entries: list[dict]) -> list[dict]:
    """The projects CodeQL may analyse and can without a build."""
    return [{"name": e["name"], "url": e["url"], "commit": e["commit"],
             "codeql": LANGUAGES[e["language"]]}
            for e in entries if e.get("language") in LANGUAGES and e.get("licence") in OSI]


def lines(name: str, sarif: dict) -> list[str]:
    """One line per result with a location: what the log carries back."""
    out = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", [])[:1]:
                physical = location.get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri", "")
                line = physical.get("region", {}).get("startLine", 0)
                if uri:
                    out.append(f"CODEQL {name} {result.get('ruleId', '?')} {uri}:{line}")
    return out


def candidates(log: str, valvur: dict[str, list[dict]]) -> list[dict]:
    """CodeQL's results at lines where valvur's scan of the same project reports
    nothing: what a candidate rule would add."""
    found = []
    for raw in log.splitlines():
        match = _LINE.search(raw)
        if not match:
            continue
        repo, rule, path, line = match[1], match[2], match[3], int(match[4])
        reported = {(f.get("path"), f.get("line")) for f in valvur.get(repo, [])}
        if (path, line) not in reported:
            found.append({"repo": repo, "rule": rule, "path": path, "line": line})
    return found


def _valvur(checkouts: Path, repos: set[str]) -> dict[str, list[dict]]:
    found = {}
    for name in repos:
        path = checkouts / name / ".security-scan" / "findings.json"
        if path.is_file():
            found[name] = json.loads(path.read_text()).get("findings", [])
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("matrix")
    one = sub.add_parser("lines")
    one.add_argument("name")
    one.add_argument("sarif", type=Path, nargs="+")
    compared = sub.add_parser("candidates")
    compared.add_argument("log", type=Path)
    args = parser.parse_args(argv)
    if args.command == "matrix":
        print(json.dumps(matrix(corpus())))
    elif args.command == "lines":
        for path in args.sarif:
            print("\n".join(lines(args.name, json.loads(path.read_text()))))
    else:
        text = args.log.read_text(encoding="utf-8", errors="replace")
        repos = {m[1] for m in _LINE.finditer(text)}
        checkouts = Path(os.environ.get("VALVUR_CORPUS", "").strip()
                         or Path.home() / ".cache" / "valvur-build" / "corpus")
        json.dump(candidates(text, _valvur(checkouts, repos)), sys.stdout, indent=1)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
