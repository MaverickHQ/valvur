"""What valvur misses, by a second engine: CodeQL over the corpus (R29.4, D65c).

    python3 scripts/codeql_corpus.py matrix               # the projects, as JSON
    gh run download <run> --pattern 'codeql-*' --dir DIR
    python3 scripts/codeql_corpus.py candidates DIR       # CodeQL's results valvur missed

`codeql-corpus.yml` analyses each project with CodeQL's default queries and keeps its
SARIF as the run's artifact `codeql-<project>`. Read against the findings valvur's own
scan of the same project wrote (the corpus's checkouts, after track 8), the results at
lines valvur does not report are candidate rules, listed in `docs/acceptance/r29.md`.
Nothing of CodeQL ships: no query, no result, no binary.

Its terms were read before it ran (`TERMS`): the corpus's projects are Open Source
Codebases hosted on GitHub.com, which the terms allow analysing, in CI too. A project
whose licence is not OSI-approved is left out. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
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


def corpus() -> list[dict]:
    return tomllib.loads((REPO / "tests" / "corpus" / "corpus.toml").read_text())["repo"]


def matrix(entries: list[dict]) -> list[dict]:
    """The projects CodeQL may analyse and can without a build."""
    return [{"name": e["name"], "url": e["url"], "commit": e["commit"],
             "codeql": LANGUAGES[e["language"]]}
            for e in entries if e.get("language") in LANGUAGES and e.get("licence") in OSI]


def results(downloaded: Path) -> list[dict]:
    """Each result with a location, from every `codeql-<project>/*.sarif` under
    `downloaded`."""
    found = []
    for sarif in sorted(downloaded.glob("codeql-*/*.sarif")):
        repo = sarif.parent.name.removeprefix("codeql-")
        for run in json.loads(sarif.read_text(encoding="utf-8")).get("runs", []):
            for result in run.get("results", []):
                for location in result.get("locations", [])[:1]:
                    physical = location.get("physicalLocation", {})
                    uri = physical.get("artifactLocation", {}).get("uri", "")
                    if uri:
                        found.append({"repo": repo, "rule": result.get("ruleId", "?"),
                                      "path": uri,
                                      "line": physical.get("region", {}).get("startLine", 0)})
    return found


def candidates(found: list[dict], valvur: dict[str, list[dict]]) -> list[dict]:
    """CodeQL's results at lines where valvur's scan of the same project reports
    nothing: what a candidate rule would add."""
    reported = {(repo, f.get("path"), f.get("line"))
                for repo, findings in valvur.items() for f in findings}
    return [r for r in found if (r["repo"], r["path"], r["line"]) not in reported]


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
    compared = sub.add_parser("candidates")
    compared.add_argument("downloaded", type=Path)
    args = parser.parse_args(argv)
    if args.command == "matrix":
        print(json.dumps(matrix(corpus())))
    else:
        found = results(args.downloaded)
        checkouts = Path(os.environ.get("VALVUR_CORPUS", "").strip()
                         or Path.home() / ".cache" / "valvur-build" / "corpus")
        valvur = _valvur(checkouts, {r["repo"] for r in found})
        json.dump(candidates(found, valvur), sys.stdout, indent=1)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
