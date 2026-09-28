"""R5.6: Cisco mcp-scanner's injection patterns against real agent files (D14).

D14: a pattern is translated into the AI Artifact Check only where it adds no
finding on the corpus's real files. Each named string of the four YARA rules the
review named (prompt injection, coercive injection, data exfiltration, credential
harvesting) is compiled as Python, and run over every file the Check reads in:
the thirteen corpus checkouts, valvur itself (the self-scan gate fails on any
finding) and the acceptance set, whose planted files are what the Check exists to
find. Usage:

    uv run python scripts/spikes/r5_6_patterns.py <mcp-scanner>/mcpscanner/data/yara_rules \\
        tests/corpus/.checkouts ~/.cache/valvur-build/acceptance-set > out.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RULES = ("prompt_injection", "coercive_injection", "data_exfiltration",
         "credential_harvesting")
STRING = re.compile(r"^\s*\$([a-z_0-9]+)\s*=\s*/(.*)/([a-z]*)\s*$")


def patterns(rules: Path) -> dict[str, re.Pattern]:
    found = {}
    for name in RULES:
        for line in (rules / f"{name}.yara").read_text().splitlines():
            m = STRING.match(line)
            if m:
                flags = re.IGNORECASE if "i" in m.group(3) else 0
                found[f"{name}.{m.group(1)}"] = re.compile(m.group(2).replace(r"\/", "/"), flags)
    return found


def agent_files(root: Path) -> list[Path]:
    from valvur.checks.ai_artifact import _artifact_files

    return _artifact_files(root)


def main(rules: Path, corpus: Path, acceptance: Path) -> dict:
    compiled = patterns(rules)
    sets = {
        "corpus": [p for repo in sorted(corpus.iterdir()) if repo.is_dir()
                   for p in agent_files(repo)],
        # awesome-cursorrules keeps hundreds of real agent instruction texts as
        # `.mdc` and `.md` files under `rules/`: not live surfaces, so the Check
        # does not read them in place, and the best false-positive corpus there is.
        "instructions": sorted(p for p in (corpus / "awesome-cursorrules").rglob("*")
                               if p.is_file() and (p.suffix in (".mdc", ".md")
                                                   or p.name == ".cursorrules")),
        "valvur": agent_files(Path(__file__).resolve().parents[2]),
        "acceptance": [p for repo in sorted(acceptance.iterdir()) if repo.is_dir()
                       for p in agent_files(repo)],
    }
    out = {"files": {k: len(v) for k, v in sets.items()}, "patterns": {}}
    for name, pattern in compiled.items():
        hits = {}
        for label, files in sets.items():
            where = []
            for path in files:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                m = pattern.search(text)
                if m:
                    where.append(f"{path.name}: {m.group(0)[:60]!r}")
            hits[label] = where
        out["patterns"][name] = hits
    return out


if __name__ == "__main__":
    print(json.dumps(main(*map(Path, sys.argv[1:4])), indent=1))
