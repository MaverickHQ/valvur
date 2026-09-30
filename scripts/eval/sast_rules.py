"""GitLab's `sast-rules`, audited by licence (R13.1, D29, ADR-0029).

    uv run --with pyyaml python scripts/eval/sast_rules.py CHECKOUT \
        > tests/eval/sast-rules.json

PyYAML is for the audit alone, which reads each rule whole; nothing else in valvur
parses YAML, and `refuse`, which the suite runs, reads rule ids by pattern.

The repository is MIT, but its rules are mostly translations of other projects'
checks, and `mappings/` names each rule's origin. A rule is eligible only when its own
file and its origin are both MIT, Apache-2.0 or BSD. The manifest lists every
candidate for the four languages D29 names, eligible or not, so the audit can be read
rather than trusted; `refuse` holds what is vendored to it.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = REPO / "tests" / "eval" / "sources.toml"
KEY = "gitlab-sast-rules"
PERMISSIVE = frozenset({"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"})

#: Each mapping file's analyzer: the project its rules were translated from, and that
#: project's licence, from its own repository (checked 2026-09-30).
ORIGINS: dict[str, tuple[str, str]] = {
    "bandit": ("bandit", "Apache-2.0"),                  # PyCQA/bandit
    "gosec": ("gosec", "Apache-2.0"),                    # securego/gosec
    "find_sec_bugs": ("find-sec-bugs", "LGPL-3.0"),
    "find_sec_bugs_kotlin": ("find-sec-bugs", "LGPL-3.0"),
    "find_sec_bugs_scala": ("find-sec-bugs", "LGPL-3.0"),
    "flawfinder": ("flawfinder", "GPL-2.0"),
    "security_code_scan": ("security-code-scan", "LGPL-3.0"),
    "brakeman": ("brakeman", "Brakeman Public Use License"),
    "nodejs_scan": ("njsscan", "LGPL-3.0"),
    "mobsf": ("mobsf", "GPL-3.0"),
    "phpcs_security_audit": ("phpcs-security-audit", "GPL-3.0"),
}
#: ESLint's rules come from two plugins, told apart by the rule's own id.
ESLINT = {"react-": ("eslint-plugin-react", "MIT"),
          "": ("eslint-plugin-security", "Apache-2.0")}
#: The trees under a licence of their own, whatever a file's header says.
TREES = {"rules/gitlab/": "GitLab EE", "rules/lgpl/": "LGPL-3.0",
         "rules/lgpl-cc/": "Commons Clause"}
#: D29's languages, as the directories that hold their candidates.
CANDIDATES = ("python/", "javascript/", "go/", "java/", "rules/gitlab/python/",
              "rules/gitlab/javascript/", "rules/gitlab/java/", "rules/lgpl/javascript/",
              "rules/lgpl/java/", "rules/lgpl-cc/python/", "rules/lgpl-cc/javascript/",
              "rules/lgpl-cc/java/")


def source() -> dict:
    return tomllib.loads(SOURCES.read_text())[KEY]


def _origins(checkout: Path) -> dict[str, tuple[str, str]]:
    """Each mapped rule path to its origin and the origin's licence."""
    import yaml

    found: dict[str, tuple[str, str]] = {}
    for mapping in sorted((checkout / "mappings").glob("*.yml")):
        for tool, body in (yaml.safe_load(mapping.read_text()) or {}).items():
            for mapped in (body or {}).get("mappings") or []:
                for rule in mapped.get("rules") or []:
                    if tool == "eslint":
                        origin = next(v for k, v in ESLINT.items()
                                      if str(mapped.get("id", "")).startswith(k))
                    elif tool.startswith("gitlab_"):
                        origin = ("gitlab", "")        # the tree's licence decides
                    else:
                        origin = ORIGINS.get(tool, (tool, "unknown"))
                    found[str(rule["path"])] = origin
    return found


def _file_licence(path: Path, relative: str) -> str:
    for tree, licence in TREES.items():
        if relative.startswith(tree):
            return licence
    header = path.read_text(encoding="utf-8", errors="replace")[:400]
    if "License: Apache 2.0" in header:
        return "Apache-2.0"
    if "MIT (c) GitLab" in header:
        return "MIT"
    return "unknown"


def manifest(checkout: Path) -> dict:
    """Every candidate rule of D29's languages, with its origin and both licences."""
    import yaml

    origins = _origins(checkout)
    rules = []
    for path in sorted(checkout.rglob("*.yml")):
        relative = path.relative_to(checkout).as_posix()
        if not relative.startswith(CANDIDATES) or path.name.startswith("test"):
            continue
        body = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        licence = _file_licence(path, relative)
        stem = relative.removesuffix(".yml")
        origin, origin_licence = origins.get(stem, ("gitlab", ""))
        origin_licence = origin_licence or licence       # GitLab's own: its file's
        for rule in body.get("rules") or []:
            metadata = rule.get("metadata") or {}
            cwe = str(metadata.get("cwe") or "")
            rules.append({
                "id": rule["id"], "path": relative, "languages": rule.get("languages") or [],
                "cwe": cwe.split(":")[0].strip(), "origin": origin,
                "origin_licence": origin_licence, "licence": licence,
                "eligible": licence in PERMISSIVE and origin_licence in PERMISSIVE,
            })
    return {"source": source()["url"], "commit": source()["commit"],
            "eligible": sum(r["eligible"] for r in rules), "rules": rules}


_RULE_ID = re.compile(r"""^\s*-\s*id:\s*["']?([^"'\s]+)""", re.M)


def refuse(vendored: Path, audited: dict) -> list[str]:
    """Each vendored rule the audit does not allow, with why: an origin or a file that
    is not permissive, or a rule the audit never saw."""
    by_id = {rule["id"]: rule for rule in audited["rules"]}
    refused = []
    files = sorted([*vendored.rglob("*.yml"), *vendored.rglob("*.yaml")]) \
        if vendored.is_dir() else []
    for path in files:
        for rule_id in _RULE_ID.findall(path.read_text(encoding="utf-8")):
            entry = by_id.get(rule_id)
            if entry is None:
                refused.append(f"{rule_id}: not in the audit")
            elif entry["origin_licence"] not in PERMISSIVE:
                refused.append(f"{entry['id']}: {entry['origin']} is {entry['origin_licence']}")
            elif entry["licence"] not in PERMISSIVE:
                refused.append(f"{entry['id']}: its file is {entry['licence']}")
    return refused


if __name__ == "__main__":
    print(json.dumps(manifest(Path(sys.argv[1])), indent=1))
