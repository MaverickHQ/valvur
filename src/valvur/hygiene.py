"""Repository hygiene: facts about the repository, reported and never ranked (D13).

The owner's audit of the lab found no `SECURITY.md` and no Dependabot, and valvur
said nothing; OpenSSF Scorecard checks both locally. They are not Findings: nothing
in the code is wrong, so they never change the Status. They are read on the host
from the File Set, as the applicability sniff reads it, because they are about
which files exist, not about what a Scanner found in them.

The third fact is what no Finding says. A workflow with no top-level `permissions:`
runs with the repository's default token, write-all on repositories created before
February 2023, and that setting is not in any file. An explicit `write-all` is
zizmor's ranked Finding (R4.2).
"""

from __future__ import annotations

import re
from pathlib import Path

#: Where GitHub looks for a security policy: the root, `.github/` and `docs/`.
SECURITY_POLICY = re.compile(r"^(?:\.github/|docs/)?security(?:\.md|\.rst|\.txt|\.adoc)?$",
                             re.IGNORECASE)
#: Dependabot's and Renovate's configuration files.
DEPENDENCY_UPDATES = re.compile(
    r"^(?:\.github/dependabot\.ya?ml"
    r"|(?:\.github/|\.gitlab/)?renovate\.json5?|\.renovaterc(?:\.json5?)?)$")
TOP_PERMISSIONS = re.compile(r"^permissions\s*:", re.MULTILINE)


def assess(workspace: Path, files: list[str]) -> dict:
    """The facts, from the File Set: the policy's path or None, the update
    configuration's path or None, and the workflows left to the default token."""
    workflows = sorted(f for f in files if f.startswith(".github/workflows/")
                       and f.count("/") == 2 and f.endswith((".yml", ".yaml")))
    return {
        "security_policy": next((f for f in sorted(files) if SECURITY_POLICY.match(f)), None),
        "dependency_updates": next((f for f in sorted(files)
                                    if DEPENDENCY_UPDATES.match(f)), None),
        "workflows": len(workflows),
        "default_permissions": [w for w in workflows
                                if not TOP_PERMISSIONS.search(_text(workspace / w))],
    }


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def lines(facts: dict | None) -> list[str]:
    """The Hygiene section's entries: only what is missing or weak."""
    if not facts:
        return []
    said = []
    if not facts.get("security_policy"):
        # express and flask publish theirs organisation-wide, from a `.github`
        # repository, which a scan of this one cannot see (measured on the corpus).
        said.append("- No `SECURITY.md` in the repository: nobody reading it is told how to "
                    "report a vulnerability, unless an organisation-wide policy applies, "
                    "which a scan of this repository cannot see.")
    if not facts.get("dependency_updates"):
        said.append("- No dependency-update configuration (Dependabot or Renovate): pinned "
                    "dependencies and actions move only when someone moves them.")
    default = facts.get("default_permissions") or []
    if default:
        named = ", ".join(f"`{w}`" for w in default[:3])
        more = f" and {len(default) - 3} more" if len(default) > 3 else ""
        said.append(f"- {len(default)} of {facts.get('workflows', 0)} workflows set no "
                    "top-level `permissions:`, so they run with the repository's default "
                    "token, write-all on repositories created before February 2023: "
                    f"{named}{more}.")
    return said
